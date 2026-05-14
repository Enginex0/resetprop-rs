//! Pure Rust Android system property manipulation.
//!
//! Directly reads and writes the mmap'd property areas at `/dev/__properties__/`
//! without depending on Magisk, forked bionic, or any custom symbols.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use resetprop::PropSystem;
//!
//! let sys = PropSystem::open()?;
//! sys.set("ro.build.type", "user")?;
//! sys.hexpatch_delete("ro.lineage.version")?;
//! # Ok::<(), resetprop::Error>(())
//! ```
//!
//! Use [`PropSystem`] for multi-file operations across the full property directory.
//! Use [`PropArea`] for single-file, low-level access.
//! Use [`PersistStore`] for the on-disk persistent property store.

mod error;
mod area;
mod trie;
mod info;
mod dict;
mod harvest;
mod compact;
mod context;
mod bionic;
mod persist;
mod appcompat;
mod wait;
pub mod seal;
pub mod inspect;
#[cfg(test)]
mod mock;

pub use error::{Error, Result};
pub use area::PropArea;
pub use persist::{PersistStore, Record};
pub use seal::{SealRecord, SealTier};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

const PROP_DIR: &str = "/dev/__properties__";

impl PropArea {
    /// Returns the value of a property, or `None` if it doesn't exist in this area.
    pub fn get(&self, name: &str) -> Option<String> {
        let (pi_offset, _) = trie::find(self, name).ok()?;
        let pi = info::PropInfo::at(self, pi_offset).ok()?;
        Some(pi.read_value())
    }

    /// Sets a property value via direct mmap write. Creates the property if it doesn't exist.
    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        match trie::find(self, name) {
            Ok((pi_offset, _)) => {
                let pi = info::PropInfo::at(self, pi_offset)?;
                pi.write_value(value)
            }
            Err(Error::NotFound) => self.add(name, value),
            Err(e) => Err(e),
        }
    }

    /// Like [`set`](Self::set), but zeros the serial counter to mimic init-time writes.
    pub fn set_init(&self, name: &str, value: &str) -> Result<()> {
        match trie::find(self, name) {
            Ok((pi_offset, _)) => {
                let pi = info::PropInfo::at(self, pi_offset)?;
                pi.write_value_init(value)
            }
            Err(Error::NotFound) => self.add(name, value),
            Err(e) => Err(e),
        }
    }

    /// Like [`set_init`](Self::set_init), but also suppresses the futex wake signal.
    pub fn set_stealth(&self, name: &str, value: &str) -> Result<()> {
        match trie::find(self, name) {
            Ok((pi_offset, _)) => {
                let pi = info::PropInfo::at(self, pi_offset)?;
                pi.write_value_quiet(value)
            }
            Err(Error::NotFound) => self.add(name, value),
            Err(e) => Err(e),
        }
    }

    /// Quiet write: preserves the per-prop serial counter, suppresses futex wake.
    /// For an existing prop, only the value bytes and length-byte change; counter
    /// stays exactly where init left it. Missing props go through the standard
    /// `add` path (bionic-baseline serial).
    pub fn set_quiet(&self, name: &str, value: &str) -> Result<()> {
        match trie::find(self, name) {
            Ok((pi_offset, _)) => {
                let pi = info::PropInfo::at(self, pi_offset)?;
                pi.write_value_quiet_preserve_serial(value)
            }
            Err(Error::NotFound) => self.add(name, value),
            Err(e) => Err(e),
        }
    }

    fn validate_key(name: &str) -> Result<()> {
        if name.is_empty() || name.starts_with('.') || name.ends_with('.') || name.contains("..") {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    fn add(&self, name: &str, value: &str) -> Result<()> {
        Self::validate_key(name)?;
        let mut remaining = name;
        // root trie node's children field is at data_offset + 16
        let mut children_offset = self.data_offset() + 16;

        loop {
            let (segment, rest) = match remaining.find('.') {
                Some(pos) => (&remaining[..pos], Some(&remaining[pos + 1..])),
                None => (remaining, None),
            };

            let parent_children = self.atomic_u32(children_offset);
            let node_off = trie::bst_insert(self, parent_children, segment.as_bytes())?;

            match rest {
                Some(r) => {
                    // next level: this node's children field is at node_off + 16
                    children_offset = node_off + 16;
                    remaining = r;
                }
                None => {
                    let pi_offset = info::alloc_prop_info(self, name, value)?;
                    let relative = (pi_offset - self.data_offset()) as u32;
                    self.atomic_u32(node_off + 4).store(relative, Ordering::Release);
                    return Ok(());
                }
            }
        }
    }

    /// Deletes a property by detaching its trie node, wiping the prop_info
    /// record (long value, name, and full 96-byte header), then pruning
    /// orphaned trie leaves. Returns `Ok(false)` if the property was not found.
    pub fn delete(&self, name: &str) -> Result<bool> {
        let (pi_offset, node_offset) = match trie::find(self, name) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        self.atomic_u32(node_offset + 4).store(0, Ordering::Release);

        let pi = info::PropInfo::at(self, pi_offset)?;
        pi.wipe()?;

        trie::prune(self);

        Ok(true)
    }

    /// Stealth-deletes a property by replacing name segments with plausible dictionary
    /// words and setting the value to `"0"`. Trie structure stays intact, making the
    /// deletion invisible to `__system_property_foreach`.
    /// Returns `Ok(false)` if the property was not found.
    pub fn hexpatch_delete(&self, name: &str) -> Result<bool> {
        let path = match trie::find_path(self, name) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        let (pi_offset, _) = trie::find(self, name)?;
        let pool = harvest::SegmentPool::from_area(self);
        let mut used: HashSet<Vec<u8>> = HashSet::new();

        for &node_off in &path {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            used.insert(node.name_bytes().to_vec());
        }

        let mut chosen: Vec<Vec<u8>> = Vec::with_capacity(path.len());

        let last_idx = path.len() - 1;
        for (idx, &node_off) in path.iter().enumerate() {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            let original = node.name_bytes().to_vec();

            if self.is_shared_segment(&node, idx == last_idx) {
                chosen.push(original);
                continue;
            }

            let replacement = harvest::replacement(&original, &used, &pool);
            used.insert(replacement.clone());

            unsafe {
                std::ptr::copy_nonoverlapping(
                    replacement.as_ptr(),
                    node.name_ptr(),
                    replacement.len(),
                );
            }

            chosen.push(replacement);
        }

        // write mangled name to prop_info using the SAME segments chosen for the trie
        let name_start = pi_offset + 96;
        if let Some(ptr) = self.ptr_at(name_start) {
            let old_len = name.len();
            unsafe {
                std::ptr::write_bytes(ptr, 0, old_len + 1);
                let mut i = 0;
                for (idx, seg) in chosen.iter().enumerate() {
                    if idx > 0 {
                        *ptr.add(i) = b'.';
                        i += 1;
                    }
                    std::ptr::copy_nonoverlapping(seg.as_ptr(), ptr.add(i), seg.len());
                    i += seg.len();
                }
            }
        }

        let pi = info::PropInfo::at(self, pi_offset)?;
        pi.stealth_write_value()?;

        Ok(true)
    }

    fn is_shared_segment(&self, node: &trie::TrieNode<'_>, is_leaf: bool) -> bool {
        // intermediate node with its own property (e.g. "ro.lineage" alongside "ro.lineage.version")
        if !is_leaf && node.prop_offset().load(Ordering::Relaxed) != 0 {
            return true;
        }

        let children = node.children().load(Ordering::Acquire);
        if children == 0 {
            return false;
        }

        if let Ok(child) = trie::TrieNode::from_offset(self, self.data_offset() + children as usize) {
            let left = child.left().load(Ordering::Relaxed);
            let right = child.right().load(Ordering::Relaxed);
            left != 0 || right != 0
        } else {
            false
        }
    }

    /// Defragments the arena by sliding live allocations forward to fill holes
    /// left by deleted properties. Returns `Ok(true)` if any compaction occurred.
    pub fn compact(&self) -> Result<bool> {
        compact::compact(self)
    }

    /// Walks every property in this area and rewrites short `ro.*` props with
    /// their own value, advancing each serial counter via init-style bionic
    /// math. Long props and non-`ro.*` props are skipped. Returns the number
    /// of properties whose serial was normalized.
    ///
    /// Mirrors Treat-Wheel's `fix_serials()` (see
    /// `treat-wheel-zygisk/src/cmd/utils.c:97-99`). The rewrite preserves the
    /// value byte-for-byte (modulo the existing UTF-8 round-trip used by all
    /// of resetprop-rs's read/write API); only the serial counter changes.
    pub fn normalize_serial(&self) -> Result<usize> {
        if !self.writable() {
            return Err(Error::PermissionDenied(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "area opened read-only",
            )));
        }
        let mut count = 0usize;
        let mut first_err: Option<Error> = None;
        trie::foreach(self, |pi_offset| {
            if first_err.is_some() {
                return;
            }
            let pi = match info::PropInfo::at(self, pi_offset) {
                Ok(p) => p,
                Err(e) => {
                    first_err = Some(e);
                    return;
                }
            };
            let name = pi.read_name();
            if !name.starts_with("ro.") {
                return;
            }
            match pi.normalize_serial() {
                Ok(true) => count += 1,
                Ok(false) => {}
                Err(e) => first_err = Some(e),
            }
        });
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(count)
    }

    /// Count-preserving stealth delete: removes the property, inserts a plausible
    /// replacement, and compacts the arena. Returns `Ok(false)` if not found.
    pub fn nuke(&self, name: &str) -> Result<bool> {
        if !self.delete(name)? {
            return Ok(false);
        }

        let mut exclude: HashSet<String> = HashSet::new();
        self.foreach(|n, _| {
            exclude.insert(n.to_string());
        });
        exclude.insert(name.to_string());

        let replacement = harvest::generate_name(self, &exclude);
        self.set_stealth(&replacement, "0")?;
        self.compact()?;
        Ok(true)
    }

    /// Iterates over all properties in this area, calling `cb(name, value)` for each.
    pub fn foreach<F: FnMut(&str, &str)>(&self, mut cb: F) {
        trie::foreach(self, |pi_offset| {
            if let Ok(pi) = info::PropInfo::at(self, pi_offset) {
                let name = pi.read_name();
                let value = pi.read_value();
                if !name.is_empty() {
                    cb(&name, &value);
                }
            }
        });
    }
}

const SERIAL_FILE: &str = "properties_serial";
const SKIP_FILES: &[&str] = &["property_info", SERIAL_FILE];

/// High-level interface that scans all property files in `/dev/__properties__/`.
///
/// This is the primary entry point for most consumers. It searches across all
/// property areas for reads and picks the correct area for writes.
///
/// ```rust,no_run
/// let sys = resetprop::PropSystem::open()?;
/// sys.set("persist.sys.timezone", "UTC")?;
/// # Ok::<(), resetprop::Error>(())
/// ```
pub struct PropSystem {
    areas: Vec<(PathBuf, PropArea)>,
    serial_area: Option<(PathBuf, PropArea)>,
    context: Option<context::PropertyContext>,
    area_by_name: HashMap<String, usize>,
    appcompat: Option<appcompat::AppcompatAreas>,
    hook_handle: OnceLock<Mutex<Option<seal::hook::HookHandle>>>,
}

impl PropSystem {
    /// Opens the default property directory at `/dev/__properties__/`.
    pub fn open() -> Result<Self> {
        Self::open_dir(Path::new(PROP_DIR))
    }

    /// Opens a custom property directory (useful for testing or alternate roots).
    pub fn open_dir(dir: &Path) -> Result<Self> {
        let mut areas = Vec::new();
        let entries = std::fs::read_dir(dir).map_err(|e| -> Error { e.into() })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if SKIP_FILES.contains(&name) {
                continue;
            }
            let area = PropArea::open(&path).or_else(|_| PropArea::open_ro(&path));
            match area {
                Ok(a) => areas.push((path, a)),
                Err(_) => continue,
            }
        }

        if areas.is_empty() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no property areas in {}", dir.display()),
            )));
        }

        let serial_path = dir.join(SERIAL_FILE);
        let serial_area = PropArea::open(&serial_path).ok().map(|a| (serial_path, a));

        let ctx = context::PropertyContext::load(dir);

        let mut area_by_name = HashMap::new();
        for (i, (path, _)) in areas.iter().enumerate() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                area_by_name.insert(name.to_string(), i);
            }
        }

        let override_dir = dir.join("appcompat_override");
        let appcompat = if override_dir.is_dir() {
            appcompat::AppcompatAreas::open(&override_dir)
        } else {
            None
        };

        Ok(Self {
            areas,
            serial_area,
            context: ctx,
            area_by_name,
            appcompat,
            hook_handle: OnceLock::new(),
        })
    }

    fn notify(&self) {
        if let Some((_, ref sa)) = self.serial_area {
            sa.bump_serial_and_wake();
        }
    }

    /// Resolve the filesystem path of the primary arena that owns `name`.
    ///
    /// Prefers `PropertyContext::resolve` when available (matches how
    /// `find_area` / `find_writable` pick the canonical arena) and falls
    /// back to a linear scan of loaded areas. Shared by `seal_arena` and
    /// `unseal_arena`, so the resolution policy lives in one place.
    fn resolve_arena_path(&self, name: &str) -> Result<PathBuf> {
        if let Some(ctx) = self.context.as_ref() {
            if let Some(filename) = ctx.resolve(name) {
                if let Some(&idx) = self.area_by_name.get(filename) {
                    return Ok(self.areas[idx].0.clone());
                }
            }
        }
        if let Some((idx, _)) = self.find_area(name) {
            return Ok(self.areas[idx].0.clone());
        }
        Err(Error::NotFound)
    }

    fn find_area(&self, name: &str) -> Option<(usize, &PropArea)> {
        if let Some(ref ctx) = self.context {
            if let Some(filename) = ctx.resolve(name) {
                if let Some(&idx) = self.area_by_name.get(filename) {
                    if self.areas[idx].1.get(name).is_some() {
                        return Some((idx, &self.areas[idx].1));
                    }
                }
            }
        }
        for (i, (_, area)) in self.areas.iter().enumerate() {
            if area.get(name).is_some() {
                return Some((i, area));
            }
        }
        None
    }

    fn find_writable(&self, name: &str) -> Option<(usize, &PropArea)> {
        if let Some(ref ctx) = self.context {
            if let Some(filename) = ctx.resolve(name) {
                if let Some(&idx) = self.area_by_name.get(filename) {
                    if self.areas[idx].1.writable() {
                        return Some((idx, &self.areas[idx].1));
                    }
                }
            }
        }
        for (i, (_, area)) in self.areas.iter().enumerate() {
            if area.writable() {
                return Some((i, area));
            }
        }
        None
    }

    fn appcompat_write(&self, area_idx: usize, op: impl Fn(&PropArea)) {
        if let Some(ref compat) = self.appcompat {
            if let Some(filename) = self.areas[area_idx].0.file_name().and_then(|n| n.to_str()) {
                if let Some(mirror) = compat.mirror_for(filename) {
                    op(mirror);
                }
            }
        }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        if let Some((_, area)) = self.find_area(name) {
            return area.get(name);
        }
        bionic::get(name)
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        if let Some((idx, area)) = self.find_area(name) {
            area.set(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set(name, value); });
            self.notify();
            return Ok(());
        }
        if let Some((idx, area)) = self.find_writable(name) {
            area.set(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set(name, value); });
            self.notify();
            return Ok(());
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn set_init(&self, name: &str, value: &str) -> Result<()> {
        if let Some((idx, area)) = self.find_area(name) {
            area.set_init(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_init(name, value); });
            self.notify();
            return Ok(());
        }
        if let Some((idx, area)) = self.find_writable(name) {
            area.set_init(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_init(name, value); });
            self.notify();
            return Ok(());
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn set_stealth(&self, name: &str, value: &str) -> Result<()> {
        if let Some((idx, area)) = self.find_area(name) {
            area.set_stealth(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_stealth(name, value); });
            return Ok(());
        }
        if let Some((idx, area)) = self.find_writable(name) {
            area.set_stealth(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_stealth(name, value); });
            return Ok(());
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn set_quiet(&self, name: &str, value: &str) -> Result<()> {
        if let Some((idx, area)) = self.find_area(name) {
            area.set_quiet(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_quiet(name, value); });
            return Ok(());
        }
        if let Some((idx, area)) = self.find_writable(name) {
            area.set_quiet(name, value)?;
            self.appcompat_write(idx, |m| { let _ = m.set_quiet(name, value); });
            return Ok(());
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        if let Some((idx, area)) = self.find_area(name) {
            let deleted = area.delete(name)?;
            if deleted {
                self.appcompat_write(idx, |m| { let _ = m.delete(name); });
                self.notify();
            }
            return Ok(deleted);
        }
        Ok(false)
    }

    /// Sets a property in both the mmap'd area and the on-disk persist store.
    pub fn set_persist(&self, name: &str, value: &str) -> Result<()> {
        self.set(name, value)?;
        let mut store = PersistStore::load()?;
        store.set(name, value)
    }

    /// Stealth-sets a property in the mmap'd area and writes it to the on-disk persist store.
    ///
    /// Combines `set_stealth` (no serial bump or futex wake) with persist-to-disk.
    pub fn set_stealth_persist(&self, name: &str, value: &str) -> Result<()> {
        self.set_stealth(name, value)?;
        let mut store = PersistStore::load()?;
        store.set(name, value)
    }

    /// Pre-seal write that matches what real init would emit for this prop class.
    /// `ro.*` properties have no listeners, so a `FUTEX_WAKE` would be a
    /// detectable anomaly — those go through `set_stealth`. Everything else
    /// (persist/sys/service/...) has real listeners that expect a wake on every
    /// update, so withholding one is the anomaly — those go through `set_init`.
    /// Single source of truth for both `seal_arena` and `seal`.
    fn seal_write(&self, name: &str, value: &str) -> Result<()> {
        if name.starts_with("ro.") {
            self.set_stealth(name, value)
        } else {
            self.set_init(name, value)
        }
    }

    /// Tier A seal: remap init's writable view of this property's arena file
    /// as `MAP_PRIVATE|MAP_FIXED`, so subsequent writes from init (PID 1) do
    /// not propagate to the backing inode or to other processes.
    ///
    /// Flow:
    /// 1. Reject `properties_serial` up front — privatizing the global serial
    ///    wake channel would break system-wide property-change notifications
    ///    (REGISTRY §1 "Arenas NOT to touch").
    /// 2. Resolve the arena filename via `PropertyContext::resolve`, falling
    ///    back to a linear scan over `self.areas` when no context is loaded.
    /// 3. `seal_write(name, value)` — emits the write through the channel
    ///    real init would use for this prop class: `set_stealth` for `ro.*`
    ///    (no listeners → wake would be a detection signal) and `set_init`
    ///    for everything else (real listeners → silent write would be the
    ///    anomaly).
    /// 4. If an appcompat mirror exists for the primary filename, derive the
    ///    mirror path via the REGISTRY-locked convention and pass both paths
    ///    to `seal::arena::seal_arena_with_mirror(1, primary, mirror)`.
    /// 5. Record the operation in the process-wide `seals_registry()`.
    ///
    /// Returns the `SealRecord` that was inserted (or refreshed on duplicate).
    pub fn seal_arena(&self, name: &str, value: &str) -> Result<SealRecord> {
        let primary_path = self.resolve_arena_path(name)?;
        let filename = arena_filename(&primary_path)?;
        if filename == SERIAL_FILE {
            return Err(Error::InvalidKey);
        }

        self.seal_write(name, value)?;

        let mirror_path = self.derive_mirror_path(&primary_path, filename);
        seal::arena::seal_arena_with_mirror(
            seal::INIT_PID,
            &primary_path,
            mirror_path.as_deref(),
        )?;

        let record = SealRecord {
            name: name.to_string(),
            arena_path: primary_path,
            tier: SealTier::Arena,
            sealed_at: SystemTime::now(),
        };
        Ok(insert_or_refresh_seal(record))
    }

    /// Reverse of `seal_arena`: restores init's shared view of the arena and
    /// removes the matching `SealTier::Arena` record from the registry.
    /// Returns `Ok(true)` if a record was removed, `Ok(false)` otherwise.
    pub fn unseal_arena(&self, name: &str) -> Result<bool> {
        let primary_path = self.resolve_arena_path(name)?;
        let filename = arena_filename(&primary_path)?;
        if filename == SERIAL_FILE {
            return Err(Error::InvalidKey);
        }

        let mirror_path = self.derive_mirror_path(&primary_path, filename);
        seal::arena::unseal_arena_with_mirror(
            seal::INIT_PID,
            &primary_path,
            mirror_path.as_deref(),
        )?;

        Ok(remove_seal_record(name))
    }

    /// Tier B seal: lazily install init's `__system_property_update` hook,
    /// then append `name` to the hook's lock list so subsequent writes with
    /// that exact name short-circuit to `mov w0, #0; ret` without mutating
    /// the arena. Unsealed neighbour properties keep writing normally.
    ///
    /// Flow:
    /// 1. Reject `properties_serial` up front — matches the P02 `seal_arena`
    ///    guard and REGISTRY §1 "Arenas NOT to touch". Keeps the Tier A /
    ///    Tier B boundary consistent even though the hook path does not
    ///    touch the serial counter directly.
    /// 2. `seal_write(name, value)` — emits the write through the channel
    ///    real init would use for this prop class (`set_stealth` for `ro.*`,
    ///    `set_init` otherwise). Runs BEFORE any ptrace work so a
    ///    misconfigured context fails fast.
    /// 3. Lazily initialise the shared `HookHandle` under the per-process
    ///    `OnceLock<Mutex<Option<HookHandle>>>`. `install_init_hook` walks
    ///    init's `/proc/1/maps` + libc ELF, then `install_trampoline`
    ///    patches the 16-byte prologue. A failure between the two leaves
    ///    the slot `None` so the next `seal()` can retry cleanly.
    /// 4. `seal::hook::seal_prop(handle, name)` appends the name under the
    ///    hook's atomic-append invariant (entry bytes → trailing sentinel
    ///    → length counter).
    /// 5. Record the operation in the process-wide `seals_registry()` as
    ///    `SealTier::Prop`; existing entries with the same `(name, tier)`
    ///    have their timestamp refreshed rather than duplicated.
    ///
    /// A poisoned hook-handle mutex is recovered with a stderr
    /// warning rather than returning a permanent error — matches the
    /// seals-registry poison handling at `insert_or_refresh_seal` and
    /// closes Gate 2 round-1 critic MAJOR 4, which flagged that the
    /// prior error surface could brick the API for the lifetime of the
    /// process after a single mid-install panic.
    pub fn seal(&self, name: &str, value: &str) -> Result<SealRecord> {
        let primary_path = self.resolve_arena_path(name)?;
        let filename = arena_filename(&primary_path)?;
        if filename == SERIAL_FILE {
            return Err(Error::InvalidKey);
        }

        self.seal_write(name, value)?;

        let slot = self.hook_handle.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().unwrap_or_else(|poisoned| {
            eprintln!("resetprop: seal: hook_handle mutex was poisoned; recovering");
            poisoned.into_inner()
        });
        if guard.is_none() {
            let mut handle = seal::hook::install_init_hook(seal::INIT_PID)?;
            seal::hook::install_trampoline(&mut handle)?;
            *guard = Some(handle);
        }
        let handle = guard
            .as_mut()
            .expect("hook handle initialised above or was already present");
        seal::hook::seal_prop(handle, name)?;
        drop(guard);

        let record = SealRecord {
            name: name.to_string(),
            arena_path: primary_path,
            tier: SealTier::Prop,
            sealed_at: SystemTime::now(),
        };
        Ok(insert_or_refresh_seal(record))
    }

    /// Reverse of [`seal`](Self::seal): remove `name` from init's hook
    /// lock list and delete the matching `SealTier::Prop` record. Arena
    /// seals for the same name (if any) are left untouched.
    ///
    /// Returns `Ok(true)` if a hook entry was removed, `Ok(false)` if no
    /// hook is installed yet or the name was never sealed. Never issues
    /// ptrace work when the hook has not been installed.
    pub fn unseal(&self, name: &str) -> Result<bool> {
        let slot = self.hook_handle.get_or_init(|| Mutex::new(None));
        let mut guard = slot.lock().unwrap_or_else(|poisoned| {
            eprintln!("resetprop: unseal: hook_handle mutex was poisoned; recovering");
            poisoned.into_inner()
        });
        let handle = match guard.as_mut() {
            Some(h) => h,
            None => return Ok(false),
        };
        let removed = seal::hook::unseal_prop(handle, name)?;
        drop(guard);

        if removed {
            let registry = seal::seals_registry();
            let mut entries = registry.lock().unwrap_or_else(|poisoned| {
                eprintln!("resetprop: unseal: seals registry mutex was poisoned; recovering");
                poisoned.into_inner()
            });
            entries.retain(|r| !(r.name == name && r.tier == SealTier::Prop));
        }
        Ok(removed)
    }

    /// Returns a snapshot of the process-wide seal registry. The returned
    /// `Vec` is an owned clone — callers can iterate without holding the
    /// internal mutex, and mutations in the registry after the call are
    /// not reflected in the snapshot.
    pub fn seals(&self) -> Result<Vec<SealRecord>> {
        let registry = seal::seals_registry();
        let entries = registry.lock().unwrap_or_else(|poisoned| {
            eprintln!("resetprop: seals: seals registry mutex was poisoned; recovering");
            poisoned.into_inner()
        });
        Ok(entries.clone())
    }

    /// Returns the appcompat mirror path for `primary_path` when the loaded
    /// `AppcompatAreas` table has a mirror registered for `filename`.
    /// The path follows the REGISTRY-locked convention
    /// `<primary_dir>/appcompat_override/<same filename as primary>`.
    fn derive_mirror_path(&self, primary_path: &Path, filename: &str) -> Option<PathBuf> {
        let compat = self.appcompat.as_ref()?;
        compat.mirror_for(filename)?;
        let parent = primary_path.parent()?;
        Some(parent.join("appcompat_override").join(filename))
    }

    /// Deletes a property from both the mmap'd area and the on-disk persist store.
    pub fn delete_persist(&self, name: &str) -> Result<bool> {
        let mem = self.delete(name)?;
        let mut store = PersistStore::load()?;
        let disk = store.delete(name)?;
        Ok(mem || disk)
    }

    pub fn hexpatch_delete(&self, name: &str) -> Result<bool> {
        for (_, area) in &self.areas {
            match area.hexpatch_delete(name) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    /// Count-preserving stealth delete across all areas.
    pub fn nuke(&self, name: &str) -> Result<bool> {
        for (_, area) in &self.areas {
            match area.nuke(name) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    pub fn nuke_persist(&self, name: &str) -> Result<bool> {
        let mem = self.nuke(name)?;
        let mut store = PersistStore::load()?;
        let disk = store.delete(name)?;
        Ok(mem || disk)
    }

    /// Compacts all writable areas, reclaiming space from deleted properties.
    /// Returns the number of areas that were actually compacted.
    pub fn compact(&self) -> Result<usize> {
        let mut count = 0;
        for (_, area) in &self.areas {
            if area.writable() && area.compact()? {
                count += 1;
            }
        }
        if count > 0 {
            self.notify();
        }
        Ok(count)
    }

    /// Walks every writable area and rewrites each short `ro.*` property with
    /// its own value, advancing the per-prop serial counter via init-style
    /// bionic math. Long props and non-`ro.*` props are skipped. Returns the
    /// total count of properties whose serial was normalized across all
    /// writable areas. Notifies via the global serial when any property was
    /// touched, matching `compact`'s post-condition.
    ///
    /// Pure-Rust analog of Treat-Wheel's `fix_serials()`
    /// (`treat-wheel-zygisk/src/cmd/utils.c:97-99`) and bionic's
    /// `__system_property_foreach` + `__system_property_update` walk pattern.
    pub fn normalize_serial(&self) -> Result<usize> {
        let mut count = 0usize;
        for (_, area) in &self.areas {
            if area.writable() {
                count += area.normalize_serial()?;
            }
        }
        if count > 0 {
            self.notify();
        }
        Ok(count)
    }

    pub fn areas(&self) -> &[(PathBuf, PropArea)] {
        &self.areas
    }

    /// Returns all properties across all areas, sorted by name.
    pub fn list(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (_, area) in &self.areas {
            area.foreach(|name, value| {
                result.push((name.to_string(), value.to_string()));
            });
        }
        if result.is_empty() && bionic::available() {
            result = bionic::foreach();
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Remaps all areas as `MAP_PRIVATE` so writes don't propagate to other processes.
    pub fn privatize(&mut self) -> Result<()> {
        for (path, area) in &mut self.areas {
            area.privatize(path)?;
        }
        if let Some((path, area)) = &mut self.serial_area {
            area.privatize(path)?;
        }
        Ok(())
    }

    /// Prevents `munmap` on drop. Use when the mappings must outlive this struct.
    pub fn leak(self) {
        let mut sys = self;
        for (_, area) in &mut sys.areas {
            area.leak();
        }
        if let Some((_, ref mut area)) = sys.serial_area {
            area.leak();
        }
    }
}

/// Extracts the UTF-8 filename of an arena path, returning `InvalidKey`
/// for paths without a valid final component. Kept separate from
/// `PropSystem` so the seal/unseal methods share one guard-clause helper.
fn arena_filename(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or(Error::InvalidKey)
}

/// Inserts `record` into the process-wide seal registry, or refreshes
/// `sealed_at` on an existing entry with the same `(name, tier)`. Returns
/// the canonical record stored in the registry.
fn insert_or_refresh_seal(record: SealRecord) -> SealRecord {
    let registry = seal::seals_registry();
    let mut guard = registry.lock().unwrap_or_else(|poisoned| {
        eprintln!("resetprop: seals registry mutex was poisoned; recovering");
        poisoned.into_inner()
    });
    if let Some(existing) = guard
        .iter_mut()
        .find(|r| r.name == record.name && r.tier == record.tier)
    {
        existing.sealed_at = record.sealed_at;
        return existing.clone();
    }
    guard.push(record.clone());
    record
}

/// Removes the `SealTier::Arena` entry for `name` from the registry.
/// Returns `true` if a record was removed, `false` otherwise.
fn remove_seal_record(name: &str) -> bool {
    let registry = seal::seals_registry();
    let mut guard = registry.lock().unwrap_or_else(|p| p.into_inner());
    let before = guard.len();
    guard.retain(|r| !(r.name == name && r.tier == SealTier::Arena));
    guard.len() != before
}
