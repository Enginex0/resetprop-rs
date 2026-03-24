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
mod persist;
pub mod inspect;
#[cfg(test)]
mod mock;

pub use error::{Error, Result};
pub use area::PropArea;
pub use persist::{PersistStore, Record};

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

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

        Ok(Self { areas, serial_area })
    }

    fn notify(&self) {
        if let Some((_, ref sa)) = self.serial_area {
            sa.bump_serial_and_wake();
        }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        for (_, area) in &self.areas {
            if let Some(val) = area.get(name) {
                return Some(val);
            }
        }
        None
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        for (_, area) in &self.areas {
            if area.get(name).is_some() {
                area.set(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        for (_, area) in &self.areas {
            if area.writable() {
                area.set(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn set_init(&self, name: &str, value: &str) -> Result<()> {
        for (_, area) in &self.areas {
            if area.get(name).is_some() {
                area.set_init(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        for (_, area) in &self.areas {
            if area.writable() {
                area.set_init(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn set_stealth(&self, name: &str, value: &str) -> Result<()> {
        for (_, area) in &self.areas {
            if area.get(name).is_some() {
                area.set_stealth(name, value)?;
                return Ok(());
            }
        }
        for (_, area) in &self.areas {
            if area.writable() {
                area.set_stealth(name, value)?;
                return Ok(());
            }
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        for (_, area) in &self.areas {
            match area.delete(name) {
                Ok(true) => {
                    self.notify();
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
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
