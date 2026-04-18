//! Tier B per-prop hook installer — stage-A (ELF parse + symbol resolution).
//!
//! P03 Task 4 scope: locate the target process's `libc.so` via `/proc/<pid>/maps`,
//! open the corresponding `/proc/<pid>/map_files/<start>-<end>` snapshot (per
//! phases/seal/references/android-libc-elf.md §1 APEX + §7 ET_DYN runtime
//! address math), parse it through [`seal::elf::parse_libc_elf`], and resolve
//! the `__system_property_update` symbol. Stage-B (remote mmap + prologue
//! snapshot) is deferred to P03 Task 5; the [`HookHandle`] shape is already
//! final so T5 only extends the construction site.
//!
//! All failure paths surface as [`Error::HookInstallFailed`] with a
//! `"stage-A: <step>: <cause>"` prefix per the P03 checklist FR-18/FR-19.

use std::fs::File;

use crate::error::{Error, Result};
use crate::seal;
use crate::seal::maps::MapEntry;

/// Per-prop Tier B hook handle.
///
/// Returned by [`install_init_hook`]. Field layout is locked by the P03 spec —
/// P04 code (same crate) mutates `lock_list_len` / `saved_prologue`; external
/// callers only need the type in their signature, so fields are `pub(crate)`.
/// T5 populates `hook_page` + `saved_prologue`; in T4 they are zero-initialised.
/// `allow(dead_code)` mirrors `LibcElfView` (seal/elf.rs:162): fields land in
/// T4 but are first READ by T5 (hook_page, saved_prologue) and P04 (lock_list_len).
#[allow(dead_code)]
pub struct HookHandle {
    pub(crate) pid: libc::pid_t,
    pub(crate) hook_page: u64,
    pub(crate) lock_list_len: u32,
    pub(crate) target_fn: u64,
    pub(crate) saved_prologue: [u8; 16],
}

/// Predicate picking the executable `libc.so` mapping out of a parsed maps file.
///
/// Two independent gates per spec:
///   1. `perms == b"r-xp"` — skip the r--p / rw-p copies of the same file.
///   2. path ends with `"/libc.so"` (the leading slash is mandatory so
///      `libc_hwasan.so` does NOT false-match — checklist §Self-Audit Gate 4).
pub(crate) fn is_libc_row(entry: &MapEntry) -> bool {
    &entry.perms == b"r-xp"
        && entry
            .path
            .as_ref()
            .and_then(|p| p.as_os_str().to_str())
            .is_some_and(|s| s.ends_with("/libc.so"))
}

/// Stage-A of the hook install pipeline.
///
/// Returns `(libc_base, target_fn)` where `libc_base` is the `r-xp` row's
/// `start` address and `target_fn = libc_base + st_value("__system_property_update")`
/// (ET_DYN runtime math per references/android-libc-elf.md §7).
///
/// Step tags preserved in error messages so operators can see exactly which
/// step failed without enabling debug logging.
pub(crate) fn install_init_hook_stage_a(pid: libc::pid_t) -> Result<(u64, u64)> {
    let entries = seal::maps::parse_maps(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_maps: {e}")))?;

    let libc_row = entries.iter().find(|e| is_libc_row(e)).ok_or_else(|| {
        Error::HookInstallFailed(format!("stage-A: libc row not found in /proc/{pid}/maps"))
    })?;

    let libc_base = libc_row.start;
    let map_path = format!(
        "/proc/{}/map_files/{:x}-{:x}",
        pid, libc_row.start, libc_row.end
    );

    let file = File::open(&map_path)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: open {map_path}: {e}")))?;

    let view = seal::elf::parse_libc_elf(&file)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_libc_elf: {e}")))?;

    let st_value = seal::elf::resolve_symbol(&view, "__system_property_update")
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: resolve_symbol: {e}")))?;

    let target_fn = libc_base
        .checked_add(st_value)
        .ok_or_else(|| Error::HookInstallFailed("stage-A: target_fn overflow".into()))?;

    Ok((libc_base, target_fn))
}

/// Install the per-prop hook in the target process.
///
/// T4 returns a handle with stage-A outputs populated; `hook_page`,
/// `lock_list_len`, and `saved_prologue` remain zero-initialised until T5
/// extends this function with the ptrace-driven remote mmap + prologue snapshot.
pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle> {
    let (_libc_base, target_fn) = install_init_hook_stage_a(pid)?;
    Ok(HookHandle {
        pid,
        hook_page: 0,
        lock_list_len: 0,
        target_fn,
        saved_prologue: [0; 16],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_entry(perms: &[u8; 4], path: Option<&str>) -> MapEntry {
        MapEntry {
            start: 0x7000_0000_0000,
            end: 0x7000_0010_0000,
            perms: *perms,
            offset: 0,
            path: path.map(PathBuf::from),
        }
    }

    /// Verifies the `HookHandle` field layout is reachable by `pub(crate)` access
    /// from within the module. Covers spec item "asserts the struct has the
    /// expected field layout (non-zero fields are reachable via accessors)".
    #[test]
    fn hook_handle_size() {
        let h = HookHandle {
            pid: 42,
            hook_page: 0xdeadbeef_cafebabe,
            lock_list_len: 7,
            target_fn: 0x1234_5678_9abc_def0,
            saved_prologue: [0xAB; 16],
        };
        assert_eq!(h.pid, 42);
        assert_eq!(h.hook_page, 0xdeadbeef_cafebabe);
        assert_eq!(h.lock_list_len, 7);
        assert_eq!(h.target_fn, 0x1234_5678_9abc_def0);
        assert_eq!(h.saved_prologue, [0xAB; 16]);
    }

    /// Exercises `is_libc_row` against the tricky cases called out in the
    /// checklist §Self-Audit Gate 4:
    ///   * APEX bionic path (canonical Android 10+) → match.
    ///   * Bootstrap libc path (early init) → match.
    ///   * `libc_hwasan.so` (suffix trap) → must NOT match.
    ///   * Non-executable row (`r--p`) → must NOT match even with matching name.
    ///   * Anonymous row with no path → must NOT match.
    #[test]
    fn libc_row_filter_r_xp_suffix() {
        let apex = mk_entry(
            b"r-xp",
            Some("/apex/com.android.runtime/lib64/bionic/libc.so"),
        );
        let bootstrap = mk_entry(b"r-xp", Some("/system/lib64/bootstrap/libc.so"));
        let hwasan = mk_entry(
            b"r-xp",
            Some("/apex/com.android.runtime/lib64/bionic/libc_hwasan.so"),
        );
        let wrong_perms = mk_entry(
            b"r--p",
            Some("/apex/com.android.runtime/lib64/bionic/libc.so"),
        );
        let anon = mk_entry(b"r-xp", None);

        assert!(is_libc_row(&apex), "APEX bionic libc.so must match");
        assert!(
            is_libc_row(&bootstrap),
            "/system/lib64/bootstrap/libc.so must match"
        );
        assert!(
            !is_libc_row(&hwasan),
            "libc_hwasan.so must NOT match (suffix trap)"
        );
        assert!(
            !is_libc_row(&wrong_perms),
            "r--p copy must NOT match (wrong perms)"
        );
        assert!(!is_libc_row(&anon), "anonymous row must NOT match");
    }
}
