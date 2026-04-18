//! Tier B per-prop hook installer — stage-A (ELF parse + symbol resolution)
//! and stage-B (remote mmap + prologue snapshot).
//!
//! P03 Task 5 scope: extend T4's stage-A pipeline with the stage-B remote
//! operations that land the handle's `hook_page` and `saved_prologue` fields.
//! Stage-B reuses the same attach / scratch-slot / remote-syscall machinery
//! as `seal::arena::remote_remap_private` (P02): a `RemoteAttach` RAII guard
//! scopes the `PTRACE_SEIZE + INTERRUPT` window, `find_scratch_slot` picks an
//! 8-byte-aligned offset in libc.text, and `remote_syscall_via_poke` executes
//! the remote `mmap` via `PEEK / POKEDATA` (which bypasses VMA write bits and
//! so accepts an `r-xp` scratch PC inside libc.text).
//!
//! # Platform note
//!
//! Stage-B issues AArch64 register-level ptrace operations via
//! `seal::ptrace::remote_syscall_via_poke`. The AArch64-specific register
//! layout (`UserPtRegs`) is cfg-gated at its definition site in
//! `seal::ptrace`, so this module compiles cleanly on x86_64 hosts for dev
//! builds and tests; at runtime stage-B is only meaningful when the tracee
//! is an aarch64 process (Android device targets).
//!
//! All failure paths surface as [`Error::HookInstallFailed`] with a stage-
//! prefixed message (`"stage-A: <step>: <cause>"` /
//! `"stage-B: <step>: <cause>"`) per the P03 checklist FR-18 / FR-19.

use std::fs::File;

use crate::error::{Error, Result};
use crate::seal;
use crate::seal::arena::{find_scratch_slot, NR_MMAP, NR_MUNMAP};
use crate::seal::maps::MapEntry;
use crate::seal::ptrace::{read_remote, remote_syscall_via_poke, write_remote};

// ─────────────────────────────────────────────────────────────────────────────
// Stage-B constants (REGISTRY §1 canonical flag values)
// ─────────────────────────────────────────────────────────────────────────────

/// `PROT_READ | PROT_WRITE | PROT_EXEC` — the hook page must be executable
/// so P04's trampoline can be landed in it, writable so we can stamp the
/// zero sentinel + future lock-list entries, and readable for load paths.
const PROT_RWX: u64 = 0x7;

/// `MAP_PRIVATE | MAP_ANONYMOUS` — anonymous RWX page in the tracee.
const MAP_PRIVATE_ANON: u64 = 0x22;

/// 4 KiB — one base page on AArch64. Mirrors `BOOTSTRAP_PAGE_SIZE` in
/// `seal::arena` but kept local to keep the stage-B constant block self-
/// contained. Kept as `u64` because the remote-syscall ABI is 64-bit and
/// the value flows straight into `remote_syscall_via_poke` args.
const HOOK_PAGE_SIZE: u64 = 4096;

/// Upper bound on how much of libc.text is read while hunting for a scratch
/// slot. Matches `seal::arena::LIBC_SCAN_LIMIT` (64 KiB) so the two stage
/// pipelines share identical scan behaviour.
const LIBC_SCAN_LIMIT: usize = 64 * 1024;

/// Per-prop Tier B hook handle.
///
/// Returned by [`install_init_hook`]. Field layout is locked by the P03 spec —
/// P04 code (same crate) mutates `lock_list_len` / `saved_prologue`; external
/// callers only need the type in their signature, so fields are `pub(crate)`.
/// Stage-B (T5) lands `hook_page` + `saved_prologue`; `lock_list_len` stays
/// at zero because P03 defines the hook page with an empty lock list (the
/// first four bytes are the zero sentinel written below).
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
/// Returns `(libc_base, libc_end, target_fn)` where `libc_base` / `libc_end`
/// are the `r-xp` row's `start` / `end` addresses and
/// `target_fn = libc_base + st_value("__system_property_update")`
/// (ET_DYN runtime math per references/android-libc-elf.md §7).
///
/// Stage-B consumes `libc_end` to size the libc.text scan window; exposing
/// it alongside `libc_base` keeps the maps-lookup cost on a single traversal.
///
/// Step tags preserved in error messages so operators can see exactly which
/// step failed without enabling debug logging.
pub(crate) fn install_init_hook_stage_a(pid: libc::pid_t) -> Result<(u64, u64, u64)> {
    let entries = seal::maps::parse_maps(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_maps: {e}")))?;

    let libc_row = entries.iter().find(|e| is_libc_row(e)).ok_or_else(|| {
        Error::HookInstallFailed(format!("stage-A: libc row not found in /proc/{pid}/maps"))
    })?;

    let libc_base = libc_row.start;
    let libc_end = libc_row.end;
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

    Ok((libc_base, libc_end, target_fn))
}

/// Pick an 8-byte-aligned scratch PC inside libc.text for
/// `remote_syscall_via_poke`.
///
/// Small helper extracted so both the initial install path and
/// `HookHandle::drop_best_effort` share one implementation: attach the
/// tracee first (the caller passes an already-acquired guard), read up to
/// `LIBC_SCAN_LIMIT` bytes of the executable libc mapping via
/// `read_remote`, and delegate slot selection to
/// `seal::arena::find_scratch_slot` (prefers a 4-NOP slide, falls back to
/// the first 8-byte-aligned offset ≥ 64 past section-start trampolines).
///
/// # Safety
///
/// The tracee must be ptrace-stopped for the duration of the call (the
/// caller is expected to hold a live `RemoteAttach`). `libc_base..libc_end`
/// must refer to the tracee's `r-xp` libc mapping.
unsafe fn derive_libc_scratch_pc(pid: libc::pid_t, libc_base: u64, libc_end: u64) -> Result<u64> {
    let libc_text_len = libc_end.saturating_sub(libc_base) as usize;
    let scan_len = core::cmp::min(libc_text_len, LIBC_SCAN_LIMIT);
    let mut scan_buf = vec![0u8; scan_len];

    // SAFETY: `libc_base..libc_base + scan_len` lies inside the tracee's
    // `r-xp` libc mapping (caller contract). `read_remote` uses
    // `process_vm_readv`, which needs only the R bit — satisfied by `r-xp`.
    // The tracee is ptrace-stopped via the caller's `RemoteAttach` guard.
    unsafe { read_remote(pid, libc_base, &mut scan_buf) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: read libc.text: {e}")))?;

    let slide_offset = find_scratch_slot(&scan_buf)
        .ok_or_else(|| Error::HookInstallFailed("stage-B: no scratch slot in libc.text".into()))?;

    Ok(libc_base + slide_offset as u64)
}

/// Install the per-prop hook in the target process.
///
/// Stage-A resolves `__system_property_update` in libc; stage-B reserves an
/// RWX page in the tracee, stamps the zero lock-list sentinel, and snapshots
/// the 16-byte prologue the P04 trampoline will later patch. The returned
/// handle owns the remote page via [`HookHandle`]'s `Drop` impl (best-effort
/// `munmap` via `remote_syscall_via_poke`).
///
/// # Error cleanup note
///
/// If stage-B fails after the `mmap` succeeds, the 4 KiB `hook_page` is
/// LEAKED in the tracee: we never construct a `HookHandle`, so its `Drop`
/// never runs, and issuing a second `RemoteAttach`-scoped `munmap` in the
/// error path would duplicate the P02 round-2 M6 cleanup complexity without
/// buying safety (a 4 KiB leak on a rare cold-path error is acceptable and
/// consistent with arena.rs's bootstrap-page leak policy).
pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle> {
    let (libc_base, libc_end, target_fn) = install_init_hook_stage_a(pid)?;

    let guard = seal::arena::RemoteAttach::new(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: attach: {e}")))?;

    // SAFETY: `guard` holds the tracee ptrace-stopped for the duration of
    // this block; `libc_base..libc_end` is the `r-xp` libc row returned by
    // stage-A on the same process. `remote_syscall_via_poke`'s contract is
    // satisfied by the resulting scratch PC (8-byte-aligned, inside an
    // executable mapping, guarded against concurrent threads by the seize).
    let scratch_pc = unsafe { derive_libc_scratch_pc(pid, libc_base, libc_end) }?;

    // SAFETY: see `derive_libc_scratch_pc` above for the scratch-PC
    // invariants; `remote_syscall_via_poke` itself saves / restores both
    // the 8-byte scratch word and the saved-regs snapshot before returning
    // (see ptrace.rs:669-705), so stage-B does not need an outer restore
    // wrapper around the mmap call.
    let ret = unsafe {
        remote_syscall_via_poke(
            pid,
            scratch_pc,
            NR_MMAP,
            [0, HOOK_PAGE_SIZE, PROT_RWX, MAP_PRIVATE_ANON, u64::MAX, 0],
        )
    }
    .map_err(|e| Error::HookInstallFailed(format!("stage-B: mmap: {e}")))?;

    // Decode mmap's return: Linux returns -errno in the range [-4095, -1]
    // and a valid address otherwise (linux-arm64-abi.md §11). Treat any
    // value in that window as an errno failure regardless of sign bit.
    if (-4095..=-1).contains(&ret) {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: mmap returned -errno={}",
            -ret
        )));
    }
    let hook_page = ret as u64;

    // NOTE: From this point until the handle is returned, a failure leaks
    // `hook_page` (4 KiB RWX) in the tracee. This is deliberate — see the
    // doc comment on `install_init_hook` above.

    // Write the 4-byte zero sentinel (lock-list length = 0). The hook page
    // is PROT_READ | WRITE | EXEC per the mmap args, so `process_vm_writev`
    // inside `write_remote` respects the W bit without needing a POKE
    // transport.
    //
    // SAFETY: `hook_page` was just returned by a successful `mmap` in the
    // tracee; tracee remains ptrace-stopped via `guard`.
    let sentinel = [0u8; 4];
    unsafe { write_remote(pid, hook_page, &sentinel) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: write sentinel: {e}")))?;

    // Snapshot the 16-byte prologue at `target_fn`. P04's trampoline
    // encoder overwrites exactly this window, so preserving the originals
    // lets us revert (or, later, single-step-over) the hook cleanly.
    //
    // SAFETY: `target_fn` points inside libc.text `r-xp`; `read_remote`
    // uses `process_vm_readv` which needs only the R bit.
    let mut saved_prologue = [0u8; 16];
    unsafe { read_remote(pid, target_fn, &mut saved_prologue) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: read prologue: {e}")))?;

    // Explicit detach — reads cleaner than leaving it to Drop, and surfaces
    // any detach failure at the install site rather than swallowing it in
    // `RemoteAttach::drop`.
    guard
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: detach: {e}")))?;

    Ok(HookHandle {
        pid,
        hook_page,
        lock_list_len: 0,
        target_fn,
        saved_prologue,
    })
}

impl HookHandle {
    /// Best-effort remote `munmap` of the hook page during `Drop`.
    ///
    /// Re-derives a libc.text scratch PC because the trampoline has not
    /// been installed yet at P03 scope, so libc.text is still pristine and
    /// a fresh `find_scratch_slot` scan will pick the same slot stage-B
    /// used (or an equivalent one — the restore invariants do not require
    /// identity). Errors propagate back to the `Drop` impl, which
    /// discards them; all failures here are non-recoverable.
    fn drop_best_effort(&self) -> Result<()> {
        let entries = seal::maps::parse_maps(self.pid)?;
        let libc_row = entries
            .iter()
            .find(|e| is_libc_row(e))
            .ok_or_else(|| Error::HookInstallFailed("drop: libc row missing".into()))?;
        let libc_base = libc_row.start;
        let libc_end = libc_row.end;

        let guard = seal::arena::RemoteAttach::new(self.pid)?;

        // SAFETY: `guard` holds the tracee ptrace-stopped; the libc row we
        // just parsed is the same `r-xp` mapping stage-B used.
        let scratch_pc = unsafe { derive_libc_scratch_pc(self.pid, libc_base, libc_end) }?;

        // SAFETY: `scratch_pc` is inside libc.text `r-xp`;
        // `remote_syscall_via_poke` bypasses VMA write bits via
        // PEEK/POKEDATA. `self.hook_page` was returned by stage-B's mmap
        // and is the only argument we pass through to munmap.
        unsafe {
            remote_syscall_via_poke(
                self.pid,
                scratch_pc,
                NR_MUNMAP,
                [self.hook_page, HOOK_PAGE_SIZE, 0, 0, 0, 0],
            )?;
        }

        guard.detach()?;
        Ok(())
    }
}

impl Drop for HookHandle {
    fn drop(&mut self) {
        // Stage-B never completed if `hook_page == 0`, so there is nothing
        // in the tracee to unmap. This covers the checklist edge case
        // "Drop fires before stage-B completes".
        if self.hook_page == 0 {
            return;
        }

        // NOTE for P04: once the trampoline is live at `target_fn`, this
        // Drop MUST NOT unmap `hook_page` — init will be executing inside
        // that page. P04 will either short-circuit Drop (flag on the
        // handle) or revert the trampoline before letting munmap run.
        //
        // Errors from the best-effort path are swallowed: Drop cannot
        // propagate, and panicking here would abort on unwind.
        let _ = self.drop_best_effort();
    }
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

    /// Compile-time confirmation that `HookHandle` implements `Drop`. The
    /// stage-B Drop body exercises `remote_syscall_via_poke` against a
    /// live tracee and is therefore not unit-testable from an x86_64 host;
    /// this check is the narrow invariant we can enforce without device
    /// integration (the `tier_b_child_smoke` integration test lands in
    /// P04 per REGISTRY §3).
    #[test]
    fn handle_drop_is_defined() {
        // `T: Drop` is the exact bound the P03 T5 spec prescribes. Clippy's
        // `drop_bounds` lint prefers `std::mem::needs_drop`, but here we
        // specifically want to assert that `HookHandle` has a user-written
        // `Drop` impl (not merely contains fields that need dropping), so
        // the stronger bound is intentional.
        #[allow(drop_bounds)]
        fn _drop_compiles<T: Drop>() {}
        _drop_compiles::<HookHandle>();
    }
}
