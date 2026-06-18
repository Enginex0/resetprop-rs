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

use std::ffi::CString;
use std::fs::File;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{Error, Result};
use crate::seal;
use crate::seal::arena::{
    find_scratch_slot, MAP_PRIVATE, MAP_PRIVATE_ANON, MFD_CLOEXEC, NR_CLOSE, NR_MEMFD_CREATE,
    NR_MMAP, NR_MUNMAP, PROT_RW, PROT_RX,
};
use crate::seal::maps::MapEntry;
use crate::seal::ptrace::{
    ptrace_poketext, read_remote, remote_syscall_via_poke, run_remote_payload, set_pc, write_remote,
};

// Stage-B constants (REGISTRY §1 canonical flag values)

/// 4 KiB — one base page on AArch64. Mirrors `BOOTSTRAP_PAGE_SIZE` in
/// `seal::arena` but kept local to keep the stage-B constant block self-
/// contained. Kept as `u64` because the remote-syscall ABI is 64-bit and
/// the value flows straight into `remote_syscall_via_poke` args.
const HOOK_PAGE_SIZE: u64 = 4096;

/// Byte offset inside `lock_list_page` where the host-written hook file
/// path is staged before the remote `openat`. Lives past
/// [`LOCK_LIST_CAPACITY`] = 1024 so the hook body's in-page walker never
/// observes the staged path bytes; the bytes are abandoned in place after
/// `openat` returns.
const PATH_STAGE_OFFSET: u64 = 2048;

/// Upper bound on how much of libc.text is read while hunting for a scratch
/// slot. Matches `seal::arena::LIBC_SCAN_LIMIT` (64 KiB) so the two stage
/// pipelines share identical scan behaviour.
const LIBC_SCAN_LIMIT: usize = 64 * 1024;

/// Hard install failures tolerated before [`install_init_hook`] stops
/// attaching for the rest of the process. A seal install pokes init's
/// prologue; a load that keeps failing is a fault that retrying only drives
/// toward a bootloop, so the installer gives up rather than keep hammering
/// PID 1. Mirrors ReZygisk's `MAX_RETRY_COUNT` ptrace-monitor ceiling
/// (loader/src/ptracer/monitor.c).
const MAX_INSTALL_HARD_FAILURES: u32 = 5;

/// Count of hard [`install_init_hook`] failures this process has seen. Module-
/// static rather than a [`HookHandle`] field because a handle only exists
/// after a *successful* install, so the throttle must outlive the failed
/// attempts that never produce one.
static INSTALL_HARD_FAILURES: AtomicU32 = AtomicU32::new(0);

// P04 T3 — hook-page layout and i-cache sync constants

/// Hook page byte offset where [`build_hook_body_bytes`]'s 140-byte body
/// lands in the hook-page mapping. Held at 1024 rather than 0 to keep
/// binary compatibility with existing trampoline encoders and tests that
/// reference the canonical offset; the preceding 1024 bytes of the hook
/// page are zero-padding.
pub(crate) const HOOK_BODY_OFFSET: u64 = 1024;

/// Lock-list byte capacity on `lock_list_page`. Entries live at offsets
/// `0..LOCK_LIST_CAPACITY`; install-time path staging reuses the same
/// page at [`PATH_STAGE_OFFSET`] (= 2048), comfortably beyond this
/// capacity.
///
/// [`seal_prop`] refuses to append when the resulting list would exceed
/// this capacity. Staying under the capacity keeps the hook body's
/// in-page walker bounded away from the staged path bytes.
///
/// Practical envelope: each entry costs `name_len + 1` bytes (name +
/// NUL separator); the list also ends in a trailing sentinel NUL. At
/// an average bionic property name of ~25 bytes, the list saturates at
/// ~37 entries before `seal_prop` starts rejecting with
/// capacity-exceeded. Accepted for the operator-initiated Tier B use
/// case (a handful of keys locked for the lifetime of the boot); a
/// future two-page layout (one RW list page, one RX body page) would
/// remove the cap at the cost of +4 KiB init working set. Reference:
/// `P04-tier-b-part2.md §Operational Envelope`.
pub(crate) const LOCK_LIST_CAPACITY: u64 = 1024;

/// A lock-list entry must never reach the install-time path staged at
/// [`PATH_STAGE_OFFSET`], or the in-init walker would read those path bytes
/// as a lock name. Binding the two constants fails the build on a future
/// capacity bump instead of letting the list silently overrun.
const _: () = assert!(LOCK_LIST_CAPACITY < PATH_STAGE_OFFSET);

/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` — kernel cmd byte
/// that registers the calling task's intent to later issue
/// `PRIVATE_EXPEDITED_SYNC_CORE`. Without this registration, the SYNC_CORE
/// call returns `-EPERM` unconditionally. Init has never registered, so
/// [`install_trampoline`] issues this cmd on init's behalf inside the
/// attach window before the SYNC_CORE. Reference:
/// `references/arm64-a64-encoding.md §i-cache invalidation options` line
/// 422 ("Requires MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
/// (0x40) registration first; kernel ≥ 4.16").
pub(crate) const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 0x40;

/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` — kernel cmd byte for
/// cross-core instruction-cache synchronisation after writing instruction
/// bytes into another process's VMA. Primary i-cache sync path after the
/// trampoline write; must be preceded by
/// [`MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE`] to avoid a
/// guaranteed `-EPERM` return. Reference:
/// `references/arm64-a64-encoding.md §i-cache invalidation options`
/// (linux/membarrier.h cmd enum value).
pub(crate) const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 0x80;

/// `__NR_membarrier` on AArch64 Linux. Source:
/// `asm-generic/unistd.h:683` cited by `linux-arm64-abi.md §1` line 29.
pub(crate) const NR_MEMBARRIER: u64 = 283;

/// Per-prop Tier B hook handle.
///
/// Returned by [`install_init_hook`]. Field layout is locked by the P03 spec —
/// P04 code (same crate) mutates `lock_list_len` / `saved_prologue` and flips
/// `trampoline_installed` to `true` after its prologue patch completes.
/// External callers only need the type in their signature, so fields are
/// `pub(crate)`.
///
/// Cached stage-A context (`libc_base`, `libc_end`, `scratch_pc`) lets
/// [`HookHandle::drop_best_effort`] reuse the install-time scratch PC
/// instead of re-parsing `/proc/<pid>/maps` and re-scanning libc.text at
/// Drop time. This removes a class of TOCTOU bugs (libc hot-swap between
/// install and drop re-deriving into a different VMA) and simplifies the
/// Drop body; the remaining stale-scratch edge case (hot-swap AFTER
/// install) surfaces as EFAULT/ESRCH from `remote_syscall_via_poke`, which
/// Drop already swallows under best-effort semantics.
#[allow(dead_code)]
pub struct HookHandle {
    pub(crate) pid: libc::pid_t,
    /// `PROT_READ | PROT_EXEC` page in the tracee holding the 140-byte hook
    /// body at [`HOOK_BODY_OFFSET`], mapped from an anonymous `memfd` the
    /// tracee created and this process filled. The fd is closed after mmap;
    /// the mapping survives via the fd's anonymous inode, leaving no on-disk
    /// residue.
    pub(crate) hook_page: u64,
    /// Anonymous `PROT_READ | PROT_WRITE` page in the tracee holding the
    /// variable-length lock list at offset 0 (up to [`LOCK_LIST_CAPACITY`]
    /// bytes). Written by [`seal_prop`] / [`unseal_prop`] via
    /// `process_vm_writev`; read by the hook body via a PC-relative
    /// literal baked in at install time.
    pub(crate) lock_list_page: u64,
    pub(crate) lock_list_len: u32,
    pub(crate) target_fn: u64,
    pub(crate) saved_prologue: [u8; 16],
    pub(crate) libc_base: u64,
    pub(crate) libc_end: u64,
    pub(crate) scratch_pc: u64,
    /// Typestate guard for Drop.
    ///
    /// Flipped to `true` by P04 after the trampoline is live at `target_fn`.
    /// Once true, Drop MUST NOT unmap either page — init is executing
    /// inside `hook_page` and reading the lock list from `lock_list_page`
    /// on every property update. P04 reverts the trampoline and unmaps
    /// both pages explicitly before the handle is dropped.
    pub(crate) trampoline_installed: bool,
    /// `/dev/kmsg` file descriptors init held open at install time, discovered
    /// from `/proc/<pid>/fd` (Port 2). The observe-init snoop reads these to
    /// recognise `write(kmsg_fd, …)` traffic among init's syscalls.
    pub(crate) kmsg_fds: Vec<u64>,
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

/// Locate the executable `libc.so` row in a parsed maps file via the hardened
/// [`is_libc_row`] gate. Stage-A and the Tier A remap share this so both pin
/// libc.text by the identical rule rather than drifting predicates.
pub(crate) fn find_libc_text_row(entries: &[MapEntry]) -> Option<&MapEntry> {
    entries.iter().find(|e| is_libc_row(e))
}

/// Stage-A of the hook install pipeline — RUN UNDER ATTACH.
///
/// Returns `(libc_base, libc_end, target_fn)` where `libc_base` / `libc_end`
/// are the `r-xp` row's `start` / `end` addresses and `target_fn` is
/// `__system_property_update` resolved against the ELF load bias
/// (`libc_base - r-xp file offset`), not against `libc_base` itself — the
/// executable segment is mapped at a non-zero file offset (ET_DYN runtime math
/// per references/android-libc-elf.md §7).
///
/// This MUST be called while the caller holds a live `RemoteAttach` on
/// `pid`. Every stage-A observation — `/proc/<pid>/maps`, the libc row,
/// `/proc/<pid>/map_files/<start>-<end>`, the parsed symbol — is a snapshot
/// of the tracee's address space, and running outside the attach window
/// opens a TOCTOU gap (APEX hot-swap / Mainline update) that lets stage-B
/// consume stale `(libc_base, libc_end, target_fn)` tuples. Mirrors P02's
/// pattern at `arena.rs:278-304` (attach, then parse maps).
///
/// Step tags preserved in error messages so operators can see exactly which
/// step failed without enabling debug logging.
fn stage_a_locked(pid: libc::pid_t) -> Result<(u64, u64, u64)> {
    let entries = seal::maps::parse_maps(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_maps: {e}")))?;

    let libc_row = find_libc_text_row(&entries).ok_or_else(|| {
        Error::HookInstallFailed(format!("stage-A: libc row not found in /proc/{pid}/maps"))
    })?;

    let libc_base = libc_row.start;
    let libc_end = libc_row.end;
    let libc_text_offset = libc_row.offset;

    // Some Android kernels (observed on Xiaomi 2409BRN2CA, Android 15, kernel
    // 6.6.58) expose /proc/<pid>/map_files at VMA granularity while
    // /proc/<pid>/maps splits by permission region — so libc_row.end may not
    // match the map_files entry's end (the kernel fuses the r-xp region with
    // an adjacent guard-page hole under the same VMA). Locate the entry by
    // its start address, which is stable across both views.
    let map_files_dir = format!("/proc/{pid}/map_files");
    let start_prefix = format!("{libc_base:x}-");
    let map_path = std::fs::read_dir(&map_files_dir)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: read_dir {map_files_dir}: {e}")))?
        .filter_map(std::result::Result::ok)
        .find(|ent| {
            ent.file_name()
                .to_str()
                .is_some_and(|s| s.starts_with(&start_prefix))
        })
        .ok_or_else(|| {
            Error::HookInstallFailed(format!(
                "stage-A: no map_files entry starting at {libc_base:x} in {map_files_dir}"
            ))
        })?
        .path();

    let file = File::open(&map_path).map_err(|e| {
        Error::HookInstallFailed(format!("stage-A: open {}: {e}", map_path.display()))
    })?;

    let view = seal::elf::parse_libc_elf(&file)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_libc_elf: {e}")))?;

    let st_value = seal::elf::resolve_symbol(&view, "__system_property_update")
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: resolve_symbol: {e}")))?;

    // A symbol's st_value is a vaddr relative to the ELF load bias, not to the
    // executable segment's mapped start. bionic's libc maps its r-xp segment at
    // a non-zero file offset (0x44000 on Android 15 bootstrap libc), and for
    // these page-aligned PT_LOADs p_vaddr == p_offset, so the load bias is the
    // segment's mapped start minus that file offset. Adding st_value to
    // libc_base directly overshoots by the file offset and lands the trampoline
    // in a neighbouring function.
    let load_bias = libc_base
        .checked_sub(libc_text_offset)
        .ok_or_else(|| Error::HookInstallFailed("stage-A: libc load bias underflow".into()))?;
    let target_fn = load_bias
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
/// Runs under a single `RemoteAttach` window so the tracee's address
/// space cannot shift (APEX hot-swap, Mainline update) between
/// observation and use. The returned handle owns two remote pages
/// whose lifecycle is tracked by [`HookHandle::drop`].
///
/// # Page layout
///
/// * `lock_list_page`: anonymous `PROT_READ | PROT_WRITE`. Holds the
///   runtime lock list at offset 0 (up to [`LOCK_LIST_CAPACITY`] bytes)
///   and temporarily stages the memfd name at [`PATH_STAGE_OFFSET`]
///   during this install only.
/// * `hook_page`: `PROT_READ | PROT_EXEC`, mapped from an anonymous
///   `memfd` the tracee created. Contains the 140-byte hook body at
///   [`HOOK_BODY_OFFSET`]; zero padding elsewhere.
///
/// The memfd relabel is what lets stage-B run on OEMs that strip
/// `process:execmem` from init's SELinux domain: the fd is relabelled to
/// the libc.so context init may execute, via `setfilecon` on
/// `/proc/<pid>/fd/<memfd>`, so init maps it `PROT_R|X` without an
/// `execmem` or file-execute denial. Nothing reaches disk, so there is no
/// residue to unlink.
///
/// # Error cleanup
///
/// Any error after `lock_list_page` is mapped issues a best-effort
/// remote `munmap` of `lock_list_page` under the same attach window,
/// so the tracee does not leak a 4 KiB page on cold paths. The memfd is
/// closed in the tracee inside the installer on every path.
///
/// # Latency
///
/// The install runs inside one `RemoteAttach` window. Observed
/// wall-clock on a modern ARM64 handset (Snapdragon-class SoC, bionic
/// libc.so ~1.2 MiB, ~5000 `.dynsym` entries): 20-50 ms for the full
/// sequence of `/proc/<pid>/maps`, libc ELF parse, GNU_HASH walk,
/// lock-list mmap, prologue snapshot, remote memfd_create, procfs write,
/// relabel, and remote mmap / close. Any thread that blocks on init for
/// a property write during this window waits out the full stall.
///
/// # Throttle
///
/// After [`MAX_INSTALL_HARD_FAILURES`] hard failures in one process the
/// installer refuses further attempts before the M1 identity check or any
/// ptrace attach, so a load that bootloops init cannot be retried into the
/// ground.
pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle> {
    if INSTALL_HARD_FAILURES.load(Ordering::Relaxed) >= MAX_INSTALL_HARD_FAILURES {
        return Err(Error::HookInstallFailed(format!(
            "install throttled after {MAX_INSTALL_HARD_FAILURES} hard failures this boot"
        )));
    }
    install_init_hook_inner(pid).inspect_err(|_| {
        INSTALL_HARD_FAILURES.fetch_add(1, Ordering::Relaxed);
    })
}

/// Uncounted install body. [`install_init_hook`] wraps this with the per-boot
/// hard-failure throttle; every `Err` it returns advances the counter that
/// eventually trips the guard.
fn install_init_hook_inner(pid: libc::pid_t) -> Result<HookHandle> {
    // M1: reject a non-init PID-1 stand-in before attaching or poking.
    seal::arena::verify_init_identity(pid)?;

    let attach = seal::arena::RemoteAttach::new(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: attach: {e}")))?;

    let handle = install_init_hook_locked(&attach)?;

    attach
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: detach: {e}")))?;

    Ok(handle)
}

/// Stage-B install body under a caller-held [`RemoteAttach`].
///
/// The attach/detach lives in the caller so the first-seal path
/// ([`install_and_seal_first`]) can run install + trampoline + first append
/// under one thread-group stop (audit M5) instead of three. The identity guard
/// and the per-boot throttle stay in the public wrappers; this body assumes a
/// live, identity-checked attach on init.
fn install_init_hook_locked(attach: &seal::arena::RemoteAttach) -> Result<HookHandle> {
    let pid = attach.pid();

    let (libc_base, libc_end, target_fn) = stage_a_locked(pid)?;

    // SAFETY: `attach` holds the tracee ptrace-stopped; `libc_base..libc_end`
    // is the `r-xp` row just returned by stage-A on the same process.
    let scratch_pc = unsafe { derive_libc_scratch_pc(pid, libc_base, libc_end) }?;

    let lock_list_page = remote_mmap_anon_rw_page(pid, scratch_pc)?;

    let saved_prologue = match write_sentinel_and_snapshot_prologue(pid, lock_list_page, target_fn)
    {
        Ok(p) => p,
        Err(e) => {
            best_effort_remote_munmap(pid, scratch_pc, lock_list_page);
            return Err(e);
        }
    };

    let body_bytes = build_hook_body_bytes(saved_prologue, lock_list_page, target_fn + 16);

    let hook_page = match install_memfd_hook_page(pid, scratch_pc, lock_list_page, &body_bytes) {
        Ok(addr) => addr,
        Err(e) => {
            best_effort_remote_munmap(pid, scratch_pc, lock_list_page);
            return Err(e);
        }
    };

    Ok(HookHandle {
        pid,
        hook_page,
        lock_list_page,
        lock_list_len: 0,
        target_fn,
        saved_prologue,
        libc_base,
        libc_end,
        scratch_pc,
        trampoline_installed: false,
        kmsg_fds: seal::kmsg_observer::discover_kmsg_fds(pid),
    })
}

/// Outcome of [`install_and_seal_first`].
///
/// Once [`install_trampoline_locked`] flips the trampoline live, init is
/// modified and the handle MUST be recorded by the caller — even if the first
/// append then fails — so the next seal retries the append against the live
/// hook instead of re-installing over already-trampolined init. A re-install
/// would snapshot the trampoline itself as the "original" prologue (see
/// `write_sentinel_and_snapshot_prologue`) and corrupt the restore path.
pub(crate) enum FirstSeal {
    /// Hook installed and the first property appended to the lock list.
    Sealed(HookHandle),
    /// Hook installed (trampoline live) but the first append failed. The caller
    /// must still record the handle; the `Error` is the append failure to
    /// surface to the user.
    InstalledNotSealed(HookHandle, Error),
}

/// Install the per-prop hook AND seal the first property under one
/// thread-group stop on `pid` (audit M5).
///
/// The seal orchestrator used to issue three separate SEIZE/INTERRUPT/DETACH
/// cycles on PID 1 for the first seal — one each for [`install_init_hook`],
/// [`install_trampoline`], and [`seal_prop`]. Folding them under a single
/// [`RemoteAttach`] shrinks the interval init's siblings spend frozen and the
/// number of attach/detach races on PID 1. Subsequent seals (hook already
/// installed) keep using [`seal_prop`] with its own short window.
///
/// The per-boot install throttle counts failures to *install* the hook
/// (identity, attach, stage-A, trampoline) — the steps that can bootloop init —
/// so a load that bootloops the trampoline patch cannot be retried into the
/// ground. A failure of only the first append does NOT count: the hook is
/// installed and returned via [`FirstSeal::InstalledNotSealed`] so the next
/// seal retries the append.
pub(crate) fn install_and_seal_first(pid: libc::pid_t, name: &str) -> Result<FirstSeal> {
    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidKey);
    }
    if INSTALL_HARD_FAILURES.load(Ordering::Relaxed) >= MAX_INSTALL_HARD_FAILURES {
        return Err(Error::HookInstallFailed(format!(
            "install throttled after {MAX_INSTALL_HARD_FAILURES} hard failures this boot"
        )));
    }
    install_and_seal_first_inner(pid, name).inspect_err(|_| {
        INSTALL_HARD_FAILURES.fetch_add(1, Ordering::Relaxed);
    })
}

/// Uncounted first-seal body. [`install_and_seal_first`] wraps this with the
/// per-boot throttle; only an `Err` here (an install failure) advances the
/// counter — an installed-but-unsealed outcome is `Ok`.
fn install_and_seal_first_inner(pid: libc::pid_t, name: &str) -> Result<FirstSeal> {
    // M1: reject a non-init PID-1 stand-in before attaching or poking.
    seal::arena::verify_init_identity(pid)?;

    let attach = seal::arena::RemoteAttach::new(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: attach: {e}")))?;

    // Phase 1a — install the hook page. On failure `install_init_hook_locked`
    // has already freed its own partial mappings; nothing to preserve.
    let mut handle = match install_init_hook_locked(&attach) {
        Ok(handle) => handle,
        Err(e) => {
            if let Err(detach_err) = attach.detach() {
                eprintln!("resetprop: detach after first-seal install error failed: {detach_err}");
            }
            return Err(e);
        }
    };

    // Phase 1b — patch the trampoline. On failure it has reverted its own
    // partial write, so init is unmodified. Detach FIRST so the dropped
    // handle's `drop_best_effort` can re-attach and free the two install pages
    // (its nested attach would fail if init were still seized here), then
    // propagate the `Err` (which the throttle counts).
    if let Err(e) = install_trampoline_locked(&attach, &mut handle) {
        if let Err(detach_err) = attach.detach() {
            eprintln!("resetprop: detach after first-seal trampoline error failed: {detach_err}");
        }
        return Err(e);
    }

    // Phase 2 — first append. The trampoline is live now, so the handle MUST
    // reach the caller regardless of the append outcome; a lost handle here
    // would make the next seal re-install over trampolined init. Detach runs
    // unconditionally so init is never left stopped; a detach failure (init
    // frozen) outranks the append result and surfaces as a hard `Err`.
    let append = seal_prop_locked(&attach, &mut handle, name);
    attach
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: detach: {e}")))?;

    match append {
        Ok(()) => Ok(FirstSeal::Sealed(handle)),
        Err(e) => Ok(FirstSeal::InstalledNotSealed(handle, e)),
    }
}

/// Result of a [`check_init_hook`] dry-run: the stage-A / scratch-slot facts
/// that the real install would compute, surfaced for an operator to validate
/// on-device before committing to the trampoline patch.
///
/// Every field is a pure observation — no page was mapped, no prologue byte
/// was written. `target_fn` is `__system_property_update` resolved in init's
/// running libc; `scratch_pc` is the 8-byte-aligned slot the install would
/// reuse for `remote_syscall_via_poke`.
pub struct CheckReport {
    pub libc_base: u64,
    pub libc_end: u64,
    pub target_fn: u64,
    pub scratch_pc: u64,
}

/// Dry-run the per-prop hook install: resolve everything the real path reads,
/// write nothing.
///
/// Runs ONLY the no-side-effect sub-ops of [`install_init_hook`] — identity
/// check, stage-A (`/proc/<pid>/maps` + libc ELF + symbol resolution), and
/// scratch-slot derivation — under the same single `RemoteAttach` window, then
/// detaches. The attach is `PTRACE_SEIZE + INTERRUPT` (a group-stop control
/// op, not a memory write); it exists so `derive_libc_scratch_pc`'s
/// `process_vm_readv` snapshot of libc.text cannot race a concurrent
/// APEX/Mainline hot-swap. No `remote_syscall_via_poke`, `ptrace_poketext`, or
/// `write_remote` runs on this path, so init's text and registers are left
/// byte-for-byte unchanged and no trampoline is installed.
///
/// Lets an operator confirm Tier B will resolve cleanly (no `SymbolNotFound`,
/// no missing libc row, a usable scratch slot) on a given device before the
/// real `--seal` pokes PID 1.
pub fn check_init_hook(pid: libc::pid_t) -> Result<CheckReport> {
    // M1: reject a non-init PID-1 stand-in before attaching.
    seal::arena::verify_init_identity(pid)?;

    let guard = seal::arena::RemoteAttach::new(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: attach: {e}")))?;

    let (libc_base, libc_end, target_fn) = stage_a_locked(pid)?;

    // SAFETY: `guard` holds the tracee ptrace-stopped; `libc_base..libc_end`
    // is the `r-xp` row just returned by stage-A on the same process.
    let scratch_pc = unsafe { derive_libc_scratch_pc(pid, libc_base, libc_end) }?;

    // No writes happened — detach and report. (Drop would resume the group
    // too, but detaching explicitly keeps the no-side-effect contract obvious
    // and surfaces a detach error rather than swallowing it.)
    guard
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: detach: {e}")))?;

    Ok(CheckReport {
        libc_base,
        libc_end,
        target_fn,
        scratch_pc,
    })
}

/// Allocate a fresh 4 KiB `PROT_READ | PROT_WRITE` anonymous page in the
/// tracee. Used for both the runtime lock list and as the staging buffer
/// for the hook file path during install.
fn remote_mmap_anon_rw_page(pid: libc::pid_t, scratch_pc: u64) -> Result<u64> {
    // SAFETY: scratch_pc is validated by `derive_libc_scratch_pc`;
    // `remote_syscall_via_poke` saves / restores scratch word + regs.
    let ret = unsafe {
        remote_syscall_via_poke(
            pid,
            scratch_pc,
            NR_MMAP,
            [0, HOOK_PAGE_SIZE, PROT_RW, MAP_PRIVATE_ANON, u64::MAX, 0],
        )
    }
    .map_err(|e| Error::HookInstallFailed(format!("stage-B: mmap anon RW: {e}")))?;

    if (-4095..=-1).contains(&ret) {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: mmap anon RW returned -errno={}",
            -ret
        )));
    }
    Ok(ret as u64)
}

/// Write the empty-list sentinel to `lock_list_page + 0` (one NUL marks the
/// list empty; the write zeroes a 4-byte word) and snapshot the 16-byte
/// prologue at `target_fn`.
fn write_sentinel_and_snapshot_prologue(
    pid: libc::pid_t,
    lock_list_page: u64,
    target_fn: u64,
) -> Result<[u8; 16]> {
    // SAFETY: `lock_list_page` is the fresh PROT_RW page; tracee stopped.
    unsafe { write_remote(pid, lock_list_page, &[0u8; 4]) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: write sentinel: {e}")))?;

    // SAFETY: `target_fn` is inside libc.text r-xp; read_remote needs R only.
    let mut saved_prologue = [0u8; 16];
    unsafe { read_remote(pid, target_fn, &mut saved_prologue) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: read prologue: {e}")))?;
    Ok(saved_prologue)
}

/// Name attached to the in-init memfd; surfaces only as the basename in
/// `/proc/<pid>/fd/<n>` and `/proc/<pid>/maps`. Cosmetic, not a real path.
const MEMFD_NAME: &[u8] = b"resetprop-hook";

/// Materialise the hook body as a `PROT_READ | PROT_EXEC` mapping in the
/// tracee, backed by an anonymous in-memory file. No bytes reach disk.
///
/// Ported from injectrc's init_injector: the tracee creates a `memfd`, this
/// process fills it through `/proc/<pid>/fd/<memfd>` and relabels it to the
/// libc.so SELinux context, then the tracee maps and closes its own fd. The
/// mapping outlives the close via the fd's anonymous inode, so there is no
/// on-disk residue and no `adb_data_file:file execute` denial to dodge.
fn install_memfd_hook_page(
    pid: libc::pid_t,
    scratch_pc: u64,
    stage_page: u64,
    body_bytes: &[u8],
) -> Result<u64> {
    let page = layout_hook_page_bytes(body_bytes)?;
    let name_vaddr = stage_cstr_in_tracee(pid, stage_page, MEMFD_NAME)?;
    run_memfd_install(
        name_vaddr,
        // SAFETY: tracee is ptrace-stopped under the caller's attach;
        // `scratch_pc` is a libc.text r-xp slot valid for the POKE-driven
        // remote syscall ABI.
        |syscall_no, args| unsafe { remote_syscall_via_poke(pid, scratch_pc, syscall_no, args) },
        |memfd| publish_page_to_memfd(pid, memfd, &page),
    )
}

/// Drive the memfd install sequence: remote `memfd_create`, host-side
/// `publish` (fill + relabel the fd), remote `mmap` `PROT_R|X`, remote
/// `close`. Generic over the remote-syscall executor and `publish` so the
/// sequence is exercised off-device with both mocked.
fn run_memfd_install<S, P>(name_vaddr: u64, mut remote_syscall: S, publish: P) -> Result<u64>
where
    S: FnMut(u64, [u64; 6]) -> Result<i64>,
    P: FnOnce(u64) -> Result<()>,
{
    let memfd = remote_syscall(NR_MEMFD_CREATE, [name_vaddr, MFD_CLOEXEC, 0, 0, 0, 0])?;
    if memfd < 0 {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: memfd_create returned -errno={}",
            -memfd
        )));
    }
    let memfd = memfd as u64;

    publish(memfd)?;

    let mapped = remote_syscall(NR_MMAP, [0, HOOK_PAGE_SIZE, PROT_RX, MAP_PRIVATE, memfd, 0])?;
    if (-4095..=-1).contains(&mapped) {
        let _ = remote_syscall(NR_CLOSE, [memfd, 0, 0, 0, 0, 0]);
        return Err(Error::HookInstallFailed(format!(
            "stage-B: memfd mmap returned -errno={}",
            -mapped
        )));
    }

    let _ = remote_syscall(NR_CLOSE, [memfd, 0, 0, 0, 0, 0]);
    Ok(mapped as u64)
}

/// `/proc/<pid>/fd/<fd>`: the procfs handle this process writes the page
/// image through and relabels.
fn proc_fd_path(pid: libc::pid_t, fd: u64) -> String {
    format!("/proc/{pid}/fd/{fd}")
}

/// Fill init's `memfd` with the 4 KiB page image through `/proc/<pid>/fd/<memfd>`
/// and relabel it to the libc.so SELinux context so init can map it `PROT_R|X`.
/// Runs while the tracee is ptrace-stopped under the caller's attach.
fn publish_page_to_memfd(pid: libc::pid_t, memfd: u64, page: &[u8]) -> Result<()> {
    let fd_path = proc_fd_path(pid, memfd);
    std::fs::write(&fd_path, page)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: write {fd_path}: {e}")))?;
    let c_path = CString::new(fd_path.clone())
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: nul in {fd_path}: {e}")))?;
    seal::selinux::relabel_to_libc_context(&c_path)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: relabel memfd: {e}")))
}

/// Pure helper: assemble a 4 KiB page image with `body_bytes` placed at
/// [`HOOK_BODY_OFFSET`], zero-padded elsewhere. Errors if the body
/// would overflow the page.
fn layout_hook_page_bytes(body_bytes: &[u8]) -> Result<Vec<u8>> {
    let body_start = HOOK_BODY_OFFSET as usize;
    let body_end = body_start
        .checked_add(body_bytes.len())
        .ok_or_else(|| Error::HookInstallFailed("stage-B: hook body offset overflow".into()))?;
    if body_end > HOOK_PAGE_SIZE as usize {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: hook body ({} bytes) exceeds page capacity at offset {}",
            body_bytes.len(),
            HOOK_BODY_OFFSET
        )));
    }
    let mut bytes = vec![0u8; HOOK_PAGE_SIZE as usize];
    bytes[body_start..body_end].copy_from_slice(body_bytes);
    Ok(bytes)
}

/// POKE a NUL-terminated C string into the tracee at `stage_page +
/// PATH_STAGE_OFFSET` and return its tracee vaddr. Stages the memfd name; the
/// bytes are abandoned once `memfd_create` reads them. The slot sits above
/// [`LOCK_LIST_CAPACITY`] (const-asserted below it), so the in-init lock
/// walker never reaches these bytes.
fn stage_cstr_in_tracee(pid: libc::pid_t, stage_page: u64, bytes: &[u8]) -> Result<u64> {
    let max_bytes = HOOK_PAGE_SIZE
        .saturating_sub(PATH_STAGE_OFFSET)
        .saturating_sub(1);
    if (bytes.len() as u64) > max_bytes {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: staged string too long ({} bytes, max {})",
            bytes.len(),
            max_bytes
        )));
    }
    let vaddr = stage_page + PATH_STAGE_OFFSET;
    let mut nul = Vec::with_capacity(bytes.len() + 1);
    nul.extend_from_slice(bytes);
    nul.push(0);
    // SAFETY: `stage_page` is the fresh PROT_RW anon page; tracee stopped.
    unsafe { write_remote(pid, vaddr, &nul) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: stage string: {e}")))?;
    Ok(vaddr)
}

/// Best-effort remote `munmap` for cleanup paths. Errors are swallowed.
fn best_effort_remote_munmap(pid: libc::pid_t, scratch_pc: u64, addr: u64) {
    // SAFETY: caller holds the tracee ptrace-stopped.
    let _ = unsafe {
        remote_syscall_via_poke(
            pid,
            scratch_pc,
            NR_MUNMAP,
            [addr, HOOK_PAGE_SIZE, 0, 0, 0, 0],
        )
    };
}

impl HookHandle {
    /// Best-effort remote `munmap` of both pages during `Drop`.
    ///
    /// Reuses `self.scratch_pc` (cached at install time) instead of
    /// re-parsing `/proc/<pid>/maps`, so Drop cannot be thrown off by
    /// a post-install libc hot-swap into a new VMA. The remaining
    /// stale-scratch edge case (libc hot-swap AFTER install so the old
    /// PC is no longer executable) surfaces as EFAULT/ESRCH from
    /// `remote_syscall_via_poke`, which the caller swallows under
    /// best-effort semantics.
    ///
    /// Both munmaps run under a single `RemoteAttach`. If the first
    /// munmap errors the second still executes, so a failing
    /// `lock_list_page` unmap does not leak `hook_page`.
    fn drop_best_effort(&self) -> Result<()> {
        let guard = seal::arena::RemoteAttach::new(self.pid)?;

        // SAFETY: `guard` holds the tracee ptrace-stopped; `scratch_pc` is
        // the cached install-time libc.text slot; both pages were returned
        // by successful remote mmaps inside `install_init_hook`.
        let list_ret = unsafe {
            remote_syscall_via_poke(
                self.pid,
                self.scratch_pc,
                NR_MUNMAP,
                [self.lock_list_page, HOOK_PAGE_SIZE, 0, 0, 0, 0],
            )
        };
        // SAFETY: same invariants as above.
        let hook_ret = unsafe {
            remote_syscall_via_poke(
                self.pid,
                self.scratch_pc,
                NR_MUNMAP,
                [self.hook_page, HOOK_PAGE_SIZE, 0, 0, 0, 0],
            )
        };

        guard.detach()?;
        list_ret?;
        hook_ret?;
        Ok(())
    }
}

impl Drop for HookHandle {
    fn drop(&mut self) {
        // Typestate guards (M5):
        //
        // * `trampoline_installed` — init is executing inside `hook_page`
        //   and reading the lock list from `lock_list_page` on every
        //   property update. Unmapping either page would crash init. P04
        //   reverts the trampoline and unmaps both pages explicitly
        //   before the handle is dropped.
        // * Either page == 0 — stage-B never produced a fully constructed
        //   handle (test factory or abandoned error path). Nothing to
        //   unmap in the tracee.
        //
        // Errors from the best-effort path are swallowed: Drop cannot
        // propagate, and panicking here would abort on unwind.
        if self.trampoline_installed {
            return;
        }
        if self.hook_page == 0 || self.lock_list_page == 0 {
            return;
        }
        let _ = self.drop_best_effort();
    }
}

/// A64 (ARM64) instruction encoders.
///
/// Every output is an aligned little-endian `u32` word. All encoders are
/// `const fn` with inline `assert!` guards on immediate ranges; they run at
/// compile time when invoked inside a `const` context and panic at runtime
/// when out-of-range arguments are passed in a non-const call site.
///
/// # References
///
/// * ARM DDI 0487 Part C, Chapter C6 — A64 base instructions.
/// * `phases/seal/references/arm64-a64-encoding.md` — canonical opcode
///   table and bit-layout mirrors used by this module.
/// * REGISTRY §1 rows `Trampoline — 16 bytes at symbol entry`,
///   `Trampoline LDR opcode for ldr x16,[pc,#8]`, `ARM64 encoder` —
///   locked canonical hex values (`NOP=0xd503201f`, `RET=0xd65f03c0`,
///   `ISB=0xd5033fdf`, `SVC #0=0xd4000001`, `BRK #0=0xd4200000`,
///   `LDR x16,[pc,#8]=0x58000050`, `BR x16=0xd61f0200`).
///
/// Scope: Task 1 of P04 ships exactly the 7 consts + 15 helpers the phase
/// spec enumerates; no additional abstractions are introduced. Task 2 /
/// Task 3 of the same phase will consume these from `build_hook_body_bytes`
/// and `install_trampoline`; until then the symbols are dead from the
/// library's perspective, hence the module-level `allow(dead_code)`.
#[allow(dead_code)]
pub(crate) mod encoder {
    /// Signed-range check for a two's-complement `bits`-wide immediate.
    ///
    /// Used by branch / PC-relative encoders to guard the imm19 / imm26
    /// fields before masking.
    #[inline]
    const fn fits_signed(v: i32, bits: u32) -> bool {
        let half = 1i32 << (bits - 1);
        v >= -half && v < half
    }

    /// Mask `v` into the low `bits` bits as an unsigned value. Callers must
    /// have already verified the range via `fits_signed`.
    #[inline]
    const fn mask_signed(v: i32, bits: u32) -> u32 {
        (v as u32) & ((1u32 << bits) - 1)
    }

    /// `nop` — canonical hint encoding (C6.2.273).
    pub const NOP: u32 = 0xd503_201f;

    /// `ret x30` — C6.2.312 with Rn=30.
    pub const RET_X30: u32 = 0xd65f_03c0;

    /// `isb sy` — C6.2.187 with CRm=0b1111.
    pub const ISB_SY: u32 = 0xd503_3fdf;

    /// `svc #0` — C6.2.392, LL=01.
    pub const SVC_0: u32 = 0xd400_0001;

    /// `brk #0` — C6.2.44, LL=00.
    pub const BRK_0: u32 = 0xd420_0000;

    /// `ldr x16, [pc, #8]` — trampoline first word (REGISTRY §1).
    pub const LDR_X16_PC8: u32 = 0x5800_0050;

    /// `br x16` — trampoline second word (REGISTRY §1).
    pub const BR_X16: u32 = 0xd61f_0200;

    /// `svc #imm16` (C6.2.392). `imm16` occupies bits [20:5].
    pub const fn svc(imm16: u16) -> u32 {
        0xd400_0001 | ((imm16 as u32) << 5)
    }

    /// `brk #imm16` (C6.2.44). `imm16` occupies bits [20:5].
    pub const fn brk(imm16: u16) -> u32 {
        0xd420_0000 | ((imm16 as u32) << 5)
    }

    /// `ret xN` (C6.2.312). Rn in bits [9:5]; default arch alias uses Rn=30.
    pub const fn ret(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd65f_0000 | ((rn as u32) << 5)
    }

    /// `br xN` (C6.2.41). Rn in bits [9:5].
    pub const fn br(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd61f_0000 | ((rn as u32) << 5)
    }

    /// `blr xN` (C6.2.40). Rn in bits [9:5]; writes X30.
    pub const fn blr(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd63f_0000 | ((rn as u32) << 5)
    }

    /// `ldr xt, [pc, #byte_offset]` (C6.2.200). `byte_offset` must be ×4
    /// and its imm19 field must fit a signed 19-bit value.
    pub const fn ldr_literal(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0x5800_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `add xd, xn, #imm12` (C6.2.4, sf=1, sh=0). `imm12` must fit 12 bits.
    pub const fn add_imm64(rd: u8, rn: u8, imm12: u16) -> u32 {
        assert!(rd < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
        0x9100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rd as u32)
    }

    /// `movz xd, #imm16, LSL #(hw*16)` (C6.2.271, sf=1). `hw` in 0..=3.
    pub const fn movz(rd: u8, imm16: u16, hw: u8) -> u32 {
        assert!(rd < 32 && hw < 4);
        0xd280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
    }

    /// `movk xd, #imm16, LSL #(hw*16)` (C6.2.270, sf=1). `hw` in 0..=3.
    pub const fn movk(rd: u8, imm16: u16, hw: u8) -> u32 {
        assert!(rd < 32 && hw < 4);
        0xf280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
    }

    /// `cbz xt, #byte_offset` (C6.2.48, sf=1). Signed 21-bit range, ×4.
    pub const fn cbz(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0xb400_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `cbnz xt, #byte_offset` (C6.2.47, sf=1). Signed 21-bit range, ×4.
    pub const fn cbnz(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0xb500_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `b #byte_offset` (C6.2.34). Signed 28-bit range, ×4.
    pub const fn b_rel(byte_offset: i32) -> u32 {
        assert!(byte_offset % 4 == 0);
        let imm26 = byte_offset / 4;
        assert!(fits_signed(imm26, 26));
        0x1400_0000 | mask_signed(imm26, 26)
    }

    /// `ldrb wt, [xn, #imm12]` unsigned-offset form (C6.2.203). Byte-scaled.
    pub const fn ldrb_imm(rt: u8, rn: u8, imm12: u16) -> u32 {
        assert!(rt < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
        0x3940_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rt as u32)
    }

    /// `nop` — shorthand for the fixed opcode.
    pub const fn nop() -> u32 {
        NOP
    }

    /// `isb sy` — shorthand for the fixed opcode.
    pub const fn isb() -> u32 {
        ISB_SY
    }
}

// P04 T2 — pure hook-body encoder

/// Canonical 35-word (140-byte) hook-body layout.
///
/// Derived from `references/arm64-a64-encoding.md` §Hook body sketch +
/// §Strcmp loop skeleton (splice rule at line 415 — "Splice the 13-word
/// STRCMP_BODY over HOOK_BODY[STRCMP_STUB]"). The reference lists the
/// template in its pre-splice form (23 words with a 1-word `b .advance`
/// stub at word 5); this const is the post-splice realisation used at
/// install time.
///
/// Word layout:
///
/// | Words | Role |
/// |---|---|
/// | 0..=4   | Header — NULL-guard, `&pi->name`, LOCK_LIST ptr, entry peek, sentinel bail |
/// | 5..=6   | Pointer rebind (`x12 = x9`, `x13 = x10`) — preserves caller x0/x1 across the splice so the fallthrough path can hand the original `prop_info*` / `value` pair back to the real `__system_property_update` at `target_fn + 16` |
/// | 7..=19  | Spliced STRCMP — canonical 13-word loop re-encoded against x12/x13 (pointers) and w14/w15 (byte temps), with the canonical `.mismatch` / `.match` exits (originally `movz wN,#…; ret` pairs) rewritten as `b .advance` / `b .on_match` to flow back into the outer loop or the short-circuit return |
/// | 20..=21 | `.on_match` — `movz w0, #0; ret` (hook's short-circuit success return) |
/// | 22..=24 | `.advance` — post-indexed `ldrb w11, [x10], #1; cbnz w11, .-4` walks `x10` past the entry's NUL terminator, then `b .next_entry` re-enters the outer loop at word 3 |
/// | 25..=28 | `.fall_through` — four stolen prologue words (patched at install) |
/// | 29..=30 | `ldr x16, =RESTORE_TARGET; br x16` — tail-branch to `target_fn + 16` |
/// | 31..=32 | `RESTORE_TARGET` u64 LE (patched at install) |
/// | 33..=34 | `LOCK_LIST` u64 LE (patched at install) |
///
/// The template seeds STOLEN_START with `nop` (so an uninitialised read
/// during construction remains deterministic) and the two u64 literal
/// slots with `0`. [`build_hook_body_bytes`] overwrites all three regions
/// before returning, so the seed value is never observable.
const HOOK_BODY_TEMPLATE: [u32; 35] = [
    0xb400_0320, // 0:  cbz  x0, .fall_through        (+100 → word 25)
    0x9101_8009, // 1:  add  x9, x0, #96
    0x5800_03ea, // 2:  ldr  x10, =LOCK_LIST           (+124 → word 33)
    0x3940_014b, // 3:  .next_entry: ldrb w11, [x10]
    0x3400_02ab, // 4:  cbz  w11, .fall_through        (+84  → word 25)
    0xaa09_03ec, // 5:  mov  x12, x9                   -- rebind: property-name ptr
    0xaa0a_03ed, // 6:  mov  x13, x10                  -- rebind: lock-list entry ptr
    0x3940_018e, // 7:  .strcmp_loop: ldrb w14, [x12]
    0x3940_01af, // 8:  ldrb w15, [x13]
    0x6b0f_01df, // 9:  cmp  w14, w15
    0x5400_00c1, // 10: b.ne .mismatch                 (+24  → word 16)
    0x3400_00ee, // 11: cbz  w14, .match               (+28  → word 18)
    0x9100_058c, // 12: add  x12, x12, #1
    0x9100_05ad, // 13: add  x13, x13, #1
    0x17ff_fff9, // 14: b    .strcmp_loop              (-28  → word 7)
    0xd503_201f, // 15: nop
    0x1400_0006, // 16: .mismatch: b .advance          (+24  → word 22)
    0xd503_201f, // 17: nop (unused — was canonical `ret`)
    0x1400_0002, // 18: .match: b .on_match            (+8   → word 20)
    0xd503_201f, // 19: nop (unused — was canonical `ret`)
    0x5280_0000, // 20: .on_match: movz w0, #0
    0xd65f_03c0, // 21: ret
    0x3840_154b, // 22: .advance: ldrb w11, [x10], #1  -- post-indexed scan
    0x35ff_ffeb, // 23: cbnz w11, .-4                  (-4   → word 22)
    0x17ff_ffeb, // 24: b    .next_entry               (-84  → word 3)
    0xd503_201f, // 25: STOLEN_0 (patched)
    0xd503_201f, // 26: STOLEN_1 (patched)
    0xd503_201f, // 27: STOLEN_2 (patched)
    0xd503_201f, // 28: STOLEN_3 (patched)
    0x5800_0050, // 29: ldr x16, =RESTORE_TARGET       (+8   → word 31)
    0xd61f_0200, // 30: br  x16
    0x0000_0000, // 31: RESTORE_TARGET lo (patched)
    0x0000_0000, // 32: RESTORE_TARGET hi (patched)
    0x0000_0000, // 33: LOCK_LIST lo (patched)
    0x0000_0000, // 34: LOCK_LIST hi (patched)
];

/// Word index of the first stolen-prologue slot inside HOOK_BODY_TEMPLATE.
///
/// The reference §Hook body sketch pins this at word 13 in its pre-splice
/// layout. P04.2 T1 expanded the template to 35 words to realise the
/// STRCMP splice + correct `.advance` scan-past-NUL block, which pushes
/// the stolen-prologue slots to words 25..=28.
const STOLEN_START: usize = 25;

/// Word index of the RESTORE_TARGET u64 low half (literal at words 31..=32).
const RESTORE_LIT: usize = 31;

/// Word index of the LOCK_LIST u64 low half (literal at words 33..=34).
const LOCK_LIST_LIT: usize = 33;

/// Emit the 140-byte hook body for the Tier B per-prop guard.
///
/// Pure, deterministic, no ptrace, no I/O, no unsafe. Given the 16 bytes of
/// stolen prologue (captured by P03 stage-B into [`HookHandle::saved_prologue`]),
/// the lock-list base address in the tracee, and the resume address
/// (`target_fn + 16`), returns the 35-word hook body with the three patch
/// regions filled in little-endian order.
///
/// # Patch layout
///
/// * Words 25..=28 (`STOLEN_START..STOLEN_START+4`) ← `saved_prologue` decoded
///   as four LE `u32`s.
/// * Words 31..=32 (`RESTORE_LIT..RESTORE_LIT+2`) ← `return_addr` split into
///   low / high LE `u32` halves.
/// * Words 33..=34 (`LOCK_LIST_LIT..LOCK_LIST_LIT+2`) ← `lock_list_vaddr`
///   split into low / high LE `u32` halves.
///
/// The returned `Vec<u8>` is the little-endian byte serialisation of the
/// 35-word array per reference §Endianness (ARM64 Linux userspace is always
/// little-endian; each `u32` is stored LSB-first).
///
/// # References
///
/// * `references/arm64-a64-encoding.md` §Hook body sketch (canonical template,
///   pre-splice form — 23 words) + §Strcmp loop skeleton (13-word canonical
///   STRCMP_BODY) + §Hook body sketch install-time patching rules (line 415
///   — "Splice the 13-word STRCMP_BODY over HOOK_BODY[STRCMP_STUB]")
/// * P04.2 T1 expanded the template to 35 words to realise the splice +
///   correct `.advance` scan-past-NUL block; patch-point indices shifted
///   from pre-splice (`STOLEN_START=13`, `RESTORE_LIT=19`, `LOCK_LIST_LIT=21`)
///   to post-splice (`STOLEN_START=25`, `RESTORE_LIT=31`, `LOCK_LIST_LIT=33`).
/// * REGISTRY §1 row `Hook page — 4 KB RWX anonymous mmap`
pub fn build_hook_body_bytes(
    saved_prologue: [u8; 16],
    lock_list_vaddr: u64,
    return_addr: u64,
) -> Vec<u8> {
    let mut body = HOOK_BODY_TEMPLATE;

    // Patch region 1: stolen prologue (words STOLEN_START..=STOLEN_START+3 = 25..=28, 16 bytes post-splice).
    for (i, word) in body[STOLEN_START..STOLEN_START + 4].iter_mut().enumerate() {
        let base = i * 4;
        *word = u32::from_le_bytes([
            saved_prologue[base],
            saved_prologue[base + 1],
            saved_prologue[base + 2],
            saved_prologue[base + 3],
        ]);
    }

    // Patch region 2: RESTORE_TARGET u64 (words RESTORE_LIT..=RESTORE_LIT+1 = 31..=32, LE lo+hi, post-splice).
    body[RESTORE_LIT] = return_addr as u32;
    body[RESTORE_LIT + 1] = (return_addr >> 32) as u32;

    // Patch region 3: LOCK_LIST u64 (words LOCK_LIST_LIT..=LOCK_LIST_LIT+1 = 33..=34, LE lo+hi, post-splice).
    body[LOCK_LIST_LIT] = lock_list_vaddr as u32;
    body[LOCK_LIST_LIT + 1] = (lock_list_vaddr >> 32) as u32;

    body.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// P04 T3 — trampoline installer + i-cache sync

/// Execute a single `isb` in the tracee by staging `isb ; brk #0` at
/// `scratch_pc` through the shared [`run_remote_payload`] skeleton: it flips
/// `pc` to the staged blob, resumes, waits for the brk, and restores the
/// original word and registers (best-effort on every error path).
///
/// Instruction payload, not a syscall: the tracee never enters the kernel, so
/// there is no syscall-number register, no args, and no return to decode — the
/// post-trap regs are discarded. This is the fallback path for
/// `install_trampoline`'s i-cache sync when
/// `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` returns `EINVAL` (cmd missing) or
/// `EPERM` (registration missing), and the i-cache resync on the revert path.
///
/// # Safety
///
/// Caller holds a live `RemoteAttach` on `pid`; `scratch_pc` is 4-byte
/// aligned, lies inside an executable mapping with at least 8 bytes of
/// room, and no other thread in the tracee is racing on those 8 bytes.
unsafe fn execute_remote_isb(pid: libc::pid_t, scratch_pc: u64) -> Result<()> {
    let payload: u64 = (encoder::ISB_SY as u64) | ((encoder::BRK_0 as u64) << 32);

    // SAFETY: forwards the caller's RemoteAttach + scratch_pc contract to the
    // shared injector; `set_pc` is the only register staged (no syscall ABI).
    unsafe {
        run_remote_payload(pid, scratch_pc, payload, |work| set_pc(work, scratch_pc))?;
    }
    Ok(())
}

/// Best-effort revert of a partial trampoline write.
///
/// Called only from `install_trampoline`'s error paths after the 16-byte
/// trampoline POKE sequence has begun. Restores the original prologue by
/// decoding `saved_prologue` as two little-endian `u64` words and issuing
/// two `PTRACE_POKEDATA` writes, then re-syncs the i-cache (L1) so a core
/// cannot keep running the half-written trampoline still cached against the
/// just-restored prologue — the same resync `install_trampoline` runs after a
/// successful write. Errors are logged via `eprintln!` and never returned —
/// the caller is already propagating the original cause and a second error
/// would only obscure it.
///
/// Caller holds the `RemoteAttach` on `pid` (tracee stopped); `scratch_pc` is
/// the cached libc.text slot the install used for its own i-cache sync.
fn revert_trampoline(pid: libc::pid_t, target_fn: u64, scratch_pc: u64, saved_prologue: &[u8; 16]) {
    let lo = u64::from_le_bytes([
        saved_prologue[0],
        saved_prologue[1],
        saved_prologue[2],
        saved_prologue[3],
        saved_prologue[4],
        saved_prologue[5],
        saved_prologue[6],
        saved_prologue[7],
    ]);
    let hi = u64::from_le_bytes([
        saved_prologue[8],
        saved_prologue[9],
        saved_prologue[10],
        saved_prologue[11],
        saved_prologue[12],
        saved_prologue[13],
        saved_prologue[14],
        saved_prologue[15],
    ]);
    if let Err(e) = ptrace_poketext(pid, target_fn, lo) {
        eprintln!("resetprop: revert_trampoline lo word failed: {e}");
    }
    if let Err(e) = ptrace_poketext(pid, target_fn + 8, hi) {
        eprintln!("resetprop: revert_trampoline hi word failed: {e}");
    }
    // L1: the writes above restore the prologue bytes, but a core may still
    // hold the half-written trampoline in its i-cache; resync so it re-fetches
    // the restored prologue. Best-effort — the caller propagates the original
    // failure.
    // SAFETY: `pid` is ptrace-stopped under the caller's RemoteAttach (this fn
    // runs only on `install_trampoline`'s in-attach error path); `scratch_pc`
    // is the libc.text slot the install used for its own membarrier/ISB sync.
    if let Err(e) = unsafe { execute_remote_isb(pid, scratch_pc) } {
        eprintln!("resetprop: revert_trampoline i-cache resync failed: {e}");
    }
}

/// Compare the trampoline bytes read back from the tracee against the two
/// words [`install_trampoline`] intended to write.
///
/// The two POKEs deliver `word_lo` then `word_hi` as consecutive little-
/// endian `u64`s at `target_fn`, so the 16 bytes that should be live are
/// exactly `word_lo.to_le_bytes()` followed by `word_hi.to_le_bytes()`. A
/// torn or partial write (one POKE landing, the other silently dropping its
/// high half, a racing writer clobbering a word) leaves `readback` differing
/// from that expectation; this is the read-back gate that catches it before
/// the i-cache sync makes the bad bytes executable.
///
/// Pure (no I/O) so the mismatch decision is unit-testable off-device:
/// `install_trampoline` performs the `read_remote` and hands the buffer here.
fn verify_trampoline_readback(word_lo: u64, word_hi: u64, readback: &[u8; 16]) -> Result<()> {
    let mut expected = [0u8; 16];
    expected[..8].copy_from_slice(&word_lo.to_le_bytes());
    expected[8..].copy_from_slice(&word_hi.to_le_bytes());
    if readback == &expected {
        Ok(())
    } else {
        Err(Error::HookInstallFailed(format!(
            "install_trampoline: trampoline read-back mismatch: \
             wrote {expected:02x?} read {readback:02x?}"
        )))
    }
}

/// Install the 16-byte absolute-target trampoline at `handle.target_fn`
/// and the 140-byte hook body at `handle.hook_page + HOOK_BODY_OFFSET`.
///
/// Write order is load-bearing: the hook body must be fully materialised
/// before the trampoline's `br x16` can land on a valid target, so the
/// body is written first (step 4) and the trampoline second (step 5). If
/// init is scheduled onto the trampoline mid-install, it sees either the
/// old prologue (trampoline not yet written) or a fully-formed hook
/// (trampoline written, body already in place) — never a half-formed
/// body.
///
/// After both writes land, the instruction cache on each core must be
/// synchronised with the updated data cache or the tracee may execute
/// stale bytes fetched before our POKEs. The primary path issues a
/// remote `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` (one syscall, no
/// symbol resolution); on `EINVAL` / `EPERM` (kernel lacks the cmd or
/// the tracee never registered) it falls back to
/// [`execute_remote_isb`].
///
/// Between the trampoline write and the i-cache sync the 16 bytes are read
/// back via [`read_remote`] and checked against the intended words by
/// [`verify_trampoline_readback`]; a torn write is caught here, reverted,
/// and aborted before it can be made executable.
///
/// On success, `handle.trampoline_installed` is flipped to `true` so
/// [`HookHandle::drop`] skips the `munmap` — init is now executing
/// inside the hook page.
///
/// # Error cleanup
///
/// Any failure after the trampoline write has begun (steps 5-7) triggers
/// a best-effort [`revert_trampoline`] under the same attach window
/// before the error propagates, so the tracee is not left running a
/// half-written trampoline.
pub fn install_trampoline(handle: &mut HookHandle) -> Result<()> {
    let attach = seal::arena::RemoteAttach::new(handle.pid)
        .map_err(|e| Error::HookInstallFailed(format!("install_trampoline: attach: {e}")))?;

    match install_trampoline_locked(&attach, handle) {
        Ok(()) => attach
            .detach()
            .map_err(|e| Error::HookInstallFailed(format!("install_trampoline: detach: {e}"))),
        Err(e) => {
            // `install_trampoline_locked` already reverted the partial write
            // under this attach window; detach and surface the original cause.
            if let Err(detach_err) = attach.detach() {
                eprintln!("resetprop: detach after install error failed: {detach_err}");
            }
            Err(e)
        }
    }
}

/// Trampoline-install body under a caller-held [`RemoteAttach`] (audit M5).
///
/// Writes the 16-byte trampoline and runs the i-cache sync, reverts the partial
/// write on any post-write failure (the caller's attach window stays live for
/// the revert), then flips `handle.trampoline_installed`. The attach/detach is
/// the caller's: [`install_trampoline`] opens one for the standalone path;
/// [`install_and_seal_first`] shares one window across the whole first seal so
/// PID 1 is stopped once, not three times.
fn install_trampoline_locked(
    attach: &seal::arena::RemoteAttach,
    handle: &mut HookHandle,
) -> Result<()> {
    let pid = attach.pid();

    // Step 1: compute the trampoline's branch target. The 140-byte hook body
    // already lives at `hook_page + HOOK_BODY_OFFSET`; `install_init_hook`
    // mapped it from init's memfd PROT_R|X, so no runtime body write is
    // required here.
    let hook_body_vaddr = handle.hook_page + HOOK_BODY_OFFSET;

    // Steps 3-5 run under the attach. A failure after the trampoline write
    // has begun must revert the trampoline before the error unwinds. Using
    // a closure lets `?` propagate cleanly while a trailing `match` runs
    // the cleanup.
    let trampoline_result = (|| -> Result<()> {
        // Step 3: write the 16-byte trampoline at `target_fn`.
        //
        // `target_fn` lives inside libc.text `r-xp`, so `process_vm_writev`
        // EFAULTs. `PTRACE_POKEDATA` bypasses VMA write bits via
        // `ptrace_access_vm`. The trampoline is two LP64 words: word_lo
        // packs `ldr x16, [pc, #8]` (low 4 bytes) with `br x16` (high 4
        // bytes); word_hi is the absolute 64-bit literal target.
        //
        // DEFECT B (T15): these two POKEs are non-atomic — a sibling init
        // thread calling `__system_property_*` *between* them would run
        // `ldr x16,[pc,#8]; br x16` over a half-written 16 bytes and branch
        // into garbage, killing PID 1. The race is closed at the source:
        // `RemoteAttach::new` froze init's ENTIRE thread group (every
        // /proc/1/task tid), so no sibling executes while these words land.
        let word_lo = (encoder::LDR_X16_PC8 as u64) | ((encoder::BR_X16 as u64) << 32);
        let word_hi = hook_body_vaddr;
        ptrace_poketext(pid, handle.target_fn, word_lo).map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: poke tramp lo: {e}"))
        })?;
        ptrace_poketext(pid, handle.target_fn + 8, word_hi).map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: poke tramp hi: {e}"))
        })?;

        // Step 3b: verify-after-write. Read the 16 bytes back via
        // `process_vm_readv` and confirm they match the two words we POKEd
        // BEFORE the i-cache sync makes them executable. A torn or partial
        // write that slipped past the POKE return codes would otherwise be
        // cache-synced into a live `ldr x16; br x16` over garbage and branch
        // init into the weeds. On mismatch the `?` aborts the closure; the
        // trailing `match` runs `revert_trampoline` to restore the prologue.
        //
        // SAFETY: `target_fn` is inside libc.text `r-xp`; `read_remote`
        // needs read permission only, and the tracee is ptrace-stopped via
        // `attach` so the read cannot race a concurrent write.
        let mut readback = [0u8; 16];
        unsafe { read_remote(pid, handle.target_fn, &mut readback) }.map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: trampoline read-back: {e}"))
        })?;
        verify_trampoline_readback(word_lo, word_hi, &readback)?;

        // Step 4: i-cache sync via remote membarrier — REGISTER then SYNC_CORE.
        //
        // SYNC_CORE (0x80) returns -EPERM unconditionally until the calling
        // task has registered intent via REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
        // (0x40). Init has never registered, so we issue REGISTER on init's
        // behalf via remote_syscall_via_poke inside this attach window,
        // then issue SYNC_CORE. If the kernel lacks either cmd
        // (-EINVAL / -ENOSYS; common on kernel < 4.16), we drop to the
        // staged ISB fallback.
        //
        // Reference: references/arm64-a64-encoding.md line 422.
        //
        // SAFETY: `handle.scratch_pc` is the 8-byte-aligned slot inside
        // libc.text cached at install time by `derive_libc_scratch_pc`; the tracee
        // is ptrace-stopped via `attach`; `remote_syscall_via_poke` saves
        // and restores both the scratch word and the saved-regs snapshot
        // internally before returning.
        let einval_neg = -(libc::EINVAL as i64);
        let enosys_neg = -(libc::ENOSYS as i64);

        let register_ret = unsafe {
            remote_syscall_via_poke(
                pid,
                handle.scratch_pc,
                NR_MEMBARRIER,
                [
                    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        }
        .map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: membarrier register: {e}"))
        })?;

        if register_ret == einval_neg || register_ret == enosys_neg {
            // SAFETY: same invariants as the register call above — `attach`
            // holds the tracee stopped; `handle.scratch_pc` is the cached
            // libc.text slot.
            return unsafe { execute_remote_isb(pid, handle.scratch_pc) };
        }
        if register_ret != 0 {
            return Err(Error::HookInstallFailed(format!(
                "install_trampoline: membarrier register returned {register_ret}"
            )));
        }

        // Step 5: issue SYNC_CORE. Post-register, -EPERM is no longer the
        // expected "not registered" result, so any non-zero return other
        // than -EINVAL (which still indicates missing kernel support for
        // the cmd) is treated as a hard failure.
        let sync_ret = unsafe {
            remote_syscall_via_poke(
                pid,
                handle.scratch_pc,
                NR_MEMBARRIER,
                [MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0, 0, 0, 0],
            )
        }
        .map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: membarrier sync_core: {e}"))
        })?;

        if sync_ret == einval_neg {
            // SAFETY: same invariants as the register call above.
            return unsafe { execute_remote_isb(pid, handle.scratch_pc) };
        }
        if sync_ret != 0 {
            return Err(Error::HookInstallFailed(format!(
                "install_trampoline: membarrier sync_core returned {sync_ret}"
            )));
        }
        Ok(())
    })();

    if let Err(e) = trampoline_result {
        // Revert under the caller's still-live attach window; the caller detaches.
        revert_trampoline(pid, handle.target_fn, handle.scratch_pc, &handle.saved_prologue);
        return Err(e);
    }

    // Flip typestate so Drop skips the munmap.
    handle.trampoline_installed = true;
    Ok(())
}

// P04 T4 — lock-list mechanics (pure helpers + public seal / unseal)

/// Append `name` + entry-NUL + empty-sentinel-NUL to a lock-list buffer in
/// the atomic-append write order. Returns the new `cur_len`, i.e. the byte
/// offset of the new trailing empty-entry sentinel.
///
/// The encoding is `<entry><NUL><entry><NUL>...<entry><NUL><NUL>` where the
/// last standalone NUL is the empty-entry sentinel that stops the hook
/// body's `cbz w11, .fallthrough` walker. Each entry's NUL serves only as
/// its own terminator; the explicit trailing NUL defends against a zero-pad
/// assumption being invalidated by a future compact-then-resize.
///
/// Write order (seal_prop's remote `write_remote` must honour this):
///
/// 1. `name` bytes at `buf[cur_len..cur_len + name.len()]` overwrite the
///    old sentinel with the entry's first byte.
/// 2. Entry terminator NUL at `buf[cur_len + name.len()]`.
/// 3. New trailing sentinel NUL at `buf[cur_len + name.len() + 1]`.
///
/// Returns `None` if the new sentinel offset would lie at or past
/// `capacity`; callers surface this as [`Error::HookInstallFailed`]. The
/// bound is `>= capacity` because the sentinel occupies the byte it names,
/// so offset `capacity` is the first byte past the lock list's reserved
/// region. Callers pass [`LOCK_LIST_CAPACITY`], which sits below
/// [`PATH_STAGE_OFFSET`], so a list that respects the bound never lets the
/// in-init walker read the path bytes staged there during install.
///
/// Interior-NUL rejection is the caller's responsibility — this helper
/// assumes `name` is a validated C-string body.
fn lock_list_append_bytes(
    buffer: &mut [u8],
    cur_len: u32,
    name: &[u8],
    capacity: u64,
) -> Option<u32> {
    let tail = cur_len as usize;
    let entry_end = tail + name.len();
    let new_sentinel = entry_end + 1;
    if (new_sentinel as u64) >= capacity {
        return None;
    }
    buffer[tail..entry_end].copy_from_slice(name);
    buffer[entry_end] = 0;
    buffer[new_sentinel] = 0;
    Some(new_sentinel as u32)
}

/// Scan `buffer[0..cur_len]` for an entry equal to `name` (followed by its
/// NUL terminator). On match, shift subsequent entries and the trailing
/// sentinel left over the removed slot, zero the now-stale tail, and return
/// `Some(new_cur_len)` where `new_cur_len = cur_len - (name.len() + 1)`.
///
/// Returns `None` when `name` is not present; the caller surfaces this as
/// `Ok(false)` to indicate the unseal was a no-op. Buffer contents are left
/// unmodified in the not-found case so callers can skip the remote write.
fn lock_list_remove_bytes(buffer: &mut [u8], cur_len: u32, name: &[u8]) -> Option<u32> {
    let tail = cur_len as usize;
    let removed_entry_len = name.len() + 1;
    let mut entry_start = 0usize;
    while entry_start < tail {
        let entry_end = buffer[entry_start..=tail]
            .iter()
            .position(|&b| b == 0)
            .map(|p| entry_start + p)?;
        if &buffer[entry_start..entry_end] == name {
            let match_end = entry_end + 1;
            buffer.copy_within(match_end..=tail, entry_start);
            let new_cur_len = tail - removed_entry_len;
            buffer[new_cur_len..=tail].fill(0);
            return Some(new_cur_len as u32);
        }
        entry_start = entry_end + 1;
    }
    None
}

/// Append a name to the tracee's in-page lock list.
///
/// Atomic-append invariant (hook-side): the hook body reads the list
/// without synchronisation, so writes must land in an order where any
/// partial observation is either the old shorter list or the new longer
/// list — never a half-written entry. The implementation issues one
/// `write_remote` covering entry bytes + entry-NUL + new-sentinel-NUL in a
/// single `process_vm_writev` call under the attach window; only after
/// that write succeeds does the tracer-side `lock_list_len` counter
/// advance.
///
/// Rejects names containing an interior NUL with [`Error::InvalidKey`]
/// before any ptrace work, because the hook body's sentinel walk would
/// prefix-match on the bytes preceding the NUL. Exceeding
/// [`LOCK_LIST_CAPACITY`] surfaces as [`Error::HookInstallFailed`].
pub fn seal_prop(handle: &mut HookHandle, name: &str) -> Result<()> {
    if name.as_bytes().contains(&0) {
        return Err(Error::InvalidKey);
    }

    let attach = seal::arena::RemoteAttach::new(handle.pid)
        .map_err(|e| Error::HookInstallFailed(format!("seal_prop: attach: {e}")))?;

    seal_prop_locked(&attach, handle, name)?;

    attach
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("seal_prop: detach: {e}")))?;

    Ok(())
}

/// Append `name` to the lock list under a caller-held [`RemoteAttach`] (M5).
///
/// The interior-NUL rejection, attach, and detach live in the caller
/// ([`seal_prop`] for the standalone path, [`install_and_seal_first`] for the
/// folded first seal), so `name` is assumed already validated. The tracer-side
/// `lock_list_len` bump stays inside this body, before the caller detaches, so
/// the handle never lies to the next append.
fn seal_prop_locked(
    attach: &seal::arena::RemoteAttach,
    handle: &mut HookHandle,
    name: &str,
) -> Result<()> {
    let pid = attach.pid();

    // L2 (lock-list write-ordering race) is closed by T15: `RemoteAttach`
    // freezes init's whole thread group, so no init thread reads this lock
    // list during the read-modify-write below. seal_prop's byte ordering
    // therefore needs no lock-free rewrite.
    let mut buffer = vec![0u8; LOCK_LIST_CAPACITY as usize];

    // SAFETY: `handle.lock_list_page` was allocated PROT_RW anonymous by
    // `install_init_hook` and is still mapped in the tracee;
    // `LOCK_LIST_CAPACITY` bytes at offset 0 lie inside the 4 KiB page.
    // Tracee is ptrace-stopped via `attach`, so no concurrent mutation
    // races the read.
    unsafe { read_remote(pid, handle.lock_list_page, &mut buffer) }
        .map_err(|e| Error::HookInstallFailed(format!("seal_prop: read_remote: {e}")))?;

    let new_len = lock_list_append_bytes(
        &mut buffer,
        handle.lock_list_len,
        name.as_bytes(),
        LOCK_LIST_CAPACITY,
    )
    .ok_or_else(|| {
        Error::HookInstallFailed(format!(
            "seal_prop: capacity exceeded (len={}, name={} bytes)",
            handle.lock_list_len,
            name.len()
        ))
    })?;

    let write_start = handle.lock_list_len as usize;
    let write_end = new_len as usize + 1;

    // SAFETY: same page invariant as the read above; tracee remains
    // ptrace-stopped via `attach`. `write_remote` loops on partial
    // transfers and bounds the write to bytes already inside the hook
    // page (`write_end <= LOCK_LIST_CAPACITY`).
    unsafe {
        write_remote(
            pid,
            handle.lock_list_page + write_start as u64,
            &buffer[write_start..write_end],
        )
    }
    .map_err(|e| Error::HookInstallFailed(format!("seal_prop: write_remote: {e}")))?;

    // Counter-before-detach: once `write_remote` succeeds, the tracee observes
    // the extended list. Bumping `handle.lock_list_len` before the caller's
    // `attach.detach()` keeps the tracer's view and the tracee's view
    // consistent — a panic or signal between detach and the counter bump would
    // otherwise leave the handle lying to the next `seal_prop` and producing an
    // off-by-entry overwrite. Addresses Gate 2 round-1 critic MAJOR 3.
    handle.lock_list_len = new_len;

    Ok(())
}

/// Remove a name from the tracee's in-page lock list.
///
/// Returns `Ok(true)` when the name was present and the compacted list was
/// written back; `Ok(false)` when the name was absent (no remote write
/// issued). Compaction shifts trailing entries left over the removed slot
/// and zeros the stale tail so the hook body never observes a stale byte
/// past the new sentinel.
pub fn unseal_prop(handle: &mut HookHandle, name: &str) -> Result<bool> {
    let attach = seal::arena::RemoteAttach::new(handle.pid)
        .map_err(|e| Error::HookInstallFailed(format!("unseal_prop: attach: {e}")))?;

    let mut buffer = vec![0u8; LOCK_LIST_CAPACITY as usize];

    // SAFETY: see `seal_prop`'s read SAFETY block — same page and attach
    // invariants apply.
    unsafe { read_remote(handle.pid, handle.lock_list_page, &mut buffer) }
        .map_err(|e| Error::HookInstallFailed(format!("unseal_prop: read_remote: {e}")))?;

    let new_len = match lock_list_remove_bytes(&mut buffer, handle.lock_list_len, name.as_bytes()) {
        Some(n) => n,
        None => {
            attach
                .detach()
                .map_err(|e| Error::HookInstallFailed(format!("unseal_prop: detach: {e}")))?;
            return Ok(false);
        }
    };

    let cur_tail = handle.lock_list_len as usize;
    let write_end = cur_tail + 1;

    // SAFETY: same invariants as `seal_prop`. Writing `[0..=cur_tail]`
    // pushes both the compacted payload and the zeroed stale tail back to
    // the tracee, so the hook body never sees leftover bytes past the new
    // sentinel.
    unsafe { write_remote(handle.pid, handle.lock_list_page, &buffer[0..write_end]) }
        .map_err(|e| Error::HookInstallFailed(format!("unseal_prop: write_remote: {e}")))?;

    // Counter-before-detach: mirrors the `seal_prop` invariant — the
    // tracee observes the compacted list once `write_remote` succeeds,
    // so the tracer's counter must update inside the attach window.
    handle.lock_list_len = new_len;

    attach
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("unseal_prop: detach: {e}")))?;

    Ok(true)
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
            lock_list_page: 0xfacefeed_12345678,
            lock_list_len: 7,
            target_fn: 0x1234_5678_9abc_def0,
            saved_prologue: [0xAB; 16],
            libc_base: 0x7000_0000_0000,
            libc_end: 0x7000_0010_0000,
            scratch_pc: 0x7000_0000_1000,
            trampoline_installed: false,
            kmsg_fds: vec![3, 8],
        };
        assert_eq!(h.pid, 42);
        assert_eq!(h.hook_page, 0xdeadbeef_cafebabe);
        assert_eq!(h.lock_list_page, 0xfacefeed_12345678);
        assert_eq!(h.lock_list_len, 7);
        assert_eq!(h.target_fn, 0x1234_5678_9abc_def0);
        assert_eq!(h.saved_prologue, [0xAB; 16]);
        assert_eq!(h.libc_base, 0x7000_0000_0000);
        assert_eq!(h.libc_end, 0x7000_0010_0000);
        assert_eq!(h.scratch_pc, 0x7000_0000_1000);
        assert!(!h.trampoline_installed);
        assert_eq!(h.kmsg_fds, vec![3, 8]);
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
    /// integration. Tier B functional acceptance runs on-device in P05
    /// against real init; the off-device `tier_b_child_smoke` sacrificial
    /// child test was removed in P04.2 T3 per Gate 2 round-1 critic
    /// CRITICAL 2 (false-positive: `is_libc_row` excludes the test binary
    /// and Rust direct-branch routing bypasses the patched `.dynsym`
    /// entry).
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

    // P04 T1 — A64 encoder submodule tests

    /// Round-trips a 16-byte absolute-target trampoline built from the
    /// encoder helpers against the canonical byte pattern from
    /// `references/arm64-a64-encoding.md` §Absolute-target trampoline.
    ///
    /// This is the strongest round-trip check we can run without a
    /// disassembler: it proves (a) `LDR_X16_PC8` and `BR_X16` consts match
    /// the helper-constructed forms for x16, and (b) the imm19 field of
    /// `ldr_literal(16, 8)` encodes to the expected `0x58000050` word.
    #[test]
    fn trampoline_from_helpers_matches_reference() {
        use super::encoder::{br, ldr_literal};

        let target: u64 = 0x0000_7fff_abcd_1234;
        let ldr = ldr_literal(16, 8).to_le_bytes();
        let br_x16 = br(16).to_le_bytes();
        let lo = (target as u32).to_le_bytes();
        let hi = ((target >> 32) as u32).to_le_bytes();

        let actual: [u8; 16] = [
            ldr[0], ldr[1], ldr[2], ldr[3], br_x16[0], br_x16[1], br_x16[2], br_x16[3], lo[0],
            lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3],
        ];

        let expected: [u8; 16] = [
            0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6, 0x34, 0x12, 0xcd, 0xab, 0xff, 0x7f,
            0x00, 0x00,
        ];

        assert_eq!(actual, expected);
    }

    /// Defends the 7 pub consts against refactoring drift. Every value is
    /// pinned in REGISTRY §1 or `references/arm64-a64-encoding.md` §Instruction
    /// Table, so any change here must be accompanied by a REGISTRY amendment.
    #[test]
    fn opcodes_match_canonical_values() {
        use super::encoder::{BRK_0, BR_X16, ISB_SY, LDR_X16_PC8, NOP, RET_X30, SVC_0};

        assert_eq!(NOP, 0xd503_201f);
        assert_eq!(RET_X30, 0xd65f_03c0);
        assert_eq!(ISB_SY, 0xd503_3fdf);
        assert_eq!(SVC_0, 0xd400_0001);
        assert_eq!(BRK_0, 0xd420_0000);
        assert_eq!(LDR_X16_PC8, 0x5800_0050);
        assert_eq!(BR_X16, 0xd61f_0200);
    }

    // Bit-range assertion sub-tests. Each helper is exercised once with an
    // out-of-range argument to confirm the inline `assert!` fires. The
    // tests are split per-case so a single regression surfaces the exact
    // helper whose guard changed.

    #[test]
    #[should_panic]
    fn add_imm64_rejects_imm12_equal_to_4096() {
        let _ = super::encoder::add_imm64(0, 0, 4096);
    }

    #[test]
    #[should_panic]
    fn add_imm64_rejects_rd_equal_to_32() {
        let _ = super::encoder::add_imm64(32, 0, 0);
    }

    #[test]
    #[should_panic]
    fn ret_rejects_rn_equal_to_32() {
        let _ = super::encoder::ret(32);
    }

    #[test]
    #[should_panic]
    fn br_rejects_rn_equal_to_32() {
        let _ = super::encoder::br(32);
    }

    #[test]
    #[should_panic]
    fn blr_rejects_rn_equal_to_32() {
        let _ = super::encoder::blr(32);
    }

    #[test]
    #[should_panic]
    fn ldr_literal_rejects_unaligned_offset() {
        let _ = super::encoder::ldr_literal(0, 2);
    }

    #[test]
    #[should_panic]
    fn ldr_literal_rejects_imm19_overflow() {
        // imm19 signed range is [-2^18, 2^18 - 1] words = [-1048576, 1048572] bytes.
        // 1048576 (2^20) in bytes is one past the positive limit and must assert.
        let _ = super::encoder::ldr_literal(0, 1 << 20);
    }

    #[test]
    #[should_panic]
    fn movz_rejects_hw_equal_to_4() {
        let _ = super::encoder::movz(0, 0, 4);
    }

    #[test]
    #[should_panic]
    fn movk_rejects_hw_equal_to_4() {
        let _ = super::encoder::movk(0, 0, 4);
    }

    #[test]
    #[should_panic]
    fn cbz_rejects_unaligned_offset() {
        let _ = super::encoder::cbz(0, 2);
    }

    #[test]
    #[should_panic]
    fn cbnz_rejects_unaligned_offset() {
        let _ = super::encoder::cbnz(0, 2);
    }

    #[test]
    #[should_panic]
    fn b_rel_rejects_imm26_overflow() {
        // imm26 signed range is [-2^25, 2^25 - 1] words. 2^25 words = 2^27 bytes
        // = 134_217_728 is one past the positive limit and must assert.
        let _ = super::encoder::b_rel(1 << 27);
    }

    #[test]
    #[should_panic]
    fn ldrb_imm_rejects_imm12_equal_to_4096() {
        let _ = super::encoder::ldrb_imm(0, 0, 4096);
    }

    // P04 T2 — build_hook_body_bytes tests

    /// Verifies [`build_hook_body_bytes`] serialises the 35-word template
    /// with the three patch regions filled in the correct byte positions.
    ///
    /// Word N lives at byte `N * 4`, so post-splice the patch regions land
    /// at: STOLEN_START=25 → byte 100, RESTORE_LIT=31 → byte 124,
    /// LOCK_LIST_LIT=33 → byte 132. Total length is 35 × 4 = 140 bytes.
    #[test]
    fn build_hook_body_bytes_roundtrip() {
        let saved_prologue = [0xABu8; 16];
        let lock_list_vaddr: u64 = 0x1111_2222_3333_4444;
        let return_addr: u64 = 0xDEAD_BEEF_CAFE_BABE;

        let bytes = build_hook_body_bytes(saved_prologue, lock_list_vaddr, return_addr);

        assert_eq!(
            bytes.len(),
            140,
            "hook body must be 35 words × 4 = 140 bytes"
        );

        // Header words 0..=1 (NULL-guard + &pi->name).
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0xb400_0320,
            "word 0: cbz x0, .fall_through (+100)"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            0x9101_8009,
            "word 1: add x9, x0, #96"
        );

        // .on_match pair at words 20..=21 (bytes 80..88).
        assert_eq!(
            u32::from_le_bytes([bytes[80], bytes[81], bytes[82], bytes[83]]),
            0x5280_0000,
            "word 20: movz w0, #0"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[84], bytes[85], bytes[86], bytes[87]]),
            0xd65f_03c0,
            "word 21: ret"
        );

        // Patch region 1: STOLEN_START at words 25..=28 (bytes 100..116).
        assert_eq!(
            &bytes[100..116],
            &saved_prologue,
            "STOLEN_START must mirror saved_prologue bytes"
        );

        // Patch region 2: RESTORE_TARGET u64 at words 31..=32 (bytes 124..132).
        assert_eq!(
            u64::from_le_bytes([
                bytes[124], bytes[125], bytes[126], bytes[127], bytes[128], bytes[129], bytes[130],
                bytes[131],
            ]),
            return_addr,
            "RESTORE_TARGET literal must equal return_addr"
        );

        // Patch region 3: LOCK_LIST u64 at words 33..=34 (bytes 132..140).
        assert_eq!(
            u64::from_le_bytes([
                bytes[132], bytes[133], bytes[134], bytes[135], bytes[136], bytes[137], bytes[138],
                bytes[139],
            ]),
            lock_list_vaddr,
            "LOCK_LIST literal must equal lock_list_vaddr"
        );
    }

    /// Compile-time coercion that pins the public signature of
    /// [`build_hook_body_bytes`].
    ///
    /// A successful `fn`-pointer assignment proves the function takes
    /// exactly `([u8; 16], u64, u64)` and returns `Vec<u8>` with no hidden
    /// `&self`, `&mut self`, or `Self`-bound parameters — i.e. it cannot
    /// depend on a tracer context, a mutex guard, or any ptrace handle.
    /// This is the strongest purity assertion the type system alone can
    /// express. The runtime call with `[0; 16]` / `0` / `0` additionally
    /// proves the function executes with all zero inputs without panic
    /// (no hidden `assert!` on the patch values) and returns the
    /// spec-locked 140-byte length.
    #[test]
    fn build_hook_body_bytes_is_pure() {
        let _: fn([u8; 16], u64, u64) -> Vec<u8> = build_hook_body_bytes;

        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);
        assert_eq!(bytes.len(), 140);
    }

    /// Pins the 7 header + pointer-rebind words (0..=6) against the
    /// post-splice hook body layout.
    ///
    /// Words 0..=4 are the reference §Hook body sketch outer-loop header
    /// re-targeted to the new `.fall_through` (word 25) and `LOCK_LIST`
    /// literal (word 33) positions after the STRCMP splice landed.
    /// Words 5..=6 are the P04.2 T1 addition — `mov x12, x9 ; mov x13, x10`
    /// — that preserves caller x0/x1 across the splice so the fallthrough
    /// path can resume `__system_property_update` at `target_fn + 16` with
    /// the ABI-mandated `(prop_info*, value)` pair intact. A drift in any
    /// of these seven words means the outer loop no longer aligns with the
    /// splice entry or the downstream fall-through target.
    #[test]
    fn build_hook_body_bytes_header_matches_spliced_layout() {
        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);

        let expected: [u32; 7] = [
            0xb400_0320, // 0: cbz  x0, .fall_through (+100 → word 25)
            0x9101_8009, // 1: add  x9, x0, #96
            0x5800_03ea, // 2: ldr  x10, =LOCK_LIST   (+124 → word 33)
            0x3940_014b, // 3: ldrb w11, [x10]
            0x3400_02ab, // 4: cbz  w11, .fall_through (+84 → word 25)
            0xaa09_03ec, // 5: mov  x12, x9
            0xaa0a_03ed, // 6: mov  x13, x10
        ];

        for (i, expected_word) in expected.iter().enumerate() {
            let base = i * 4;
            let actual = u32::from_le_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
            ]);
            assert_eq!(
                actual, *expected_word,
                "header word {i} drifted from spliced-layout canonical"
            );
        }
    }

    /// Pins the 13 spliced STRCMP words (7..=19) against the canonical
    /// `STRCMP_BODY` from `references/arm64-a64-encoding.md` §Strcmp loop
    /// skeleton, re-encoded with the pointer/byte-temp register rebind
    /// (`x0→x12`, `x1→x13`, `w9→w14`, `w10→w15`) and with the canonical
    /// `.mismatch` / `.match` exits (originally `movz wN,#…; ret` pairs)
    /// rewritten as `b .advance` / `b .on_match` to flow back into the
    /// hook's outer loop.
    ///
    /// This is the round-trip test requested by Gate 2 round-1 critic
    /// CRITICAL 1 — without it, a future drift in `HOOK_BODY_TEMPLATE`
    /// could silently reintroduce a stub in place of the splice and the
    /// unit tests alone would still pass.
    #[test]
    fn build_hook_body_bytes_splices_strcmp_body() {
        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);

        let expected: [u32; 13] = [
            0x3940_018e, // 7:  ldrb w14, [x12]    (was `ldrb w9,  [x0]`)
            0x3940_01af, // 8:  ldrb w15, [x13]    (was `ldrb w10, [x1]`)
            0x6b0f_01df, // 9:  cmp  w14, w15     (was `cmp w9, w10`)
            0x5400_00c1, // 10: b.ne .mismatch    (+24 → word 16)
            0x3400_00ee, // 11: cbz  w14, .match  (+28 → word 18)
            0x9100_058c, // 12: add  x12, x12, #1 (was `add x0, x0, #1`)
            0x9100_05ad, // 13: add  x13, x13, #1 (was `add x1, x1, #1`)
            0x17ff_fff9, // 14: b    .strcmp_loop (-28 → word 7)
            0xd503_201f, // 15: nop
            0x1400_0006, // 16: .mismatch: b .advance (+24 → word 22)
            0xd503_201f, // 17: nop (unused — was canonical `ret`)
            0x1400_0002, // 18: .match:    b .on_match (+8 → word 20)
            0xd503_201f, // 19: nop (unused — was canonical `ret`)
        ];

        for (i, expected_word) in expected.iter().enumerate() {
            let word_index = 7 + i;
            let base = word_index * 4;
            let actual = u32::from_le_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
            ]);
            assert_eq!(
                actual, *expected_word,
                "splice word {word_index} drifted — expected canonical STRCMP \
                 with register rebind / exit redirect"
            );
        }
    }

    /// Pins the 3-word `.advance` block (words 22..=24) that walks `x10`
    /// past the current entry's NUL terminator and re-enters the outer
    /// loop at `.next_entry` (word 3).
    ///
    /// Pre-P04.2 the template carried a single-word `add x10, x10, #1`
    /// stub here, which advanced by exactly one byte per outer iteration
    /// — wrong for any entry longer than one byte. Critic CRITICAL 1
    /// called for a post-indexed scan that advances past the full entry
    /// and its terminator in one pass.
    #[test]
    fn build_hook_body_bytes_advance_block_scans_past_nul() {
        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);

        let expected: [u32; 3] = [
            0x3840_154b, // 22: ldrb w11, [x10], #1  (post-indexed load+advance)
            0x35ff_ffeb, // 23: cbnz w11, .-4        (-4 → word 22, loop on non-NUL)
            0x17ff_ffeb, // 24: b    .next_entry    (-84 → word 3)
        ];

        for (i, expected_word) in expected.iter().enumerate() {
            let word_index = 22 + i;
            let base = word_index * 4;
            let actual = u32::from_le_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
            ]);
            assert_eq!(
                actual, *expected_word,
                ".advance word {word_index} drifted from scan-past-NUL canonical"
            );
        }
    }

    // T16 / H1 — independent encoding oracle

    /// The golden trampoline image, assembled out-of-band from
    /// `oracle/hook_body.s` by a real ARM64 assembler (`aarch64-linux-gnu-as`
    /// + `objcopy -O binary`; `llvm-mc` was verified to emit identical bytes).
    ///
    /// Because the assembler derives every opcode *and every branch
    /// displacement* from labelled mnemonics — not from the hand-written hex in
    /// [`HOOK_BODY_TEMPLATE`] — this blob is an *independent* derivation. A
    /// transcription slip in the template can therefore no longer ratify
    /// itself: the exact failure mode that let Defect-A's `ldrb w11,[x10],#16`
    /// (0x3841_054b) ship green against an equally-wrong hand-typed golden.
    ///
    /// Regeneration command lives in the header of `oracle/hook_body.s`.
    const HOOK_BODY_ORACLE: &[u8] = include_bytes!("oracle/hook_body.golden.bin");

    /// Diffs every word of [`HOOK_BODY_TEMPLATE`] against the independent
    /// assembler oracle.
    ///
    /// Covers all 35 words, so mutating any single template word — opcode,
    /// immediate, or branch displacement — turns this test red. This closes the
    /// gap Defect-A slipped through: the old advance-block test asserted the
    /// same wrong constant the template carried, so both agreed and the bug was
    /// green. The oracle's bytes come from a different tool, so they cannot
    /// agree with a hand-encoding mistake.
    #[test]
    fn hook_body_template_matches_independent_oracle() {
        assert_eq!(
            HOOK_BODY_ORACLE.len(),
            HOOK_BODY_TEMPLATE.len() * 4,
            "oracle blob must be 35 words × 4 = 140 bytes; regenerate via oracle/hook_body.s"
        );

        let template_bytes: Vec<u8> = HOOK_BODY_TEMPLATE
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();

        for (i, (tpl, gold)) in template_bytes
            .chunks_exact(4)
            .zip(HOOK_BODY_ORACLE.chunks_exact(4))
            .enumerate()
        {
            let tpl_w = u32::from_le_bytes([tpl[0], tpl[1], tpl[2], tpl[3]]);
            let gold_w = u32::from_le_bytes([gold[0], gold[1], gold[2], gold[3]]);
            assert_eq!(
                tpl_w, gold_w,
                "word {i}: HOOK_BODY_TEMPLATE 0x{tpl_w:08x} diverges from the \
                 independent oracle 0x{gold_w:08x} — a hand-encoding error, or \
                 the template changed and oracle/hook_body.s needs regenerating"
            );
        }
    }

    /// Confirms [`build_hook_body_bytes`] carries the assembler-verified
    /// instruction words through unmodified — only the three patch regions may
    /// differ from the oracle.
    ///
    /// The patcher overwrites the stolen-prologue, RESTORE_TARGET, and
    /// LOCK_LIST data slots; every *instruction* word it emits must still match
    /// the independent oracle. Anchoring the patcher's output to the oracle
    /// (not to a second hand-derived copy) extends the Defect-A guard from the
    /// static template to the bytes actually written into the tracee. The patch
    /// set is derived from the module's patch-point constants so this test
    /// tracks any future layout shift.
    #[test]
    fn build_hook_body_bytes_instruction_surface_matches_oracle() {
        let saved_prologue = [0xABu8; 16];
        let lock_list_vaddr: u64 = 0x1111_2222_3333_4444;
        let return_addr: u64 = 0xDEAD_BEEF_CAFE_BABE;

        let body = build_hook_body_bytes(saved_prologue, lock_list_vaddr, return_addr);

        let is_patched = |w: usize| {
            (STOLEN_START..STOLEN_START + 4).contains(&w)
                || (RESTORE_LIT..RESTORE_LIT + 2).contains(&w)
                || (LOCK_LIST_LIT..LOCK_LIST_LIT + 2).contains(&w)
        };

        for (i, (body_w, gold)) in body
            .chunks_exact(4)
            .zip(HOOK_BODY_ORACLE.chunks_exact(4))
            .enumerate()
        {
            if is_patched(i) {
                continue;
            }
            let got = u32::from_le_bytes([body_w[0], body_w[1], body_w[2], body_w[3]]);
            let want = u32::from_le_bytes([gold[0], gold[1], gold[2], gold[3]]);
            assert_eq!(
                got, want,
                "instruction word {i} emitted by build_hook_body_bytes \
                 (0x{got:08x}) diverges from the independent oracle (0x{want:08x})"
            );
        }
    }

    // P04 T4 — lock-list mechanics tests

    /// Builds a dummy `HookHandle` for NUL-rejection paths that never reach
    /// ptrace. Both `hook_page == 0` and `lock_list_page == 0` short-circuit
    /// [`HookHandle::drop`] so no spurious remote work fires at end of scope.
    fn dummy_handle_for_pre_attach_reject() -> HookHandle {
        HookHandle {
            pid: 0,
            hook_page: 0,
            lock_list_page: 0,
            lock_list_len: 0,
            target_fn: 0,
            saved_prologue: [0u8; 16],
            libc_base: 0,
            libc_end: 0,
            scratch_pc: 0,
            trampoline_installed: false,
            kmsg_fds: Vec::new(),
        }
    }

    /// Three successive appends into a zero-init 1024-byte buffer yield the
    /// canonical `<entry><NUL>...<NUL><NUL>` layout; `cur_len` advances to
    /// the offset of the new trailing sentinel after each call. The final
    /// 10-byte payload matches the hook body's `cbz w11, .fallthrough`
    /// walker expectations (a standalone NUL sentinel after the last
    /// entry's own terminator).
    #[test]
    fn lock_list_append_bytes_three_entries() {
        let mut buf = vec![0u8; LOCK_LIST_CAPACITY as usize];
        let mut cur_len: u32 = 0;

        cur_len = lock_list_append_bytes(&mut buf, cur_len, b"a", LOCK_LIST_CAPACITY).unwrap();
        assert_eq!(cur_len, 2);

        cur_len = lock_list_append_bytes(&mut buf, cur_len, b"bb", LOCK_LIST_CAPACITY).unwrap();
        assert_eq!(cur_len, 5);

        cur_len = lock_list_append_bytes(&mut buf, cur_len, b"ccc", LOCK_LIST_CAPACITY).unwrap();
        assert_eq!(cur_len, 9);

        assert_eq!(&buf[0..10], b"a\0bb\0ccc\0\0");
    }

    /// Capacity guard fires when the new sentinel offset would land at or
    /// past `capacity`. At `cap = 16`, the last accepted name has
    /// `name.len() == 14` (sentinel lands at offset 15, the last valid
    /// index); `name.len() == 15` is the first rejected case because the
    /// sentinel would alias offset 16 — the first byte of the hook body.
    #[test]
    fn lock_list_append_bytes_rejects_capacity_overflow() {
        let mut buf = vec![0u8; 16];
        assert!(lock_list_append_bytes(&mut buf, 0, b"123456789012345", 16).is_none());
        assert!(lock_list_append_bytes(&mut buf, 0, b"12345678901234", 16).is_some());
    }

    /// Removing a middle entry shifts the trailing entries + sentinel left
    /// over the removed slot and zeros the now-stale tail. New `cur_len`
    /// equals the old `cur_len` minus `name.len() + 1` (the removed entry
    /// and its NUL terminator).
    #[test]
    fn lock_list_remove_bytes_middle_entry() {
        let mut buf = vec![0u8; LOCK_LIST_CAPACITY as usize];
        buf[0..10].copy_from_slice(b"a\0bb\0ccc\0\0");

        let new_len = lock_list_remove_bytes(&mut buf, 9, b"bb").unwrap();
        assert_eq!(new_len, 6);
        assert_eq!(&buf[0..7], b"a\0ccc\0\0");

        for byte in &buf[7..10] {
            assert_eq!(*byte, 0, "stale tail bytes must be zeroed after compaction");
        }
    }

    /// Missing name returns `None`; the buffer is left byte-for-byte
    /// unchanged so the caller can skip the remote write.
    #[test]
    fn lock_list_remove_bytes_missing_returns_none() {
        let mut buf = vec![0u8; LOCK_LIST_CAPACITY as usize];
        buf[0..6].copy_from_slice(b"a\0bb\0\0");
        let snapshot = buf.clone();

        assert!(lock_list_remove_bytes(&mut buf, 5, b"missing").is_none());
        assert_eq!(buf, snapshot);
    }

    /// Removing the only entry drops `cur_len` to zero and leaves the
    /// sentinel at offset 0 — the initial empty-list state the hook body
    /// encounters immediately after P03 stage-B.
    #[test]
    fn lock_list_remove_bytes_only_entry_resets_to_empty() {
        let mut buf = vec![0u8; LOCK_LIST_CAPACITY as usize];
        buf[0..6].copy_from_slice(b"solo\0\0");

        let new_len = lock_list_remove_bytes(&mut buf, 5, b"solo").unwrap();
        assert_eq!(new_len, 0);
        assert_eq!(buf[0], 0, "sentinel must sit at offset 0 for empty list");
    }

    /// Interior-NUL rejection fires before any ptrace work, so a dummy
    /// handle with `hook_page == 0` suffices — `seal_prop`'s guard clause
    /// returns `Err(Error::InvalidKey)` without touching
    /// `RemoteAttach::new`.
    #[test]
    fn seal_prop_rejects_interior_nul() {
        let mut handle = dummy_handle_for_pre_attach_reject();
        let err = seal_prop(&mut handle, "a\0b").unwrap_err();
        assert!(matches!(err, Error::InvalidKey));
    }

    // T04 / M2 — verify-after-write read-back gate

    /// The two words `install_trampoline` POKEs, packed exactly as they land
    /// in tracee memory: `word_lo` (`ldr x16,[pc,#8]` | `br x16`) then the
    /// absolute body target. Shared by the read-back tests so the "intended"
    /// bytes match the production encoder path.
    fn intended_trampoline_words(target: u64) -> (u64, u64) {
        let word_lo = (encoder::LDR_X16_PC8 as u64) | ((encoder::BR_X16 as u64) << 32);
        (word_lo, target)
    }

    /// A faithful read-back — the 16 bytes that came back equal the two words
    /// we wrote — passes the gate, so the i-cache sync proceeds untouched on a
    /// good install.
    #[test]
    fn verify_trampoline_readback_accepts_faithful_write() {
        let (word_lo, word_hi) = intended_trampoline_words(0x0000_7fff_abcd_1234);
        let mut readback = [0u8; 16];
        readback[..8].copy_from_slice(&word_lo.to_le_bytes());
        readback[8..].copy_from_slice(&word_hi.to_le_bytes());

        assert!(verify_trampoline_readback(word_lo, word_hi, &readback).is_ok());
    }

    /// Forces the torn write Defect-B can still produce past the POKE return
    /// codes: the high half of `word_hi` is dropped, so the read-back holds a
    /// half-written `br x16` target. The gate must flag the mismatch and
    /// return the typed [`Error::HookInstallFailed`] — spec assertions (a)
    /// detection and (d) typed error.
    #[test]
    fn verify_trampoline_readback_detects_torn_write() {
        let (word_lo, word_hi) = intended_trampoline_words(0x0000_7fff_abcd_1234);

        // Simulate a torn POKE: lo word landed, hi word lost its top 4 bytes.
        let torn_hi = word_hi & 0x0000_0000_ffff_ffff;
        let mut readback = [0u8; 16];
        readback[..8].copy_from_slice(&word_lo.to_le_bytes());
        readback[8..].copy_from_slice(&torn_hi.to_le_bytes());

        let err = verify_trampoline_readback(word_lo, word_hi, &readback).unwrap_err();
        assert!(
            matches!(err, Error::HookInstallFailed(ref m) if m.contains("read-back mismatch")),
            "torn write must surface as HookInstallFailed, got {err:?}"
        );
    }

    /// End-to-end of the rollback contract against a 16-byte model of
    /// `target_fn` in tracee memory: the install POKEs land a torn trampoline,
    /// the gate detects it, and the same decode `revert_trampoline` uses (two
    /// little-endian `u64` words of `saved_prologue`) restores init's original
    /// 16-byte prologue byte-for-byte — spec assertions (b) revert runs and
    /// (c) prologue intact.
    #[test]
    fn torn_trampoline_write_reverts_to_prologue() {
        let target = 0x0000_7fff_abcd_1234u64;
        let saved_prologue: [u8; 16] = [
            0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, // stp x29,x30 / mov x29,sp
            0x00, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6, // mov x0,#0 / ret
        ];

        // Model of the 16 bytes at `target_fn`, seeded with init's prologue.
        let mut cell = saved_prologue;

        // The install writes the trampoline words, but the hi POKE tears
        // (drops its top half). Mirror that into the cell.
        let (word_lo, word_hi) = intended_trampoline_words(target);
        let torn_hi = word_hi & 0x0000_0000_ffff_ffff;
        cell[..8].copy_from_slice(&word_lo.to_le_bytes());
        cell[8..].copy_from_slice(&torn_hi.to_le_bytes());
        assert_ne!(cell, saved_prologue, "torn write must perturb the cell");

        // The gate reads `cell` back and rejects it.
        assert!(verify_trampoline_readback(word_lo, word_hi, &cell).is_err());

        // `revert_trampoline` decodes `saved_prologue` as two LE u64 words and
        // POKEs them back over `target_fn` / `target_fn + 8`. Replay that
        // decode against the cell; the result must be the original prologue.
        let lo = u64::from_le_bytes(saved_prologue[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(saved_prologue[8..16].try_into().unwrap());
        cell[..8].copy_from_slice(&lo.to_le_bytes());
        cell[8..].copy_from_slice(&hi.to_le_bytes());

        assert_eq!(
            cell, saved_prologue,
            "revert must leave init's prologue byte-for-byte intact"
        );
    }

    /// `check_init_hook`'s remote sub-ops (attach + `process_vm_readv`) need a
    /// live aarch64 init and are exercised on-device in P05, not from an
    /// x86_64 host — same constraint as `install_init_hook` and the Drop body.
    /// What we can pin off-device is the public dry-run report surface: every
    /// resolved fact is reachable, matching the `hook_handle_size` field-layout
    /// check above.
    #[test]
    fn check_report_fields_reachable() {
        let r = CheckReport {
            libc_base: 0x7000_0000_0000,
            libc_end: 0x7000_0010_0000,
            target_fn: 0x7000_0001_2340,
            scratch_pc: 0x7000_0000_1000,
        };
        assert_eq!(r.libc_base, 0x7000_0000_0000);
        assert_eq!(r.libc_end, 0x7000_0010_0000);
        assert_eq!(r.target_fn, 0x7000_0001_2340);
        assert_eq!(r.scratch_pc, 0x7000_0000_1000);
    }

    // T08 / M4 / R3: per-boot install throttle

    /// After [`MAX_INSTALL_HARD_FAILURES`] hard failures the next
    /// `install_init_hook` is refused by the throttle guard, returning the
    /// reused [`Error::HookInstallFailed`] before the M1 identity check or
    /// any ptrace attach. `pid_t::MAX` names no live process, so every
    /// pre-threshold call fails in `verify_init_identity`'s `/proc` read with
    /// no remote work, forcing the counter to the ceiling off-device. This is
    /// the only test that touches `INSTALL_HARD_FAILURES`; it brackets the
    /// body with a reset so a parallel run starts and leaves it clean.
    #[test]
    fn install_init_hook_throttles_after_max_hard_failures() {
        INSTALL_HARD_FAILURES.store(0, Ordering::Relaxed);

        let absent_pid = libc::pid_t::MAX;
        for _ in 0..MAX_INSTALL_HARD_FAILURES {
            let Err(err) = install_init_hook(absent_pid) else {
                panic!("install_init_hook on an absent pid must fail without a live init");
            };
            assert!(
                !matches!(&err, Error::HookInstallFailed(m) if m.contains("throttled")),
                "pre-threshold failure must be a real install fault, not the throttle: {err:?}"
            );
        }

        let Err(err) = install_init_hook(absent_pid) else {
            panic!("a throttled install must return Err, not a handle");
        };
        assert!(
            matches!(&err, Error::HookInstallFailed(m) if m.contains("throttled")),
            "after {MAX_INSTALL_HARD_FAILURES} hard failures the next install must be throttled: {err:?}"
        );

        INSTALL_HARD_FAILURES.store(0, Ordering::Relaxed);
    }

    // T09 / Port 1: memfd install round-trip

    /// `proc_fd_path` formats the procfs handle this process fills and relabels.
    #[test]
    fn proc_fd_path_formats_procfs_link() {
        assert_eq!(proc_fd_path(1, 7), "/proc/1/fd/7");
    }

    /// `run_memfd_install` threads the fd from `memfd_create` into the `mmap`
    /// and `close`, runs `publish` against it, and returns the mapped address.
    /// Mocked remote syscalls return a non-zero address, exercising the
    /// sequence off-device.
    #[test]
    fn run_memfd_install_threads_fd_and_returns_mapped_addr() {
        use std::cell::RefCell;

        let fake_memfd: i64 = 7;
        let fake_addr: i64 = 0x0000_7f00_0000;
        let calls: RefCell<Vec<(u64, [u64; 6])>> = RefCell::new(Vec::new());
        let published = RefCell::new(None);

        let addr = run_memfd_install(
            0xdead_beef,
            |syscall_no, args| {
                calls.borrow_mut().push((syscall_no, args));
                match syscall_no {
                    NR_MEMFD_CREATE => Ok(fake_memfd),
                    NR_MMAP => Ok(fake_addr),
                    NR_CLOSE => Ok(0),
                    other => panic!("unexpected remote syscall {other}"),
                }
            },
            |memfd| {
                *published.borrow_mut() = Some(memfd);
                Ok(())
            },
        )
        .expect("memfd install must succeed with mocked syscalls");

        assert_eq!(addr, fake_addr as u64, "returns the mmap address as the hook page");
        assert_eq!(
            published.borrow().unwrap(),
            fake_memfd as u64,
            "publish runs against the created fd"
        );

        let calls = calls.borrow();
        assert_eq!(calls[0].0, NR_MEMFD_CREATE);
        assert_eq!(calls[0].1[0], 0xdead_beef, "memfd_create reads the staged name vaddr");
        assert_eq!(calls[0].1[1], MFD_CLOEXEC);
        assert_eq!(calls[1].0, NR_MMAP);
        assert_eq!(calls[1].1[2], PROT_RX, "hook page is mapped PROT_R|X");
        assert_eq!(calls[1].1[4], fake_memfd as u64, "mmap maps the created memfd");
        assert_eq!(calls[2].0, NR_CLOSE);
        assert_eq!(calls[2].1[0], fake_memfd as u64, "close releases the memfd");
    }

    /// A `-errno` return from `mmap` surfaces as `HookInstallFailed` and still
    /// closes the fd, so a failed install leaves no fd leaked in init.
    #[test]
    fn run_memfd_install_closes_fd_on_mmap_failure() {
        use std::cell::RefCell;

        let closed = RefCell::new(false);
        let err = run_memfd_install(
            0,
            |syscall_no, _args| match syscall_no {
                NR_MEMFD_CREATE => Ok(9),
                NR_MMAP => Ok(-12),
                NR_CLOSE => {
                    *closed.borrow_mut() = true;
                    Ok(0)
                }
                other => panic!("unexpected remote syscall {other}"),
            },
            |_memfd| Ok(()),
        )
        .unwrap_err();

        assert!(
            matches!(err, Error::HookInstallFailed(ref m) if m.contains("mmap")),
            "mmap failure must surface as HookInstallFailed, got {err:?}"
        );
        assert!(*closed.borrow(), "the memfd must be closed even when mmap fails");
    }
}
