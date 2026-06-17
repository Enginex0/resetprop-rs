//! Tier A arena seal — remote `MAP_PRIVATE|MAP_FIXED` remap of init's writable
//! view of a property arena. T1 shipped the mapping-lookup step; T2 shipped
//! the word-granularity PEEK / POKE primitives and the libc.text NOP-slide
//! finder; T3 (this file) ships the remote remap primitive
//! (`remote_remap_private`) that T4's `seal_arena` / `unseal_arena`
//! orchestrators will consume.

use std::path::Path;

use super::maps::{parse_maps, MapEntry};
use crate::error::{Error, Result};

// Syscall numbers and flag constants (REGISTRY §1 canonical values)

// Syscall numbers (asm-generic/unistd.h via linux-arm64-abi.md §1)
pub(crate) const NR_OPENAT: u64 = 56;
pub(crate) const NR_MMAP: u64 = 222;
pub(crate) const NR_CLOSE: u64 = 57;
pub(crate) const NR_MUNMAP: u64 = 215;

// fcntl/mman constants (asm-generic/fcntl.h, asm-generic/mman-common.h)
pub(crate) const AT_FDCWD: u64 = -100_i64 as u64; // sign-extended to 64 bits
pub(crate) const O_RDONLY: u64 = 0;
pub(crate) const O_RDONLY_NOFOLLOW: u64 = 0x20000;
pub(crate) const O_RDWR_NOFOLLOW: u64 = 0x20002;
pub(crate) const PROT_RW: u64 = 0x3;
pub(crate) const PROT_RX: u64 = 0x5;
pub(crate) const MAP_PRIVATE: u64 = 0x2;
pub(crate) const MAP_PRIVATE_FIXED: u64 = 0x12;
pub(crate) const MAP_SHARED_FIXED: u64 = 0x11;
pub(crate) const MAP_PRIVATE_ANON: u64 = 0x22;

// Bootstrap scratch page size — one 4 KiB RWX anonymous mapping in init.
pub(crate) const BOOTSTRAP_PAGE_SIZE: u64 = 4096;

// Upper bound on how much of libc.text we read when scanning for a NOP slide.
// 64 KiB covers any real libc far beyond the typical .text size but caps the
// cross-process copy cost.
pub(crate) const LIBC_SCAN_LIMIT: usize = 64 * 1024;

/// Pure helper: scan a pre-parsed maps slice for init's writable view of
/// `arena_path`.
///
/// Returns the first entry whose path equals `arena_path` and whose permissions
/// start with `b"rw"`. If only a read-only (`b"r-"`) match exists — or no match
/// at all — the error is `ArenaNotMapped(arena_path.to_path_buf())`; the
/// variant is reused for the ro-only case because both conditions surface the
/// same operator-visible failure (init does not have a writable mapping we can
/// remap), and a single error shape keeps caller branches simple.
///
/// NOTE: `MapEntry` is not `Clone` in P01 by design (deriving `Clone` would
/// widen its public surface). We reconstruct a fresh struct literal here
/// rather than returning `&MapEntry`, because `find_arena_mapping` owns the
/// `Vec<MapEntry>` from `parse_maps` and a borrowed return would tie the
/// caller to that vec's lifetime.
#[allow(dead_code)] // first direct caller lives in the integration smoke test (T5)
fn find_arena_mapping_in(entries: &[MapEntry], arena_path: &Path) -> Result<MapEntry> {
    for entry in entries {
        if entry.path.as_deref() == Some(arena_path) && entry.perms.starts_with(b"rw") {
            return Ok(MapEntry {
                start: entry.start,
                end: entry.end,
                perms: entry.perms,
                offset: entry.offset,
                path: entry.path.clone(),
            });
        }
    }
    Err(Error::ArenaNotMapped(arena_path.to_path_buf()))
}

/// Locate init's writable mapping of `arena_path` in `/proc/<pid>/maps`.
pub(crate) fn find_arena_mapping(pid: libc::pid_t, arena_path: &Path) -> Result<MapEntry> {
    let entries = parse_maps(pid)?;
    find_arena_mapping_in(&entries, arena_path)
}

/// AArch64 `nop` instruction encoding: `d503201f` little-endian bytes
/// `[0x1f, 0x20, 0x03, 0xd5]`. Source: ARM ARM C6.2.203.
pub(crate) const ARM64_NOP: u32 = 0xd503_201f;

/// Scan `bytes` for the first 8-byte-aligned offset where at least four
/// consecutive `ARM64_NOP` words (16 bytes) appear.
///
/// Returns the offset into `bytes`. Callers add it to the mapping's start
/// address to get a scratch PC that is (a) inside an executable mapping,
/// (b) inside a benign nop run so restoring the original bytes after the
/// bootstrap `svc+brk` is trivial, and (c) 8-byte aligned so a two-word
/// blob writes atomically via a single PTRACE_POKEDATA.
///
/// Returns `None` if no qualifying run exists in `bytes`. Modern bionic
/// `libc.so` on Android 15 is compiled tightly and does not guarantee a
/// 4-NOP run anywhere in `.text`; callers should prefer [`find_scratch_slot`]
/// which falls back to any aligned offset because the save/restore guards
/// around the POKE window already cover the correctness invariant this
/// scanner was added to protect.
pub(crate) fn find_nop_slide(bytes: &[u8]) -> Option<usize> {
    const NOP_BYTES: [u8; 4] = ARM64_NOP.to_le_bytes();
    if bytes.len() < 16 {
        return None;
    }
    let mut off = 0;
    while off + 16 <= bytes.len() {
        if off % 8 == 0
            && bytes[off..off + 4] == NOP_BYTES
            && bytes[off + 4..off + 8] == NOP_BYTES
            && bytes[off + 8..off + 12] == NOP_BYTES
            && bytes[off + 12..off + 16] == NOP_BYTES
        {
            return Some(off);
        }
        off += 4; // ARM64 instruction stride; 8-byte alignment filter applied above
    }
    None
}

/// Minimum scratch offset used by the fallback path — skips past any ELF
/// entry stubs or PLT-adjacent prologues that might appear right at the
/// start of `.text`. 64 bytes = 16 ARM64 instructions, well beyond the
/// largest trampoline bionic emits at section start.
const SCRATCH_FALLBACK_MIN_OFFSET: usize = 64;

/// Pick an 8-byte-aligned scratch offset inside the libc.text scan window.
///
/// Prefers a 4-NOP slide when one exists (defense in depth — if a restore
/// POKE ever fails mid-flight, NOPs are a safe re-entry for a stray thread).
/// Falls back to the first aligned offset ≥ [`SCRATCH_FALLBACK_MIN_OFFSET`]
/// when no NOP run is present, which is the common case on modern bionic.
///
/// Safety of the fallback rests on two invariants that P02 already enforces:
/// 1. `RemoteAttach` SEIZE+INTERRUPT stops the tracee before we POKE, so
///    no thread executes at `scratch_pc` during the bootstrap window.
/// 2. Every `?`-propagation after the POKE is wrapped with a best-effort
///    `ptrace_poketext`-based restore of the original bytes plus register
///    state, so libc.text is left pristine whether we succeed or unwind.
///
/// Returns `None` only when `bytes` is smaller than one scratch slot; the
/// caller surfaces that as `Error::HookInstallFailed`.
pub(crate) fn find_scratch_slot(bytes: &[u8]) -> Option<usize> {
    if let Some(offset) = find_nop_slide(bytes) {
        return Some(offset);
    }
    let min = SCRATCH_FALLBACK_MIN_OFFSET;
    if bytes.len() < min + 16 {
        return None;
    }
    Some(min.next_multiple_of(8))
}

// RemapFlags — direction selector for remote_remap_private

/// Direction of the arena remap — `Private` seals (blocks writes from
/// propagating), `Shared` restores init's original view (unseal).
#[derive(Debug, Clone, Copy)]
pub(crate) enum RemapFlags {
    Private,
    Shared,
}

impl RemapFlags {
    const fn open_flags(self) -> u64 {
        match self {
            Self::Private => O_RDONLY_NOFOLLOW,
            Self::Shared => O_RDWR_NOFOLLOW,
        }
    }
    const fn mmap_flags(self) -> u64 {
        match self {
            Self::Private => MAP_PRIVATE_FIXED,
            Self::Shared => MAP_SHARED_FIXED,
        }
    }
}

// verify_init_identity — M1 init-identity guard (runs BEFORE any RemoteAttach)

/// Read `/proc/<pid>/comm` — the kernel's per-process command name, written
/// with a trailing newline. Authored fresh for the M1 guard; no other
/// `/proc/<pid>/comm` reader exists in the tree.
fn read_proc_comm(pid: super::Pid) -> Result<String> {
    Ok(std::fs::read_to_string(format!("/proc/{pid}/comm"))?)
}

/// M1 init-identity guard. Verify `pid` really is Android init *before* the
/// caller opens a [`RemoteAttach`] window or pokes a single byte, so a non-init
/// PID-1 stand-in is rejected with [`Error::NotInit`] rather than silently
/// patched. Both Tier A (`remote_remap_private`) and Tier B
/// (`super::hook::install_init_hook`) call this in front of `RemoteAttach::new`.
pub(crate) fn verify_init_identity(pid: super::Pid) -> Result<()> {
    let comm = read_proc_comm(pid)?;
    let maps = parse_maps(pid)?;
    check_init_identity(&comm, &maps)
}

/// Pure decision core for [`verify_init_identity`], split out so both gates are
/// unit-testable against a fabricated fake-PID-1 fixture (a `comm` string and a
/// `MapEntry` slice) with no real `/proc` access.
///
/// Two independent gates:
///   1. `/proc/<pid>/comm` is exactly `init`.
///   2. an r-xp `libc.so` row is mapped, mirroring [`super::hook::is_libc_row`]
///      — the expected APEX/system bionic libc the seal pipeline patches.
fn check_init_identity(comm: &str, maps: &[MapEntry]) -> Result<()> {
    let name = comm.trim_end();
    if name != "init" {
        return Err(Error::NotInit(format!(
            "/proc/<pid>/comm is {name:?}, expected \"init\""
        )));
    }
    if !maps.iter().any(super::hook::is_libc_row) {
        return Err(Error::NotInit(
            "no r-xp libc.so mapping in target; not the expected bionic init".into(),
        ));
    }
    Ok(())
}

// RemoteAttach — RAII guard that detaches on drop

/// RAII guard that group-stops init's **entire** thread group on construction
/// and resumes every frozen thread on Drop.
///
/// [`RemoteAttach::new`] freezes every `/proc/<pid>/task/` tid (not just the
/// leader) via SEIZE+INTERRUPT+wait_stop and re-scans until the group is stable
/// — the T15 fix for Defect B, where init's siblings kept running on other
/// cores through the Tier A remap and the Tier B trampoline pokes. If any
/// subsequent operation returns `Err`, the `?` unwinds through this guard and
/// every seized thread is released. Detach failures during unwind are logged
/// via `eprintln!` and swallowed — there is no recoverable action, and
/// panicking in Drop would abort on unwind (double panic).
///
/// The group-stop machinery itself lives in [`super::ptrace`]
/// (`seize_thread_group` / `detach_thread_group`); this guard is the single
/// entry point both tiers and T03's pending init-identity guard build on, so
/// its public surface (`new` / `detach` / `pid`) is held stable — T03 rebases
/// its guard *in front of* `new`.
pub(crate) struct RemoteAttach {
    /// Thread-group leader pid (init's `1`). `pid()` returns this; all remote
    /// PEEK/POKE/syscall work still targets the leader's (shared) address space.
    pid: super::Pid,
    /// Every tid SEIZE+INTERRUPT+wait_stop froze for this window — the whole
    /// thread group, leader included. Resumed in `detach` / Drop.
    stopped_tids: Vec<super::Pid>,
    detached: bool,
}

impl RemoteAttach {
    // P03 T5 promoted `new` / `detach` / `pid` to `pub(crate)` so the Tier B
    // hook installer in `seal::hook` consumes this RAII guard without
    // reimplementing the attach. T15 widens the body from a leader-only stop to
    // a whole-thread-group stop while keeping that public surface intact.
    pub(crate) fn new(pid: super::Pid) -> Result<Self> {
        // T15 group-stop entry point — freeze the ENTIRE thread group of `pid`
        // before any caller pokes. See `super::ptrace::seize_thread_group`.
        let stopped_tids = super::ptrace::seize_thread_group(pid)?;
        Ok(Self {
            pid,
            stopped_tids,
            detached: false,
        })
    }

    pub(crate) fn detach(mut self) -> Result<()> {
        self.detached = true;
        super::ptrace::detach_thread_group(&self.stopped_tids)
    }

    pub(crate) fn pid(&self) -> super::Pid {
        self.pid
    }
}

impl Drop for RemoteAttach {
    fn drop(&mut self) {
        if !self.detached {
            // Best-effort: resume every frozen tid (ESRCH-tolerant). Errors are
            // logged and swallowed; panicking in Drop would abort on unwind.
            if let Err(e) = super::ptrace::detach_thread_group(&self.stopped_tids) {
                eprintln!("resetprop: thread-group detach during unwind failed: {e}");
            }
        }
    }
}

// remote_remap_private — the core Tier A seal primitive

/// Remap init's mapping of `arena_path` as `MAP_PRIVATE|MAP_FIXED`
/// (Tier A seal) or `MAP_SHARED|MAP_FIXED` (unseal) via remote syscalls
/// executed in the tracee's own address space.
///
/// Bootstrap flow:
/// 1. Attach to `pid` (SEIZE + INTERRUPT + wait_stop(PTRACE_EVENT_STOP)).
///    Guarded by `RemoteAttach` so a `?`-propagation still detaches.
/// 2. Parse `/proc/<pid>/maps`, locate the first `r-xp` mapping of libc.so.
/// 3. Read up to `LIBC_SCAN_LIMIT` bytes of its text via `read_remote`;
///    `find_nop_slide` locates an 8-byte-aligned 16-byte NOP run.
/// 4. Save the 8 bytes at `scratch_pc` via `ptrace_peektext`; POKE the
///    `svc #0 ; brk #0` blob via `ptrace_poketext`.
/// 5. Snapshot registers, build work regs running `mmap(NULL, 4096,
///    PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)`, resume until brk, read x0
///    as `bootstrap_page`. Restore scratch bytes and registers immediately
///    — before any error-check can `?` — so libc.text is always left
///    pristine.
/// 6. Write the NUL-terminated arena path to `bootstrap_page` via
///    `write_remote`; `remote_syscall` openat (scratch_pc=bootstrap_page,
///    the fresh RWX page); `remote_syscall` mmap
///    (`MAP_PRIVATE|MAP_FIXED` or `MAP_SHARED|MAP_FIXED` per `flags`) over
///    the arena VMA — must return exactly `mapping.start`; `remote_syscall`
///    close the fd.
/// 7. munmap the bootstrap page (runs on every post-mmap exit), then
///    `guard.detach()` returns cleanly.
///
/// # Safety
///
/// Caller guarantees `pid` refers to a process whose address space may be
/// modified (typically `1` for init on a rooted Android device). The
/// function installs a temporary 4 KiB RW anonymous mapping in the tracee
/// and frees it on every post-mmap exit (see the closure + munmap at the
/// end of the body). A tracee death mid-sequence is detected as
/// `Error::PtraceOp` via the existing `last_ptrace_op_err` path in P01's
/// primitives.
pub(crate) unsafe fn remote_remap_private(
    pid: super::Pid,
    mapping: &super::maps::MapEntry,
    arena_path: &std::path::Path,
    flags: RemapFlags,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    // M1: reject a non-init PID-1 stand-in before attaching or poking.
    verify_init_identity(pid)?;

    let guard = RemoteAttach::new(pid)?;

    // --- Locate a libc.text NOP slide in the tracee ----------------------
    let maps_entries = super::maps::parse_maps(pid)?;
    let libc_text = maps_entries
        .iter()
        .find(|e| {
            e.perms.starts_with(b"r-x")
                && e.path
                    .as_deref()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n == "libc.so" || n.starts_with("libc.so."))
        })
        .ok_or_else(|| Error::HookInstallFailed("no libc.so r-x mapping in target".into()))?;

    let scan_len = (libc_text.end - libc_text.start).min(LIBC_SCAN_LIMIT as u64) as usize;
    let mut scan_buf = vec![0u8; scan_len];
    // SAFETY: `libc_text` came from parse_maps, so `libc_text.start..+scan_len`
    // is an `r-xp` mapping of at least `scan_len` bytes in the tracee, which
    // process_vm_readv reads without issue (the `r` bit is set). The tracee
    // is ptrace-stopped for the duration (guarded by `RemoteAttach` above).
    unsafe { super::ptrace::read_remote(pid, libc_text.start, &mut scan_buf)? };

    let slide_offset = find_scratch_slot(&scan_buf).ok_or_else(|| {
        Error::HookInstallFailed("libc.text scan too small for scratch slot".into())
    })?;
    let scratch_pc = libc_text.start + slide_offset as u64;

    // --- Bootstrap: POKEDATA an svc+brk blob at scratch_pc ---------------
    let saved_bytes = super::ptrace::ptrace_peektext(guard.pid(), scratch_pc)?;

    // trap (low 4 bytes) ; brk (high 4 bytes), little-endian pack
    let trap_brk: u64 =
        (super::ptrace::TRAP_INSN as u64) | ((super::ptrace::BRK_INSN as u64) << 32);
    super::ptrace::ptrace_poketext(guard.pid(), scratch_pc, trap_brk)?;

    let bootstrap_page = {
        let saved_regs = super::ptrace::getregset(guard.pid())?;
        let mut work = saved_regs;
        // mmap(NULL, 4096, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0) — page is
        // data-only, so no execmem is requested. Staged through the arch-
        // neutral interface so no raw register index appears here.
        super::ptrace::set_syscall_args(
            &mut work,
            scratch_pc,
            NR_MMAP,
            [
                0,                   // addr = NULL
                BOOTSTRAP_PAGE_SIZE, // len  = 4096
                PROT_RW,             // prot
                MAP_PRIVATE_ANON,    // flags
                (-1_i64) as u64,     // fd = -1
                0,                   // offset
            ],
        );

        super::ptrace::setregset(guard.pid(), &work)?;

        // SAFETY: `libc::ptrace` FFI; tracee is stopped per RemoteAttach's
        // post-wait_stop contract; `addr` / `data` are NULL per the
        // PTRACE_CONT contract.
        let rc = unsafe {
            libc::ptrace(
                super::ptrace::PTRACE_CONT as _,
                guard.pid(),
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if rc == -1 {
            // Best-effort restore before propagating, so libc.text isn't
            // left with the svc+brk bytes in place.
            let _ = super::ptrace::ptrace_poketext(guard.pid(), scratch_pc, saved_bytes);
            let _ = super::ptrace::setregset(guard.pid(), &saved_regs);
            return Err(Error::PtraceOp(std::io::Error::last_os_error()));
        }

        // Always restore scratch bytes + registers before inspecting the
        // result. A failure in `wait_stop` or `getregset` must not leave
        // libc.text containing live svc+brk or the tracee's saved regs in
        // work-state — RemoteAttach::drop would release init into that
        // poisoned state and the next thread scheduled at scratch_pc would
        // trap on brk #0. On the pre-restore failure paths the errors from
        // the restore calls are discarded in favor of the original cause.
        let wait_result = super::ptrace::wait_stop(guard.pid(), 0);
        if wait_result.is_err() {
            let _ = super::ptrace::ptrace_poketext(guard.pid(), scratch_pc, saved_bytes);
            let _ = super::ptrace::setregset(guard.pid(), &saved_regs);
        }
        wait_result?;

        let out_result = super::ptrace::getregset(guard.pid());
        if out_result.is_err() {
            let _ = super::ptrace::ptrace_poketext(guard.pid(), scratch_pc, saved_bytes);
            let _ = super::ptrace::setregset(guard.pid(), &saved_regs);
        }
        let out = out_result?;
        let ret = super::ptrace::get_syscall_return(&out);

        super::ptrace::ptrace_poketext(guard.pid(), scratch_pc, saved_bytes)?;
        super::ptrace::setregset(guard.pid(), &saved_regs)?;

        if (-4095..=-1).contains(&ret) {
            return Err(Error::HookInstallFailed(format!(
                "bootstrap mmap failed: errno={}",
                -ret
            )));
        }
        ret as u64
    };

    // --- Stage path, openat, remap, close --------------------------------
    // Every fallible step lives in this closure so the single munmap below
    // frees `bootstrap_page` on both the success and the error exit — no
    // post-mmap path can leak the page.
    let staged = (|| -> Result<()> {
        // --- Stage the arena path at `bootstrap_page` --------------------
        let path_bytes = arena_path.as_os_str().as_bytes();
        let mut path_nul = Vec::with_capacity(path_bytes.len() + 1);
        path_nul.extend_from_slice(path_bytes);
        path_nul.push(0);
        if path_nul.len() as u64 > BOOTSTRAP_PAGE_SIZE {
            return Err(Error::HookInstallFailed(format!(
                "arena path exceeds scratch page: {} bytes",
                path_nul.len()
            )));
        }
        // SAFETY: `bootstrap_page` is the fresh `PROT_RW` page we just mapped;
        // process_vm_writev respects VMA write bits and the page is writable.
        // Tracee remains ptrace-stopped for the duration (guarded above).
        unsafe { super::ptrace::write_remote(pid, bootstrap_page, &path_nul)? };

        // --- openat(AT_FDCWD, bootstrap_page, flags.open_flags(), 0, 0, 0) -
        // SAFETY: scratch_pc points into libc.text r-xp; PEEK/POKEDATA bypasses
        // VMA write bits; tracee stopped by RemoteAttach; bootstrap_page is
        // PROT_RW and holds the NUL-terminated pathname at its base.
        let fd_ret = unsafe {
            super::ptrace::remote_syscall_via_poke(
                pid,
                scratch_pc,
                NR_OPENAT,
                [AT_FDCWD, bootstrap_page, flags.open_flags(), 0, 0, 0],
            )?
        };
        if fd_ret < 0 {
            return Err(Error::HookInstallFailed(format!(
                "openat failed: errno={}",
                -fd_ret
            )));
        }
        let fd = fd_ret as u64;

        // --- mmap(mapping.start, len, PROT_RW, flags.mmap_flags(), fd, 0) -
        // SAFETY: same rationale as the openat call above.
        let mmap_ret = unsafe {
            super::ptrace::remote_syscall_via_poke(
                pid,
                scratch_pc,
                NR_MMAP,
                [
                    mapping.start,
                    mapping.end - mapping.start,
                    PROT_RW,
                    flags.mmap_flags(),
                    fd,
                    0,
                ],
            )?
        };
        if mmap_ret as u64 != mapping.start {
            // Best-effort close; diagnostic wins over tidy here.
            // SAFETY: same rationale as the openat call above.
            let _ = unsafe {
                super::ptrace::remote_syscall_via_poke(
                    pid,
                    scratch_pc,
                    NR_CLOSE,
                    [fd, 0, 0, 0, 0, 0],
                )
            };
            return Err(Error::HookInstallFailed(format!(
                "mmap returned {mmap_ret:#x}, expected {:#x}",
                mapping.start
            )));
        }

        // --- close(fd) ---------------------------------------------------
        // SAFETY: scratch_pc is in libc.text r-xp; PEEK/POKEDATA bypasses write
        // bits. Close failure here is benign — the seal is already applied, and
        // a retry would leak a second bootstrap page. Diagnostic over tidy.
        let _ = unsafe {
            super::ptrace::remote_syscall_via_poke(pid, scratch_pc, NR_CLOSE, [fd, 0, 0, 0, 0, 0])
        };

        Ok(())
    })();

    // --- munmap(bootstrap_page, BOOTSTRAP_PAGE_SIZE) ---------------------
    // Runs on BOTH the success and the error exit of the closure above, so the
    // bootstrap page is freed on every post-mmap path — no error unwind leaks
    // the 4 KiB.
    // SAFETY: scratch_pc is in libc.text r-xp; remote_syscall_via_poke bypasses
    // VMA write bits via PEEK/POKEDATA. munmap failure here is benign (leaked
    // 4 KiB in the tracee) — the seal itself is already applied, so do not
    // propagate the error.
    let _ = unsafe {
        super::ptrace::remote_syscall_via_poke(
            pid,
            scratch_pc,
            NR_MUNMAP,
            [bootstrap_page, BOOTSTRAP_PAGE_SIZE, 0, 0, 0, 0],
        )
    };

    // Propagate any staging error only after the page has been released above.
    staged?;

    guard.detach()?;
    Ok(())
}

// Tier A orchestrators — thin compositions over find_arena_mapping +
// remote_remap_private. These are the public seam consumed by
// `PropSystem::seal_arena` / `::unseal_arena` and by the T5 smoke test.

/// Tier A seal: remap init's writable view of `arena_path` as
/// `MAP_PRIVATE|MAP_FIXED`. Thin composition of `find_arena_mapping` +
/// `remote_remap_private` with `RemapFlags::Private`.
pub fn seal_arena(pid: super::Pid, arena_path: &std::path::Path) -> Result<()> {
    let mapping = find_arena_mapping(pid, arena_path)?;
    // SAFETY: `pid` and `mapping` are caller-verified; the underlying
    // primitive handles attach/detach/scratch-restoration internally.
    unsafe { remote_remap_private(pid, &mapping, arena_path, RemapFlags::Private) }
}

/// Inverse of `seal_arena`: remap with `MAP_SHARED|MAP_FIXED` to restore
/// init's original view.
pub fn unseal_arena(pid: super::Pid, arena_path: &std::path::Path) -> Result<()> {
    let mapping = find_arena_mapping(pid, arena_path)?;
    // SAFETY: same rationale as `seal_arena`.
    unsafe { remote_remap_private(pid, &mapping, arena_path, RemapFlags::Shared) }
}

/// Apply `seal_arena` to `primary`, then to `mirror` if present.
/// First-error-wins: if sealing the primary fails, the mirror is not
/// attempted; if the primary succeeds but the mirror fails, the error
/// propagates with the primary already sealed.
pub fn seal_arena_with_mirror(
    pid: super::Pid,
    primary: &std::path::Path,
    mirror: Option<&std::path::Path>,
) -> Result<()> {
    seal_arena(pid, primary)?;
    if let Some(m) = mirror {
        seal_arena(pid, m)?;
    }
    Ok(())
}

/// Inverse of `seal_arena_with_mirror`.
pub fn unseal_arena_with_mirror(
    pid: super::Pid,
    primary: &std::path::Path,
    mirror: Option<&std::path::Path>,
) -> Result<()> {
    unseal_arena(pid, primary)?;
    if let Some(m) = mirror {
        unseal_arena(pid, m)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk(path: &str, perms: &[u8; 4], start: u64) -> MapEntry {
        MapEntry {
            start,
            end: start + 0x1000,
            perms: *perms,
            offset: 0,
            path: Some(PathBuf::from(path)),
        }
    }

    #[test]
    fn find_arena_mapping_picks_rw_view() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![
            mk(arena.to_str().unwrap(), b"r-xp", 0x1000),
            mk(arena.to_str().unwrap(), b"rw-p", 0xdead_0000),
        ];
        let hit = find_arena_mapping_in(&entries, arena).expect("rw match expected");
        assert!(hit.perms.starts_with(b"rw"));
        assert_eq!(hit.start, 0xdead_0000);
    }

    #[test]
    fn find_arena_mapping_rejects_ro_only_fixture() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![mk(arena.to_str().unwrap(), b"r-xp", 0x1000)];
        match find_arena_mapping_in(&entries, arena) {
            Err(Error::ArenaNotMapped(p)) => assert_eq!(p, arena.to_path_buf()),
            other => panic!("expected ArenaNotMapped, got {other:?}"),
        }
    }

    #[test]
    fn find_arena_mapping_returns_not_mapped_on_miss() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![
            mk("/some/other/file", b"rw-p", 0x1000),
            mk("/another/unrelated", b"rw-p", 0x2000),
        ];
        match find_arena_mapping_in(&entries, arena) {
            Err(Error::ArenaNotMapped(p)) => assert_eq!(p, arena.to_path_buf()),
            other => panic!("expected ArenaNotMapped, got {other:?}"),
        }
    }

    /// Build a byte buffer with `n` consecutive ARM64_NOP words at `offset`.
    fn with_nop_run(prefix_len: usize, nop_words: usize, suffix_len: usize) -> Vec<u8> {
        let nop = ARM64_NOP.to_le_bytes();
        let mut buf = vec![0xFFu8; prefix_len];
        for _ in 0..nop_words {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, suffix_len));
        buf
    }

    #[test]
    fn find_nop_slide_locates_first_aligned_run() {
        // 32 bytes of 0xFF, then 4 NOP words (16 bytes), then 16 bytes of 0xFF.
        // First qualifying 8-byte-aligned 4-NOP run starts at offset 32.
        let buf = with_nop_run(32, 4, 16);
        assert_eq!(find_nop_slide(&buf), Some(32));
    }

    #[test]
    fn find_nop_slide_returns_none_when_no_run_exists() {
        let buf = vec![0xFFu8; 64];
        assert!(find_nop_slide(&buf).is_none());
    }

    #[test]
    fn find_scratch_slot_prefers_nop_slide_when_present() {
        let buf = with_nop_run(32, 4, 16);
        assert_eq!(find_scratch_slot(&buf), Some(32));
    }

    #[test]
    fn find_scratch_slot_falls_back_to_aligned_offset() {
        let buf = vec![0xFFu8; 128];
        assert_eq!(find_scratch_slot(&buf), Some(SCRATCH_FALLBACK_MIN_OFFSET));
    }

    #[test]
    fn find_scratch_slot_returns_none_when_buffer_too_small() {
        let buf = vec![0xFFu8; SCRATCH_FALLBACK_MIN_OFFSET];
        assert!(find_scratch_slot(&buf).is_none());
    }

    #[test]
    fn find_nop_slide_prefers_aligned_run_over_earlier_unaligned() {
        // Layout: [4 bytes 0xFF][4 NOPs at offset 4 — UNALIGNED][12 bytes 0xFF]
        //         [4 NOPs at offset 32 — ALIGNED][trailing 0xFF]
        // The unaligned run must be skipped; the aligned run at 32 wins.
        let nop = ARM64_NOP.to_le_bytes();
        let mut buf = vec![0xFFu8; 4];
        for _ in 0..4 {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, 12));
        assert_eq!(buf.len(), 32);
        for _ in 0..4 {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, 16));
        assert_eq!(find_nop_slide(&buf), Some(32));
    }

    #[test]
    fn remap_flags_private_maps_to_correct_values() {
        assert_eq!(RemapFlags::Private.open_flags(), 0x20000);
        assert_eq!(RemapFlags::Private.mmap_flags(), 0x12);
    }

    #[test]
    fn remap_flags_shared_maps_to_correct_values() {
        assert_eq!(RemapFlags::Shared.open_flags(), 0x20002);
        assert_eq!(RemapFlags::Shared.mmap_flags(), 0x11);
    }

    #[test]
    fn constants_match_registry_canonical_values() {
        // Syscall numbers (REGISTRY §1, linux-arm64-abi.md §1)
        assert_eq!(NR_OPENAT, 56);
        assert_eq!(NR_MMAP, 222);
        assert_eq!(NR_CLOSE, 57);
        assert_eq!(NR_MUNMAP, 215);

        // fcntl / mman flags
        assert_eq!(AT_FDCWD, (-100_i64) as u64);
        assert_eq!(O_RDONLY, 0);
        assert_eq!(O_RDONLY_NOFOLLOW, 0x20000);
        assert_eq!(O_RDWR_NOFOLLOW, 0x20002);
        assert_eq!(PROT_RW, 0x3);
        assert_eq!(PROT_RX, 0x5);
        assert_eq!(MAP_PRIVATE, 0x2);
        assert_eq!(MAP_PRIVATE_FIXED, 0x12);
        assert_eq!(MAP_SHARED_FIXED, 0x11);
        assert_eq!(MAP_PRIVATE_ANON, 0x22);

        // Bootstrap / scan sizing
        assert_eq!(BOOTSTRAP_PAGE_SIZE, 4096);
        assert_eq!(LIBC_SCAN_LIMIT, 64 * 1024);
    }

    fn libc_row() -> MapEntry {
        mk(
            "/apex/com.android.runtime/lib64/bionic/libc.so",
            b"r-xp",
            0x2000,
        )
    }

    #[test]
    fn init_identity_accepts_init_with_libc_row() {
        let maps = vec![mk("/system/bin/init", b"r-xp", 0x1000), libc_row()];
        assert!(check_init_identity("init\n", &maps).is_ok());
    }

    #[test]
    fn init_identity_rejects_non_init_comm() {
        let maps = vec![libc_row()];
        match check_init_identity("system_server\n", &maps) {
            Err(Error::NotInit(_)) => {}
            other => panic!("expected NotInit, got {other:?}"),
        }
    }

    #[test]
    fn init_identity_rejects_init_without_libc_row() {
        let maps = vec![mk("/system/bin/init", b"r-xp", 0x1000)];
        match check_init_identity("init\n", &maps) {
            Err(Error::NotInit(_)) => {}
            other => panic!("expected NotInit, got {other:?}"),
        }
    }

    #[test]
    fn init_identity_rejects_live_non_init_pid() {
        // The test process stands in as a real, live non-init PID-1: its comm is
        // the test binary, not "init", so the full /proc path must reject it.
        match verify_init_identity(std::process::id() as libc::pid_t) {
            Err(Error::NotInit(_)) => {}
            other => panic!("expected NotInit for self pid, got {other:?}"),
        }
    }
}
