//! ARM64 ptrace core — attach/detach primitives and register IO.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `linux/ptrace.h` lines 17, 21, 27-31 — `PTRACE_*` request numbers
//! - `linux/elf.h` line 301 — `NT_PRSTATUS`
//! - `asm-arm64/asm/ptrace.h` lines 49-54 — `struct user_pt_regs`
//!
//! See `phases/seal/references/linux-arm64-abi.md` §3-§6 for the full reference.
//!
//! P01 Task 3 scope: the six ptrace primitives (`ptrace_seize`,
//! `ptrace_interrupt`, `wait_stop`, `getregset`, `setregset`, `ptrace_detach`),
//! the `UserPtRegs` layout with a 272-byte compile-time size assertion,
//! and the raw ARM64 instruction encodings used by P01 Task 4's
//! `remote_syscall` injector.

use super::Pid;
use crate::error::{Error, Result};
use std::io;

use libc::{c_int, c_void, iovec, process_vm_readv, process_vm_writev};

// ─────────────────────────────────────────────────────────────────────────────
// PTRACE request numbers — from bionic/libc/kernel/uapi/linux/ptrace.h
// ─────────────────────────────────────────────────────────────────────────────

/// `PTRACE_CONT` — resume a stopped tracee. source: linux/ptrace.h:17
pub const PTRACE_CONT: c_int = 7;

/// `PTRACE_DETACH` — detach from tracee. source: linux/ptrace.h:21
pub const PTRACE_DETACH: c_int = 17;

/// `PTRACE_GETREGSET` — read a register set via iovec. source: linux/ptrace.h:27
pub const PTRACE_GETREGSET: c_int = 0x4204;

/// `PTRACE_SETREGSET` — write a register set via iovec. source: linux/ptrace.h:28
pub const PTRACE_SETREGSET: c_int = 0x4205;

/// `PTRACE_SEIZE` — non-destructive attach (no stop). source: linux/ptrace.h:29
pub const PTRACE_SEIZE: c_int = 0x4206;

/// `PTRACE_INTERRUPT` — request synchronous stop on seized tracee. source: linux/ptrace.h:30
pub const PTRACE_INTERRUPT: c_int = 0x4207;

/// `PTRACE_PEEKDATA` — read one word from tracee memory, bypassing VMA read
/// bits via the ptrace_access_vm path. Pair with [`PTRACE_POKEDATA`] for
/// bootstrap staging of a first `svc` into an `r-xp` libc.text NOP slide,
/// since `process_vm_readv` respects VMA permissions while PEEK/POKE do not.
/// source: linux/ptrace.h:12
pub const PTRACE_PEEKDATA: c_int = 2;

/// `PTRACE_POKEDATA` — write one word (u64 on AArch64) into tracee memory,
/// bypassing VMA write bits. Used exclusively to stage the bootstrap
/// `svc #0 ; brk #0` blob at a libc.text scratch PC in P02's Tier A seal
/// flow; subsequent writes go through [`write_remote`] once a fresh
/// `MAP_PRIVATE|MAP_ANON` RWX page has been acquired.
/// source: linux/ptrace.h:15
pub const PTRACE_POKEDATA: c_int = 5;

/// `PTRACE_O_TRACESYSGOOD` — when set via the `data` arg of `PTRACE_SEIZE`,
/// makes syscall-stops distinguishable from regular `SIGTRAP` via status
/// `stopsig == 0x85`. Required for safe operation against multi-threaded
/// tracees (e.g. init in P04) where concurrent syscall-stops would otherwise
/// alias brk-traps. source: linux/ptrace.h:100
pub const PTRACE_O_TRACESYSGOOD: c_int = 1;

/// `PTRACE_EVENT_STOP` — upper-byte marker of the initial `PTRACE_SEIZE +
/// PTRACE_INTERRUPT` group-stop. Distinct from brk-trap (event == 0).
/// source: linux/ptrace.h:99
pub const PTRACE_EVENT_STOP: u32 = 128;

/// `NT_PRSTATUS` — note type selecting general-purpose regs for REGSET ops.
/// source: linux/elf.h:301
pub const NT_PRSTATUS: c_int = 1;

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 instruction encodings — used by P01 T4 remote_syscall stager
// ─────────────────────────────────────────────────────────────────────────────

/// `svc #0` — AArch64 supervisor call, little-endian bytes `01 00 00 d4`.
/// `pub(crate)` scope because only [`remote_syscall`] consumes this; the
/// ARM64 encoder in P04 (`seal/hook.rs`) re-derives its own encodings.
/// source: ARM ARM C6.2.304; linux-arm64-abi.md §2
pub(crate) const ARM64_SVC_0: u32 = 0xd400_0001;

/// `brk #0` — AArch64 software breakpoint (delivers SIGTRAP),
/// little-endian bytes `00 00 20 d4`. `pub(crate)` for the same reason as
/// [`ARM64_SVC_0`].
/// source: ARM ARM C6.2.41; linux-arm64-abi.md §2
pub(crate) const ARM64_BRK_0: u32 = 0xd420_0000;

// ─────────────────────────────────────────────────────────────────────────────
// UserPtRegs — AArch64 general-purpose register set exchanged via NT_PRSTATUS
// ─────────────────────────────────────────────────────────────────────────────

/// AArch64 general-purpose register set.
///
/// Layout mirrors `struct user_pt_regs` at
/// `bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.h:49-54`:
///
/// ```c
/// struct user_pt_regs {
///   __u64 regs[31];   // x0..x30
///   __u64 sp;
///   __u64 pc;
///   __u64 pstate;
/// };
/// ```
///
/// `regs[8]` is `x8` (AArch64 syscall number register); `regs[0..=5]` carry
/// syscall args 1..6; `regs[30]` is the link register.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// Compile-time tripwire: the NT_PRSTATUS iovec contract demands exactly 272
// bytes (31*8 regs + sp + pc + pstate). On non-arm64 hosts the assertion is
// still sound (size is layout-invariant under `#[repr(C)]`), but we gate it
// to aarch64 per spec §Approach.4 so host `cargo check` on x86_64 dev boxes
// stays green even if future porting changes the primitive sizes.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Wrap the current `errno` as [`Error::PtraceOp`].
///
/// Used by post-attach ptrace, `waitpid`, and `process_vm_*` call sites — the
/// operation-failure catch-all. [`ptrace_seize`] uses
/// [`classify_seize_err`] instead so attach-phase failures surface as
/// [`Error::PtraceAttach`] (with yama classification) rather than
/// [`Error::PtraceOp`].
fn last_ptrace_op_err() -> Error {
    Error::PtraceOp(io::Error::last_os_error())
}

/// Read `TracerPid:` from `/proc/<pid>/status`. Returns `0` when the line is
/// absent, the file is unreadable, or the value is unparseable — i.e. callers
/// should treat any `Ok(0)` as "no concurrent tracer detected" rather than
/// "definitely none". Used by [`classify_seize_err`] to disambiguate `EPERM`
/// from yama vs. an existing tracer holding the tracee.
pub(crate) fn read_tracer_pid(pid: Pid) -> Pid {
    let path = format!("/proc/{pid}/status");
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return 0;
    };
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("TracerPid:") {
            return rest.trim().parse().unwrap_or(0);
        }
    }
    0
}

/// Classify a failed `PTRACE_SEIZE`. Order:
/// 1. `EPERM` + nonzero `TracerPid` → `PtraceTracerBusy` (another module holds
///    the tracee — most actionable diagnostic).
/// 2. `EPERM` + `ptrace_scope >= 1` → `PtraceScope`.
/// 3. Anything else → `PtraceAttach`.
///
/// Called only from `ptrace_seize`.
fn classify_seize_err(pid: Pid) -> Error {
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EPERM) {
        let tracer_pid = read_tracer_pid(pid);
        if tracer_pid != 0 {
            return Error::PtraceTracerBusy { tracer_pid };
        }
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            let trimmed = s.trim();
            match trimmed.bytes().next() {
                Some(b'0') => {}
                Some(_) => return Error::PtraceScope,
                None => {}
            }
        }
    }
    Error::PtraceAttach(err)
}

// ─────────────────────────────────────────────────────────────────────────────
// ptrace primitives
// ─────────────────────────────────────────────────────────────────────────────

/// `PTRACE_SEIZE` — attach without stopping the tracee. Sets
/// `PTRACE_O_TRACESYSGOOD` atomically via the `data` argument so subsequent
/// syscall-stops (status `0x85`) are distinguishable from brk-traps
/// (status `0x05`, event 0) — required for multi-threaded tracees per
/// linux-arm64-abi.md §6 step 1.
///
/// On `EPERM` the wrapper reads `/proc/sys/kernel/yama/ptrace_scope`; any
/// restrictive value (>= 1) is surfaced as [`Error::PtraceScope`] so the CLI
/// can print the remediation. Other failures map to
/// [`Error::PtraceAttach`] with the raw `errno` preserved.
pub fn ptrace_seize(pid: Pid) -> Result<()> {
    // SAFETY: `libc::ptrace` is a well-defined FFI. `addr` is NULL per the
    // PTRACE_SEIZE contract; `data` carries the options bitmask (treated as
    // an integer-in-pointer by ptrace, standard pattern). The call has no
    // tracer-side memory effect — failure only sets `errno`.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_SEIZE as _,
            pid,
            std::ptr::null_mut::<c_void>(),
            PTRACE_O_TRACESYSGOOD as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(classify_seize_err(pid));
    }
    Ok(())
}

/// `PTRACE_INTERRUPT` — request a synchronous stop on a seized tracee.
///
/// Must be paired with a subsequent [`wait_stop`] call.
pub fn ptrace_interrupt(pid: Pid) -> Result<()> {
    // SAFETY: `libc::ptrace` FFI; no memory exchanged (addr/data NULL).
    let rc = unsafe {
        libc::ptrace(
            PTRACE_INTERRUPT as _,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    Ok(())
}

/// Verdict for one decoded `waitpid` status, produced by [`classify_stop`].
///
/// Ported from ReZygisk's `wait_for_trace` branch ladder
/// (`loader/src/ptracer/utils.c:1043-1082`): a benign intermediate stop is
/// re-`CONT`ed and the loop continues; the awaited stop is accepted; anything
/// else is the strict `PtraceUnexpectedStatus` fault.
enum StopVerdict {
    /// A benign intermediate stop (init busy → `SIGCHLD` group-stop). Mirrors
    /// the `WIFSTOPPED && WSTOPSIG == SIGCHLD` arm at utils.c:1058 — re-`CONT`
    /// the tracee and wait again. NOT the awaited event, so it is never
    /// returned to the caller as success.
    ContAndRetry,
    /// The awaited ptrace-stop: `WIFSTOPPED && WSTOPSIG == SIGTRAP &&
    /// event == expected_event`. The original strict acceptance, preserved
    /// verbatim for the final stop.
    Awaited,
    /// A genuinely-unexpected status. Surfaced as
    /// [`Error::PtraceUnexpectedStatus`] — kept strict so the seal spine still
    /// detects real faults; deliberately NOT a catch-all.
    Unexpected,
}

/// Pure status classifier — no syscalls — so the [`wait_stop`] loop is unit
/// testable on any host by injecting raw `waitpid` statuses.
///
/// Port fidelity (ReZygisk `wait_for_trace`, utils.c:1043-1082):
/// - `SIGCHLD` ptrace-stop → [`StopVerdict::ContAndRetry`] (utils.c:1058-1063).
/// - the awaited `SIGTRAP` + `event == expected_event` → [`StopVerdict::Awaited`].
/// - everything else → [`StopVerdict::Unexpected`] (strict, no catch-all).
///
/// The reference's `PTRACE_EVENT_SECCOMP` skip-syscall arm (utils.c:1064-1069)
/// is deliberately not ported: this engine never sets `PTRACE_O_TRACESECCOMP`,
/// so a seccomp-event stop cannot arise on our tracee.
fn classify_stop(status: i32, expected_event: u32) -> StopVerdict {
    let is_stopped = libc::WIFSTOPPED(status);
    let sig = libc::WSTOPSIG(status);
    let event = ((status >> 16) & 0xffff) as u32;
    if is_stopped && sig == libc::SIGCHLD {
        return StopVerdict::ContAndRetry;
    }
    if is_stopped && sig == libc::SIGTRAP && event == expected_event {
        return StopVerdict::Awaited;
    }
    StopVerdict::Unexpected
}

/// `waitpid(pid, &status, __WALL)` — block until the awaited ptrace-stop
/// arrives, tolerating benign intermediate stops, and verify it matches the
/// caller's expected stop kind.
///
/// Ported from ReZygisk's `wait_for_trace` (`loader/src/ptracer/utils.c:1043`):
/// loops over `waitpid`, retrying on `EINTR` and re-`CONT`ing benign `SIGCHLD`
/// group-stops (raised when init forks while traced) before waiting again.
/// The loop terminates by genuine progress: every benign stop consumed via
/// `PTRACE_CONT` advances the tracee, so the kernel does not redeliver it, and
/// any non-benign status returns immediately (awaited stop or fault).
///
/// The FINAL awaited stop keeps the original strict check: `WIFSTOPPED(status)
/// && WSTOPSIG(status) == SIGTRAP` AND the upper event byte equals
/// `expected_event`. Callers pass [`PTRACE_EVENT_STOP`] (128) to consume the
/// initial SEIZE+INTERRUPT group-stop, or `0` to consume a brk-trap
/// (post-`svc`). Any mismatch surfaces as [`Error::PtraceUnexpectedStatus`]
/// carrying the raw status bits for diagnosis. `waitpid` syscall failure maps
/// to [`Error::PtraceOp`] via [`last_ptrace_op_err`].
pub fn wait_stop(pid: Pid, expected_event: u32) -> Result<i32> {
    loop {
        let mut status: i32 = 0;
        // SAFETY: `status` lives on the stack for the duration of the call;
        // `waitpid` writes through the pointer only while blocked, returns
        // pid on success or -1 on error (captured via errno).
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if rc == -1 {
            // Port of utils.c:1047 — a signal interrupted the wait; retry.
            // SAFETY: reading the thread-local errno slot.
            if unsafe { *errno_ptr() } == libc::EINTR {
                continue;
            }
            return Err(last_ptrace_op_err());
        }
        match classify_stop(status, expected_event) {
            StopVerdict::ContAndRetry => {
                // Port of utils.c:1061 — resume the tracee past the benign
                // stop, then loop back into `waitpid`.
                // SAFETY: `libc::ptrace` FFI; `addr`/`data` are NULL per the
                // PTRACE_CONT contract. The tracee is ptrace-stopped (we just
                // observed a stop status for it), so a CONT is legal.
                let cont = unsafe {
                    libc::ptrace(
                        PTRACE_CONT as _,
                        pid,
                        std::ptr::null_mut::<c_void>(),
                        std::ptr::null_mut::<c_void>(),
                    )
                };
                if cont == -1 {
                    return Err(last_ptrace_op_err());
                }
            }
            StopVerdict::Awaited => return Ok(status),
            StopVerdict::Unexpected => return Err(Error::PtraceUnexpectedStatus(status)),
        }
    }
}

/// `PTRACE_GETREGSET` with `NT_PRSTATUS` — snapshot AArch64 GP registers.
///
/// Uses a 272-byte iovec buffer per the NT_PRSTATUS contract
/// (linux-arm64-abi.md §5).
pub fn getregset(pid: Pid) -> Result<UserPtRegs> {
    let mut regs = UserPtRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut UserPtRegs as *mut c_void,
        iov_len: core::mem::size_of::<UserPtRegs>(),
    };
    // SAFETY: `iov.iov_base` points at a stack-allocated `UserPtRegs`
    // (272 bytes, matches `iov_len`); the kernel writes ≤272 bytes into
    // it. `&mut iov` outlives the syscall. No aliasing: `regs` is not
    // otherwise borrowed.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_GETREGSET as _,
            pid,
            NT_PRSTATUS as *mut c_void,
            &mut iov as *mut iovec as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    Ok(regs)
}

/// `PTRACE_SETREGSET` with `NT_PRSTATUS` — write AArch64 GP registers.
pub fn setregset(pid: Pid, regs: &UserPtRegs) -> Result<()> {
    let mut iov = iovec {
        // Kernel only reads through this pointer; casting `*const` to
        // `*mut c_void` is the standard pattern (iovec lacks a const form).
        iov_base: regs as *const UserPtRegs as *mut c_void,
        iov_len: core::mem::size_of::<UserPtRegs>(),
    };
    // SAFETY: `iov.iov_base` points at caller-owned `UserPtRegs` (272 bytes
    // matching `iov_len`); the kernel only reads through it on SETREGSET.
    // `&mut iov` lives for the duration of the syscall.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_SETREGSET as _,
            pid,
            NT_PRSTATUS as *mut c_void,
            &mut iov as *mut iovec as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    Ok(())
}

/// `PTRACE_DETACH` — release the tracee and resume it.
pub fn ptrace_detach(pid: Pid) -> Result<()> {
    // SAFETY: `libc::ptrace` FFI; no memory exchanged (addr/data NULL).
    let rc = unsafe {
        libc::ptrace(
            PTRACE_DETACH as _,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Thread-group stop — T15 / Defect B (freeze every init thread before any poke)
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound on re-scan passes before a thread group is declared
/// non-convergent. Init carries a small, near-static thread count, so a real
/// group settles in one or two passes; eight passes is generous head-room that
/// still bounds liveness against a pathologically thread-churning target.
const MAX_GROUP_SCAN_PASSES: u32 = 8;

/// True when `err` means the targeted thread is already gone (it exited inside
/// the attach/stop/detach window) rather than a genuine ptrace fault. Covers
/// `ESRCH` from seize/interrupt/detach and a thread-exit wait status surfaced by
/// [`wait_stop`] as [`Error::PtraceUnexpectedStatus`]. Per-tid `ESRCH` tolerance
/// (T15): such a tid is skipped, never a hard error.
fn is_thread_gone(err: &Error) -> bool {
    match err {
        Error::PtraceAttach(e) | Error::PtraceOp(e) => e.raw_os_error() == Some(libc::ESRCH),
        Error::PtraceUnexpectedStatus(status) => {
            libc::WIFEXITED(*status) || libc::WIFSIGNALED(*status)
        }
        _ => false,
    }
}

/// `PTRACE_SEIZE` with bounded retry to ride out transient tracer contention
/// from other modules (Magisk / KSU-style hooks that inject and detach in a
/// tight window). After the final attempt the original error is propagated so
/// [`Error::PtraceTracerBusy`] still reaches the caller with the holder's PID
/// intact. A thread that has already exited (`ESRCH`) is not contention, so it
/// short-circuits without burning the backoff budget.
///
/// Moved here from `arena::RemoteAttach::seize_with_retry` (T15) so every attach
/// primitive lives beside [`ptrace_seize`]; the group-stop loop calls it per
/// tid.
fn seize_with_retry(pid: Pid) -> Result<()> {
    const MAX_ATTEMPTS: u32 = 3;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

    let mut last_err: Option<Error> = None;
    for attempt in 0..MAX_ATTEMPTS {
        match ptrace_seize(pid) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let is_contention = !is_thread_gone(&err)
                    && matches!(err, Error::PtraceTracerBusy { .. } | Error::PtraceAttach(_));
                last_err = Some(err);
                if !is_contention || attempt + 1 == MAX_ATTEMPTS {
                    break;
                }
                std::thread::sleep(BACKOFF);
            }
        }
    }
    Err(last_err.expect("seize_with_retry without an error after the loop"))
}

/// Enumerate every kernel task (thread) id in `pid`'s thread group by reading
/// `/proc/<pid>/task/`. Returned tids are sorted ascending (the leader, `pid`,
/// sorts in naturally). A read failure — the process is gone, or `/proc` is
/// unreadable — propagates as `Error`.
///
/// This is the raw, ptrace-free enumeration step; it runs identically on any
/// Linux host, which is why the host unit test exercises it directly while the
/// live SEIZE path stays `#[cfg(target_arch = "aarch64")]` + `#[ignore]`.
pub(crate) fn enumerate_thread_group(pid: Pid) -> Result<Vec<Pid>> {
    let mut tids = Vec::new();
    for entry in std::fs::read_dir(format!("/proc/{pid}/task"))? {
        let name = entry?.file_name();
        if let Some(tid) = name.to_str().and_then(|s| s.parse::<Pid>().ok()) {
            tids.push(tid);
        }
    }
    tids.sort_unstable();
    Ok(tids)
}

/// Seize+interrupt+wait_stop a single tid. Returns `Ok(true)` once the tid is
/// group-stopped, `Ok(false)` when it exited mid-attach (ESRCH-tolerated: skip),
/// and `Err` on a genuine ptrace fault.
fn seize_one_tid(tid: Pid) -> Result<bool> {
    match seize_with_retry(tid) {
        Ok(()) => {}
        Err(e) if is_thread_gone(&e) => return Ok(false),
        Err(e) => return Err(e),
    }
    // SEIZE took; the kernel auto-detaches on thread death, so a later `ESRCH`
    // needs no explicit detach — just skip the tid.
    if let Err(e) = ptrace_interrupt(tid) {
        return if is_thread_gone(&e) { Ok(false) } else { Err(e) };
    }
    match wait_stop(tid, PTRACE_EVENT_STOP) {
        Ok(_) => Ok(true),
        Err(e) if is_thread_gone(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Re-scan-until-stable driver (T15). Repeatedly `enumerate`s the thread group
/// and `seize`s every tid not yet stopped, until a full pass adds no new tid —
/// the fixpoint — or `max_passes` is exceeded.
///
/// # Why this converges, and why it is race-free in the poke window
///
/// Each pass that stops a tid strictly grows the stopped set, which is bounded
/// by the process's (finite) thread count, so the loop cannot grow forever. A
/// thread that is *group-stopped cannot execute `clone`* — so once a pass adds
/// nothing, every listed thread is stopped and no running thread remains to
/// spawn another. The fixpoint is therefore a *fully* frozen group, and the
/// pokes that run afterwards (and before detach) face no live sibling: the
/// "thread spawned during enumeration" race that defines Defect B is closed.
///
/// # Clone-after-enumeration policy (the residual)
///
/// We deliberately do **not** set `PTRACE_O_TRACECLONE`. ReZygisk sidesteps the
/// multi-thread hazard by injecting only when its target is single-threaded
/// (`monitor.c:694`); init is multi-threaded at patch time, so that prior-art
/// trick does not apply. TRACECLONE would auto-trace new threads but at the cost
/// of threading `PTRACE_EVENT_CLONE` stops and child-SIGSTOP reaping through the
/// carefully-ported [`wait_stop`] ladder — added moving parts on the PID 1 path.
/// Instead we use a *bounded* re-scan: because a frozen group can birth no new
/// thread, the only way to keep seeing fresh tids is a target that out-spawns
/// our scan for `max_passes` consecutive passes. That cannot be poked safely, so
/// we ABORT (return [`Error::PtraceAttach`]) rather than proceed against a
/// partially-frozen init. The residual is thus a refusal, never a half-written
/// poke.
fn rescan_until_stable<E, S>(
    leader: Pid,
    max_passes: u32,
    mut enumerate: E,
    mut seize: S,
) -> Result<Vec<Pid>>
where
    E: FnMut() -> Result<Vec<Pid>>,
    S: FnMut(Pid) -> Result<bool>,
{
    let mut stopped: Vec<Pid> = Vec::new();
    for _ in 0..max_passes {
        let mut added = 0u32;
        for tid in enumerate()? {
            if stopped.contains(&tid) {
                continue;
            }
            if seize(tid)? {
                stopped.push(tid);
                added += 1;
            }
        }
        if added == 0 {
            return Ok(stopped);
        }
    }
    Err(Error::PtraceAttach(io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
            "thread group of {leader} did not stabilize after {max_passes} scan passes; \
             refusing to poke a partially-frozen process"
        ),
    )))
}

/// Freeze `pid`'s **entire** thread group — every `/proc/<pid>/task/` tid, not
/// just the leader — with SEIZE+INTERRUPT+wait_stop, re-scanning until the group
/// is stable so siblings spawned mid-enumeration are caught too. Returns every
/// stopped tid; [`detach_thread_group`] resumes them all. This is the T15 fix
/// for Defect B: the leader-only stop left init's siblings running on other
/// cores through the Tier A remap and the Tier B trampoline pokes.
pub(crate) fn seize_thread_group(pid: Pid) -> Result<Vec<Pid>> {
    rescan_until_stable(
        pid,
        MAX_GROUP_SCAN_PASSES,
        || enumerate_thread_group(pid),
        seize_one_tid,
    )
}

/// `PTRACE_DETACH` (resume) every tid in `tids`, tolerating per-tid `ESRCH` (a
/// thread that exited inside the window is already reaped by the kernel). Every
/// tid is attempted even if one fails, so a single stuck detach never strands
/// the rest still-stopped; the first genuine fault is returned afterwards.
/// Preserves PLAN G2:424-425 ("re-detach all task threads").
pub(crate) fn detach_thread_group(tids: &[Pid]) -> Result<()> {
    let mut first_err: Option<Error> = None;
    for &tid in tids {
        match ptrace_detach(tid) {
            Ok(()) => {}
            Err(e) if is_thread_gone(&e) => {}
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    first_err.map_or(Ok(()), Err)
}

// ─────────────────────────────────────────────────────────────────────────────
// Word-granularity tracee memory IO — PTRACE_PEEKDATA / PTRACE_POKEDATA
// ─────────────────────────────────────────────────────────────────────────────

/// `PTRACE_PEEKDATA` — read one 64-bit word from `addr` in the tracee.
///
/// The ptrace PEEKDATA contract returns -1 both for a valid word of all ones
/// AND for an error; the caller MUST clear `errno` before the call and
/// inspect it afterward, per `man 2 ptrace` ("On error, all these calls
/// return -1, and errno is set appropriately. Since the value returned by a
/// successful PTRACE_PEEK* request may be -1, the caller must clear errno
/// before the call, and check it afterward").
/// Portable handle to the thread-local `errno` slot.
///
/// glibc exposes `__errno_location`; bionic exposes `__errno`. This selects
/// the correct symbol at compile time so the crate builds on both
/// `x86_64-unknown-linux-gnu` (dev/CI) and `aarch64-linux-android` (target).
#[inline]
unsafe fn errno_ptr() -> *mut c_int {
    #[cfg(target_os = "android")]
    {
        libc::__errno()
    }
    #[cfg(not(target_os = "android"))]
    {
        libc::__errno_location()
    }
}

pub fn ptrace_peektext(pid: Pid, addr: u64) -> Result<u64> {
    // SAFETY: The errno reset is scoped to this call; `libc::ptrace` returns
    // a `c_long` which on LP64 AArch64 is 64 bits wide — exactly one word.
    unsafe {
        *errno_ptr() = 0;
    }
    let word = unsafe {
        libc::ptrace(
            PTRACE_PEEKDATA as _,
            pid,
            addr as *mut c_void,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if word == -1 {
        let errno = unsafe { *errno_ptr() };
        if errno != 0 {
            return Err(last_ptrace_op_err());
        }
    }
    Ok(word as u64)
}

/// `PTRACE_POKEDATA` — write a 64-bit `value` to `addr` in the tracee.
///
/// Unlike [`write_remote`] (which uses `process_vm_writev` and respects VMA
/// write bits), POKEDATA goes through the ptrace_access_vm kernel path and
/// bypasses write protection. This is the ONLY safe way to stage an initial
/// `svc ; brk` blob into an `r-xp` mapping (e.g., a libc.text NOP slide) when
/// no RWX scratch page exists yet. Once P02 has used one POKEDATA-staged
/// `mmap` syscall to acquire a fresh `MAP_PRIVATE|MAP_ANON` RWX page,
/// subsequent staging uses `write_remote` on the new page.
pub fn ptrace_poketext(pid: Pid, addr: u64, value: u64) -> Result<()> {
    // SAFETY: `libc::ptrace` FFI. `addr` and `value` are caller-verified
    // integer-in-pointer arguments per the PTRACE_POKEDATA contract. The
    // call writes exactly one `c_long`-sized word; on AArch64 LP64 that is
    // 64 bits so the full `u64` is delivered in one call.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_POKEDATA as _,
            pid,
            addr as *mut c_void,
            value as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-process memory IO — process_vm_{readv,writev} partial-transfer loops
// ─────────────────────────────────────────────────────────────────────────────

/// Loop `process_vm_readv` until the entire `buf` has been filled from
/// `remote_addr` in the tracee, or the kernel returns an error.
///
/// See linux-arm64-abi.md §10: partial transfers are legal, so callers must
/// advance and retry until the requested length is satisfied. A zero-byte
/// return with bytes still outstanding is treated as a stalled transfer and
/// surfaces as [`Error::PtraceOp`].
///
/// # Safety
///
/// Caller guarantees `remote_addr..remote_addr + buf.len()` is readable in
/// the tracee's address space (typically a verified mapping from
/// [`super::maps::parse_maps`]) and that the tracee is ptrace-stopped so the
/// read is not racing concurrent mutation.
pub(crate) unsafe fn read_remote(pid: Pid, remote_addr: u64, buf: &mut [u8]) -> Result<()> {
    let mut transferred: usize = 0;
    while transferred < buf.len() {
        let remaining = buf.len() - transferred;
        let local = iovec {
            iov_base: buf.as_mut_ptr().add(transferred) as *mut c_void,
            iov_len: remaining,
        };
        let remote = iovec {
            iov_base: (remote_addr + transferred as u64) as *mut c_void,
            iov_len: remaining,
        };
        // SAFETY: `local.iov_base` points at `buf[transferred..]`, which is
        // valid for `remaining` bytes of write. `remote` addresses tracee
        // memory guaranteed readable by the function's safety contract.
        // `flags` must be 0 per the man page; we pass one iovec per side.
        let n = unsafe { process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n == -1 {
            return Err(last_ptrace_op_err());
        }
        if n == 0 {
            return Err(Error::PtraceOp(io::Error::other(format!(
                "process_vm_readv stalled: {transferred}/{} bytes transferred",
                buf.len()
            ))));
        }
        transferred += n as usize;
    }
    Ok(())
}

/// Loop `process_vm_writev` until the entire `buf` has been written to
/// `remote_addr` in the tracee, or the kernel returns an error.
///
/// Mirror of [`read_remote`]; same partial-transfer handling per
/// linux-arm64-abi.md §10.
///
/// # Safety
///
/// Caller guarantees `remote_addr..remote_addr + buf.len()` covers a VMA in
/// the tracee with write permission (per `man 2 process_vm_writev`: the call
/// respects VMA write bits and returns `EFAULT` on non-writable pages; it
/// does NOT bypass page-table protection like `PTRACE_POKEDATA` or
/// `/proc/<pid>/mem` do). For RX-only targets (e.g. `libc.so` code), callers
/// must either `mprotect` the VMA writable remotely first or use a different
/// transport. Caller also guarantees the tracee is ptrace-stopped so the
/// write is not racing concurrent execution.
pub(crate) unsafe fn write_remote(pid: Pid, remote_addr: u64, buf: &[u8]) -> Result<()> {
    let mut transferred: usize = 0;
    while transferred < buf.len() {
        let remaining = buf.len() - transferred;
        let local = iovec {
            iov_base: buf.as_ptr().add(transferred) as *mut c_void,
            iov_len: remaining,
        };
        let remote = iovec {
            iov_base: (remote_addr + transferred as u64) as *mut c_void,
            iov_len: remaining,
        };
        // SAFETY: `local.iov_base` reads from `buf[transferred..]`, valid for
        // `remaining` bytes. `remote` addresses tracee memory guaranteed
        // writable by the function's safety contract. `flags` is 0.
        let n = unsafe { process_vm_writev(pid, &local, 1, &remote, 1, 0) };
        if n == -1 {
            return Err(last_ptrace_op_err());
        }
        if n == 0 {
            return Err(Error::PtraceOp(io::Error::other(format!(
                "process_vm_writev stalled: {transferred}/{} bytes transferred",
                buf.len()
            ))));
        }
        transferred += n as usize;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// remote_syscall — stage `svc #0 ; brk #0` and run one syscall in the tracee
// ─────────────────────────────────────────────────────────────────────────────

/// Execute `syscall_no(args...)` inside `pid` by staging an 8-byte
/// `svc #0 ; brk #0` blob at `scratch_pc`, resuming until the `brk` traps,
/// and reading `x0` back.
///
/// Caller must have already:
/// - invoked [`ptrace_seize`] + [`ptrace_interrupt`] on `pid`;
/// - consumed the initial SEIZE stop via [`wait_stop`];
/// - ensured `scratch_pc` is 4-byte aligned and points inside an executable
///   mapping in the tracee with at least 8 bytes of readable+writable+
///   executable room (typically a bootstrap `mmap` page or a located libc
///   padding region, per linux-arm64-abi.md §8).
///
/// Returns the raw `x0` as `i64`; values in `-4095..=-1` are `-errno`.
///
/// # Safety
///
/// Caller guarantees (a) the tracee is ptrace-stopped at entry, (b)
/// `scratch_pc` satisfies the alignment/mapping contract above, and (c) no
/// other thread in the tracee is racing on those 8 bytes.
pub unsafe fn remote_syscall(
    pid: Pid,
    scratch_pc: u64,
    syscall_no: u64,
    args: [u64; 6],
) -> Result<i64> {
    // Payload: `svc #0 ; brk #0` little-endian. Derived from the two public
    // constants so the encoding cannot drift from the ARM ARM citations.
    let svc_bytes = ARM64_SVC_0.to_le_bytes();
    let brk_bytes = ARM64_BRK_0.to_le_bytes();
    let mut payload = [0u8; 8];
    payload[..4].copy_from_slice(&svc_bytes);
    payload[4..].copy_from_slice(&brk_bytes);

    // (§7 step 2) Save the 8 bytes we are about to clobber.
    let mut saved_bytes = [0u8; 8];
    // SAFETY: forwards caller's `scratch_pc` readability guarantee.
    unsafe { read_remote(pid, scratch_pc, &mut saved_bytes)? };

    // (§7 step 3) Stage the svc+brk blob.
    // SAFETY: forwards caller's `scratch_pc` writability guarantee.
    unsafe { write_remote(pid, scratch_pc, &payload)? };

    // (§7 step 4) Snapshot registers so we can restore on exit.
    let saved_regs = getregset(pid)?;

    // (§7 step 5) Build the work register set: pc=scratch, x8=syscall,
    // x0..x5=args. Leave sp/pstate/lr untouched — kernel uses its own stack.
    let mut work = saved_regs;
    work.pc = scratch_pc;
    work.regs[8] = syscall_no;
    work.regs[0..6].copy_from_slice(&args);

    // (§7 step 6) Install the work regs, then resume.
    setregset(pid, &work)?;

    // SAFETY: `libc::ptrace` FFI. `addr`/`data` are NULL per PTRACE_CONT
    // contract. Tracee is guaranteed ptrace-stopped by the function's own
    // safety contract, so a CONT is legal here.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_CONT as _,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if rc == -1 {
        // Best-effort restore before propagating: libc.text (or whichever
        // scratch VMA the caller picked) must not retain live svc+brk, and
        // the tracee's saved regs must not remain in work-state. Any error
        // here is discarded — the original cause is more informative.
        // SAFETY: forwards caller's `scratch_pc` writability guarantee.
        let _ = unsafe { write_remote(pid, scratch_pc, &saved_bytes) };
        let _ = setregset(pid, &saved_regs);
        return Err(last_ptrace_op_err());
    }

    // (§7 step 7) Wait for the brk trap. `wait_stop` verifies
    // `WIFSTOPPED && WSTOPSIG == SIGTRAP && event == 0` atomically per its
    // contract — group-stops (event=128) and syscall-stops (signal=0x85) are
    // rejected as `Error::PtraceUnexpectedStatus`.
    let wait_result = wait_stop(pid, 0);
    if wait_result.is_err() {
        // SAFETY: forwards caller's `scratch_pc` writability guarantee.
        let _ = unsafe { write_remote(pid, scratch_pc, &saved_bytes) };
        let _ = setregset(pid, &saved_regs);
    }
    wait_result?;

    // (§7 step 8) Read x0 from the post-trap register state.
    let out_result = getregset(pid);
    if out_result.is_err() {
        // SAFETY: forwards caller's `scratch_pc` writability guarantee.
        let _ = unsafe { write_remote(pid, scratch_pc, &saved_bytes) };
        let _ = setregset(pid, &saved_regs);
    }
    let out = out_result?;
    let ret = out.regs[0] as i64;

    // (§7 step 9) Restore in order: regs first (so pc points back at the
    // caller's resume address), then the scratch bytes (so a subsequent
    // `remote_syscall` invocation sees pristine memory to clobber).
    setregset(pid, &saved_regs)?;
    // SAFETY: forwards caller's `scratch_pc` writability guarantee.
    unsafe { write_remote(pid, scratch_pc, &saved_bytes)? };

    Ok(ret)
}

// ─────────────────────────────────────────────────────────────────────────────
// remote_syscall_via_poke — same as remote_syscall, but PEEK/POKEDATA scratch
// ─────────────────────────────────────────────────────────────────────────────

/// Execute `syscall_no(args...)` inside `pid` by staging an 8-byte
/// `svc #0 ; brk #0` blob at `scratch_pc` via [`ptrace_peektext`] /
/// [`ptrace_poketext`] (word-granularity PEEK/POKEDATA) rather than
/// [`read_remote`] / [`write_remote`] (process_vm_readv/writev).
///
/// Rationale: `process_vm_writev` respects VMA write bits and EFAULTs on
/// `r-xp` libc.text; `PTRACE_POKEDATA` bypasses the write bit via the
/// `ptrace_access_vm` kernel path. Use this variant when `scratch_pc` lives
/// inside a libc.text NOP slide (i.e. always, in P02's post-bootstrap flow).
///
/// Behavior and return semantics are otherwise identical to
/// [`remote_syscall`] — caller contract matches verbatim.
///
/// # Safety
///
/// Caller guarantees (a) the tracee is ptrace-stopped at entry, (b)
/// `scratch_pc` is 4-byte aligned and points inside an executable mapping
/// with at least 8 bytes of readable+executable room, (c) no other thread
/// in the tracee is racing on those 8 bytes. Unlike [`remote_syscall`] the
/// scratch VMA does NOT need to be writable: PEEK/POKEDATA bypass VMA
/// write bits, so an `r-xp` libc.text NOP slide is a legal target.
pub(crate) unsafe fn remote_syscall_via_poke(
    pid: Pid,
    scratch_pc: u64,
    syscall_no: u64,
    args: [u64; 6],
) -> Result<i64> {
    // Payload: `svc #0 ; brk #0` little-endian packed into one 64-bit word.
    // Same byte pattern `[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]`
    // as [`remote_syscall`]; construction differs only in transport.
    let svc_brk: u64 = (ARM64_SVC_0 as u64) | ((ARM64_BRK_0 as u64) << 32);

    // Save the 8 bytes we are about to clobber (one PEEKDATA word on LP64).
    let saved_word = ptrace_peektext(pid, scratch_pc)?;

    // Stage the svc+brk blob via POKEDATA — bypasses VMA write bits so the
    // scratch may be an `r-xp` libc.text NOP slide.
    ptrace_poketext(pid, scratch_pc, svc_brk)?;

    // Snapshot registers so we can restore on exit.
    let saved_regs = getregset(pid)?;

    // Build the work register set: pc=scratch, x8=syscall, x0..x5=args.
    // Leave sp/pstate/lr untouched — kernel uses its own stack.
    let mut work = saved_regs;
    work.pc = scratch_pc;
    work.regs[8] = syscall_no;
    work.regs[0..6].copy_from_slice(&args);

    // Install the work regs, then resume.
    setregset(pid, &work)?;

    // SAFETY: `libc::ptrace` FFI. `addr`/`data` are NULL per PTRACE_CONT
    // contract. Tracee is guaranteed ptrace-stopped by the function's own
    // safety contract, so a CONT is legal here.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_CONT as _,
            pid,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>(),
        )
    };
    if rc == -1 {
        // Best-effort restore before propagating: libc.text must not retain
        // live svc+brk at scratch_pc, and the tracee's saved regs must not
        // remain in work-state (pc=scratch_pc, x8=syscall_no). Otherwise
        // RemoteAttach::drop detaches init into a poisoned state and the
        // next thread scheduled at scratch_pc traps on brk #0.
        let _ = ptrace_poketext(pid, scratch_pc, saved_word);
        let _ = setregset(pid, &saved_regs);
        return Err(last_ptrace_op_err());
    }

    // Wait for the brk trap. `wait_stop` verifies
    // `WIFSTOPPED && WSTOPSIG == SIGTRAP && event == 0` atomically.
    let wait_result = wait_stop(pid, 0);
    if wait_result.is_err() {
        let _ = ptrace_poketext(pid, scratch_pc, saved_word);
        let _ = setregset(pid, &saved_regs);
    }
    wait_result?;

    // Read x0 from the post-trap register state.
    let out_result = getregset(pid);
    if out_result.is_err() {
        let _ = ptrace_poketext(pid, scratch_pc, saved_word);
        let _ = setregset(pid, &saved_regs);
    }
    let out = out_result?;
    let ret = out.regs[0] as i64;

    // Restore in order: regs first (so pc points back at the caller's resume
    // address), then the scratch word (so a subsequent
    // `remote_syscall_via_poke` sees pristine memory to clobber).
    setregset(pid, &saved_regs)?;
    ptrace_poketext(pid, scratch_pc, saved_word)?;

    Ok(ret)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test name referenced by P01 checklist as `seal::ptrace::size_assert`.
    /// On aarch64 this reaches the compile-time assertion; on other arches
    /// it verifies the layout is at least internally consistent.
    #[test]
    fn size_assert() {
        assert_eq!(core::mem::size_of::<UserPtRegs>(), 272);
    }

    #[test]
    fn constants_match_canonical_values() {
        assert_eq!(PTRACE_CONT, 7);
        assert_eq!(PTRACE_DETACH, 17);
        assert_eq!(PTRACE_GETREGSET, 0x4204);
        assert_eq!(PTRACE_SETREGSET, 0x4205);
        assert_eq!(PTRACE_SEIZE, 0x4206);
        assert_eq!(PTRACE_INTERRUPT, 0x4207);
        assert_eq!(PTRACE_PEEKDATA, 2);
        assert_eq!(PTRACE_POKEDATA, 5);
        assert_eq!(PTRACE_O_TRACESYSGOOD, 1);
        assert_eq!(PTRACE_EVENT_STOP, 128);
        assert_eq!(NT_PRSTATUS, 1);
        assert_eq!(ARM64_SVC_0, 0xd400_0001);
        assert_eq!(ARM64_BRK_0, 0xd420_0000);
    }

    /// Build a `waitpid` ptrace-stop status: low byte `0x7f` makes
    /// `WIFSTOPPED` true, `WSTOPSIG` is bits 8..16, the ptrace event is
    /// bits 16..32. Matches the encoding `wait_stop` decodes.
    fn stopped_status(sig: i32, event: u32) -> i32 {
        let s = 0x7f | (sig << 8) | ((event as i32) << 16);
        assert!(libc::WIFSTOPPED(s));
        assert_eq!(libc::WSTOPSIG(s), sig);
        s
    }

    /// A benign `SIGCHLD` group-stop is classified as `ContAndRetry`; the
    /// awaited `SIGTRAP` + matching event that follows reaches `Awaited`.
    /// This is the spurious-stop tolerance: an intermediate stop is
    /// re-`CONT`ed, then the expected event still lands.
    #[test]
    fn benign_intermediate_stop_then_reaches_expected_event() {
        let benign = stopped_status(libc::SIGCHLD, 0);
        assert!(
            matches!(classify_stop(benign, PTRACE_EVENT_STOP), StopVerdict::ContAndRetry),
            "benign SIGCHLD stop must be re-CONTed, not accepted or faulted"
        );

        let awaited = stopped_status(libc::SIGTRAP, PTRACE_EVENT_STOP);
        assert!(
            matches!(classify_stop(awaited, PTRACE_EVENT_STOP), StopVerdict::Awaited),
            "the awaited SIGTRAP + matching event must be accepted as the final stop"
        );
    }

    /// Drive the same decision sequence the `wait_stop` loop would: a queue of
    /// statuses with two benign SIGCHLD stops ahead of the awaited brk-trap
    /// (event 0). The loop consumes the benign ones and stops on the awaited
    /// one, proving the intermediate stops do not abort the wait.
    #[test]
    fn loop_consumes_benign_stops_until_expected() {
        let queue = [
            stopped_status(libc::SIGCHLD, 0),
            stopped_status(libc::SIGCHLD, 0),
            stopped_status(libc::SIGTRAP, 0),
        ];
        let mut retried = 0;
        let mut reached = None;
        for status in queue {
            match classify_stop(status, 0) {
                StopVerdict::ContAndRetry => retried += 1,
                StopVerdict::Awaited => {
                    reached = Some(status);
                    break;
                }
                StopVerdict::Unexpected => panic!("unexpected status 0x{status:x} in benign run"),
            }
        }
        assert_eq!(retried, 2, "both benign stops must be re-CONTed");
        assert_eq!(reached, Some(queue[2]), "loop must land on the awaited brk-trap");
    }

    /// The strict final check is intact: a `SIGTRAP` with the WRONG event, and
    /// a non-SIGTRAP/non-SIGCHLD stop, both classify as `Unexpected` so
    /// `wait_stop` returns `PtraceUnexpectedStatus`. The benign tolerance must
    /// not have widened into a catch-all.
    #[test]
    fn genuinely_unexpected_status_stays_strict() {
        // SIGTRAP but event=0 when the caller awaited the group-stop (128).
        let wrong_event = stopped_status(libc::SIGTRAP, 0);
        assert!(
            matches!(classify_stop(wrong_event, PTRACE_EVENT_STOP), StopVerdict::Unexpected),
            "a SIGTRAP with the wrong event must stay PtraceUnexpectedStatus"
        );

        // A stop signal that is neither the awaited SIGTRAP nor benign SIGCHLD.
        let foreign = stopped_status(libc::SIGSEGV, 0);
        assert!(
            matches!(classify_stop(foreign, 0), StopVerdict::Unexpected),
            "a foreign stop signal must stay PtraceUnexpectedStatus"
        );

        // Confirm the error path actually maps to PtraceUnexpectedStatus.
        match classify_stop(wrong_event, PTRACE_EVENT_STOP) {
            StopVerdict::Unexpected => {
                let err = Error::PtraceUnexpectedStatus(wrong_event);
                assert!(matches!(err, Error::PtraceUnexpectedStatus(s) if s == wrong_event));
            }
            _ => unreachable!(),
        }
    }

    /// Fork a child, SEIZE + INTERRUPT it, then PEEK a parent-allocated word
    /// (child inherits the VA via COW), POKE a new value, PEEK back, and
    /// assert the round-trip. Gated behind `#[ignore]` because it requires
    /// `/proc/sys/kernel/yama/ptrace_scope <= 1` and the `aarch64`
    /// target (the POKEDATA word width matches `c_long`, which on LP64
    /// AArch64 is 64 bits — the width our `u64` API contract assumes).
    #[cfg(target_os = "linux")]
    #[cfg(target_arch = "aarch64")]
    #[test]
    #[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]
    fn peek_poke_roundtrip_on_self() {
        /// RAII guard: SIGKILL + reap on drop so the child never outlives
        /// the test even if an assertion panics mid-flow.
        struct ChildGuard(libc::pid_t);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    let mut status: i32 = 0;
                    libc::waitpid(self.0, &mut status, 0);
                }
            }
        }

        // Parent-owned word on the heap, shared with the child via COW on fork.
        let slot: Box<u64> = Box::new(0x1111_2222_3333_4444);
        let slot_addr = Box::into_raw(slot) as u64;

        // SAFETY: `fork` is async-signal-safe; the child branch only calls
        // async-signal-safe syscalls (`pause`) before being reaped.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child: park until the parent SIGKILLs us.
            unsafe { libc::pause() };
            unsafe { libc::_exit(0) };
        }

        let guard = ChildGuard(pid);

        ptrace_seize(pid).expect("seize");
        ptrace_interrupt(pid).expect("interrupt");
        wait_stop(pid, PTRACE_EVENT_STOP).expect("wait_stop");

        let peeked_before = ptrace_peektext(pid, slot_addr).expect("peek before");
        assert_eq!(peeked_before, 0x1111_2222_3333_4444);

        let new_value: u64 = 0xdead_beef_cafe_babe;
        ptrace_poketext(pid, slot_addr, new_value).expect("poke");

        let peeked_after = ptrace_peektext(pid, slot_addr).expect("peek after");
        assert_eq!(peeked_after, new_value);

        ptrace_detach(pid).expect("detach");
        drop(guard);

        // Reclaim the heap word so miri/leak sanitizers stay clean.
        // SAFETY: `slot_addr` came from `Box::into_raw` above; no other owner exists.
        unsafe {
            drop(Box::from_raw(slot_addr as *mut u64));
        }
    }

    // ── T15: thread-group stop (Defect B) ───────────────────────────────────

    #[test]
    fn thread_gone_detects_exit_and_esrch_only() {
        assert!(is_thread_gone(&Error::PtraceAttach(io::Error::from_raw_os_error(
            libc::ESRCH
        ))));
        assert!(is_thread_gone(&Error::PtraceOp(io::Error::from_raw_os_error(
            libc::ESRCH
        ))));
        // WIFEXITED(0) is true (low 7 bits == 0): a clean thread exit status.
        assert!(libc::WIFEXITED(0));
        assert!(is_thread_gone(&Error::PtraceUnexpectedStatus(0)));
        // A real ptrace stop with the wrong event is NOT a thread exit.
        let bad_stop = stopped_status(libc::SIGSEGV, 0);
        assert!(!is_thread_gone(&Error::PtraceUnexpectedStatus(bad_stop)));
        // A non-ESRCH op failure is a genuine fault, not a vanished thread.
        assert!(!is_thread_gone(&Error::PtraceOp(io::Error::from_raw_os_error(
            libc::EIO
        ))));
    }

    #[test]
    fn rescan_until_stable_catches_thread_spawned_mid_scan() {
        // Pass 1 lists {10,11}; tid 12 is born during pass 1 and shows up in
        // pass 2; pass 3 adds nothing → fixpoint. Each live tid is seized once.
        let passes: [&[Pid]; 3] = [&[10, 11], &[10, 11, 12], &[10, 11, 12]];
        let mut call = 0usize;
        let mut seized: Vec<Pid> = Vec::new();
        let stopped = rescan_until_stable(
            1,
            MAX_GROUP_SCAN_PASSES,
            || {
                let snap = passes[call.min(passes.len() - 1)].to_vec();
                call += 1;
                Ok(snap)
            },
            |tid| {
                seized.push(tid);
                Ok(true)
            },
        )
        .expect("a settling group converges to a fixpoint");
        assert_eq!(stopped, vec![10, 11, 12]);
        assert_eq!(seized, vec![10, 11, 12], "each live tid seized exactly once");
    }

    #[test]
    fn rescan_until_stable_tolerates_threads_that_exit_mid_attach() {
        // tid 11 exits the instant we try to seize it (seize → Ok(false)); it
        // must be skipped, never recorded, and the group still converges.
        let passes: [&[Pid]; 2] = [&[10, 11, 12], &[10, 12]];
        let mut call = 0usize;
        let stopped = rescan_until_stable(
            1,
            MAX_GROUP_SCAN_PASSES,
            || {
                let snap = passes[call.min(passes.len() - 1)].to_vec();
                call += 1;
                Ok(snap)
            },
            |tid| Ok(tid != 11),
        )
        .expect("converges despite a thread exiting mid-attach");
        assert_eq!(
            stopped,
            vec![10, 12],
            "the exited tid is never recorded as stopped"
        );
    }

    #[test]
    fn rescan_until_stable_aborts_when_group_never_settles() {
        // Every pass introduces one brand-new tid, so the group never settles →
        // the bounded re-scan refuses (abort); it does not poke an unfrozen
        // process. This is the documented residual of the bounded policy.
        let mut call = 0i32;
        let err = rescan_until_stable(
            1,
            4,
            || {
                call += 1;
                Ok((100..100 + call).collect())
            },
            |_tid| Ok(true),
        )
        .expect_err("a never-settling group must abort, not silently proceed");
        assert!(
            matches!(err, Error::PtraceAttach(_)),
            "non-convergence is surfaced as an attach-phase failure"
        );
    }

    /// Spawn several real worker threads, have each report its kernel tid, then
    /// confirm `enumerate_thread_group` on this process lists the leader and
    /// every worker. Exercises the live `/proc/<pid>/task/` enumerator on any
    /// host (no ptrace), per the T15 acceptance criterion.
    #[cfg(target_os = "linux")]
    #[test]
    fn enumerate_thread_group_lists_leader_and_all_workers() {
        use std::sync::mpsc;
        use std::sync::{Arc, Barrier};

        const WORKERS: usize = 4;
        let gate = Arc::new(Barrier::new(WORKERS + 1));
        let (tx, rx) = mpsc::channel::<Pid>();

        let mut handles = Vec::with_capacity(WORKERS);
        for _ in 0..WORKERS {
            let gate = Arc::clone(&gate);
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                // SAFETY: SYS_gettid takes no args and only reads the caller's
                // kernel tid — always safe.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as Pid;
                tx.send(tid).expect("report tid");
                gate.wait(); // park until the assertions have run
            }));
        }
        drop(tx);

        let worker_tids: Vec<Pid> = (0..WORKERS).map(|_| rx.recv().expect("worker tid")).collect();

        let listed =
            enumerate_thread_group(std::process::id() as Pid).expect("enumerate own task dir");
        // SAFETY: see above — SYS_gettid is argument-free and side-effect-free.
        let leader_tid = unsafe { libc::syscall(libc::SYS_gettid) } as Pid;
        assert!(
            listed.contains(&leader_tid),
            "the calling (leader) thread must be listed"
        );
        for wt in &worker_tids {
            assert!(
                listed.contains(wt),
                "spawned worker tid {wt} must be enumerated"
            );
        }

        gate.wait(); // release the workers
        for h in handles {
            h.join().expect("join worker");
        }
    }
}
