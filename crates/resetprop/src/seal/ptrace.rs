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

/// `waitpid(pid, &status, __WALL)` — block until a ptrace-stop arrives and
/// verify it matches the caller's expected stop kind.
///
/// Verifies `WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP` AND that the
/// upper event byte equals `expected_event`. Callers pass
/// [`PTRACE_EVENT_STOP`] (128) to consume the initial SEIZE+INTERRUPT
/// group-stop, or `0` to consume a brk-trap (post-`svc`). Any mismatch
/// surfaces as [`Error::PtraceUnexpectedStatus`] carrying the raw status
/// bits for diagnosis. `waitpid` syscall failure maps to
/// [`Error::PtraceOp`] via [`last_ptrace_op_err`].
pub fn wait_stop(pid: Pid, expected_event: u32) -> Result<i32> {
    let mut status: i32 = 0;
    // SAFETY: `status` lives on the stack for the duration of the call;
    // `waitpid` writes through the pointer only while blocked, returns
    // pid on success or -1 on error (captured via errno).
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    if rc == -1 {
        return Err(last_ptrace_op_err());
    }
    let is_stopped = libc::WIFSTOPPED(status);
    let sig = libc::WSTOPSIG(status);
    let event = ((status >> 16) & 0xffff) as u32;
    if !is_stopped || sig != libc::SIGTRAP || event != expected_event {
        return Err(Error::PtraceUnexpectedStatus(status));
    }
    Ok(status)
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
}
