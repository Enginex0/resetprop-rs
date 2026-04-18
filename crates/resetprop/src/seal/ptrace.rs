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

use libc::{c_int, c_void, iovec};

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

/// `NT_PRSTATUS` — note type selecting general-purpose regs for REGSET ops.
/// source: linux/elf.h:301
pub const NT_PRSTATUS: c_int = 1;

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 instruction encodings — used by P01 T4 remote_syscall stager
// ─────────────────────────────────────────────────────────────────────────────

/// `svc #0` — AArch64 supervisor call, little-endian bytes `01 00 00 d4`.
/// source: ARM ARM C6.2.304; linux-arm64-abi.md §2
pub const ARM64_SVC_0: u32 = 0xd400_0001;

/// `brk #0` — AArch64 software breakpoint (delivers SIGTRAP),
/// little-endian bytes `00 00 20 d4`.
/// source: ARM ARM C6.2.41; linux-arm64-abi.md §2
pub const ARM64_BRK_0: u32 = 0xd420_0000;

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 syscall numbers (asm-generic/unistd.h)
// ─────────────────────────────────────────────────────────────────────────────

/// `__NR_getpid` — AArch64 syscall number for `getpid()`.
/// source: asm-generic/unistd.h:461 (`__NR_getpid`)
pub const NR_GETPID: u64 = 172;

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

/// Wrap the current `errno` as [`Error::PtraceAttach`].
///
/// Used by every wrapper except `ptrace_seize`, which additionally classifies
/// `EPERM` against `/proc/sys/kernel/yama/ptrace_scope`.
fn last_ptrace_err() -> Error {
    Error::PtraceAttach(io::Error::last_os_error())
}

/// Classify a failed `PTRACE_SEIZE` (`ptrace_scope >= 1` → `PtraceScope`,
/// else → `PtraceAttach`). Called only from `ptrace_seize`.
fn classify_seize_err() -> Error {
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EPERM) {
        // Yama may be the gate. Read the scope file; if it indicates any
        // restriction (>= 1), surface PtraceScope so the CLI can suggest
        // `echo 0 > /proc/sys/kernel/yama/ptrace_scope`. Otherwise the EPERM
        // is likely SELinux / uid-mismatch and stays an attach failure.
        if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
            let trimmed = s.trim();
            match trimmed.bytes().next() {
                Some(b'0') => {} // scope==0: fall through to PtraceAttach
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

/// `PTRACE_SEIZE` — attach without stopping the tracee.
///
/// On `EPERM` the wrapper reads `/proc/sys/kernel/yama/ptrace_scope`; any
/// restrictive value (>= 1) is surfaced as [`Error::PtraceScope`] so the CLI
/// can print the remediation. Other failures map to
/// [`Error::PtraceAttach`] with the raw `errno` preserved.
pub fn ptrace_seize(pid: Pid) -> Result<()> {
    // SAFETY: `libc::ptrace` is a well-defined FFI. `addr`/`data` are NULL
    // per the PTRACE_SEIZE contract; the call has no tracer-side memory
    // effect — failure only sets `errno` which we read immediately.
    let rc =
        unsafe { libc::ptrace(PTRACE_SEIZE as _, pid, 0 as *mut c_void, 0 as *mut c_void) };
    if rc == -1 {
        return Err(classify_seize_err());
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
            0 as *mut c_void,
            0 as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(last_ptrace_err());
    }
    Ok(())
}

/// `waitpid(pid, &status, __WALL)` — block until a ptrace-stop arrives.
///
/// Verifies `WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP` and returns
/// the raw status word on success; unexpected stop kinds surface as
/// [`Error::PtraceAttach`] wrapping an `io::Error` that carries the raw
/// status value for debugging.
pub fn wait_stop(pid: Pid) -> Result<i32> {
    let mut status: i32 = 0;
    // SAFETY: `status` lives on the stack for the duration of the call;
    // `waitpid` writes through the pointer only while blocked, returns
    // pid on success or -1 on error (captured via errno).
    let rc = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
    if rc == -1 {
        return Err(last_ptrace_err());
    }
    let is_stopped = libc::WIFSTOPPED(status);
    let sig = libc::WSTOPSIG(status);
    if !is_stopped || sig != libc::SIGTRAP {
        return Err(Error::PtraceAttach(io::Error::new(
            io::ErrorKind::Other,
            format!("unexpected wait status: 0x{status:x}"),
        )));
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
        return Err(last_ptrace_err());
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
        return Err(last_ptrace_err());
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
            0 as *mut c_void,
            0 as *mut c_void,
        )
    };
    if rc == -1 {
        return Err(last_ptrace_err());
    }
    Ok(())
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
        assert_eq!(NT_PRSTATUS, 1);
        assert_eq!(ARM64_SVC_0, 0xd400_0001);
        assert_eq!(ARM64_BRK_0, 0xd420_0000);
        assert_eq!(NR_GETPID, 172);
    }
}
