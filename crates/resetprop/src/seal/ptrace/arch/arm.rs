//! 32-bit ARM (AArch32) register layout and syscall-ABI glue for the ptrace
//! facade.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `asm-arm/asm/ptrace.h:69-89` — `struct pt_regs { long uregs[18]; }` with
//!   the `ARM_*` index macros (`uregs[15]` = pc, `uregs[7]` = r7 syscall nr,
//!   `uregs[0]` = r0).
//!
//! Syscall ABI (Linux OABI/EABI): number in `r7`, args in `r0..r5`, return in
//! `r0`. See injectrc `init_injector/ptrace_utils.hpp:51-64` and ReZygisk
//! `loader/src/ptracer/utils.c:917-935`.
//!
//! NOTE (T13 scope): seal stays gated to aarch64 at the `lib.rs` boundary; this
//! module supplies only the register glue that lets the crate compile for
//! armv7. Thumb-mode gadget handling (the `CPSR_T` bit) is part of the deferred
//! runtime port, not this register-layout extraction.

/// `svc #0` — AArch32 supervisor call (ARM encoding), bytes `00 00 00 ef`.
/// source: ARM ARM A8.8.361.
pub const TRAP_INSN: u32 = 0xef00_0000;

/// `bkpt #0` — AArch32 software breakpoint (ARM encoding), bytes `70 00 20 e1`.
/// source: ARM ARM A8.8.24.
pub const BRK_INSN: u32 = 0xe120_0070;

/// NT_PRSTATUS iovec byte contract for this arch: 18 × `u32` = 72 bytes,
/// matching `sizeof(struct user_regs)` from the NDK arm sysroot.
pub const NT_PRSTATUS_SIZE: usize = 72;

/// AArch32 general-purpose register set exchanged via NT_PRSTATUS.
///
/// Mirrors `struct pt_regs { long uregs[18]; }`: `uregs[0..=12]` are r0..r12,
/// `uregs[13]` sp, `uregs[14]` lr, `uregs[15]` pc, `uregs[16]` cpsr,
/// `uregs[17]` orig_r0.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub uregs: [u32; 18],
}

const _: () = assert!(core::mem::size_of::<UserPtRegs>() == NT_PRSTATUS_SIZE);

/// Stage `regs` to invoke `syscall_no(args...)` at `pc`: pc=uregs[15],
/// r7=uregs[7]=number, r0..r5=uregs[0..6]=args. Args are truncated to the
/// 32-bit register width. Mirrors the arm arm of ReZygisk's `remote_syscall`
/// reg setup (`loader/src/ptracer/utils.c:917-926`); Thumb-mode pc handling is
/// deferred with the rest of the armv7 runtime port.
#[inline]
pub fn set_syscall_args(regs: &mut UserPtRegs, pc: u64, syscall_no: u64, args: [u64; 6]) {
    regs.uregs[15] = pc as u32;
    regs.uregs[7] = syscall_no as u32;
    for (i, arg) in args.iter().enumerate() {
        regs.uregs[i] = *arg as u32;
    }
}

/// Read the syscall return value (r0) from a post-trap register snapshot,
/// sign-extended to `i64` so `-errno` values are preserved.
#[inline]
pub fn get_syscall_return(regs: &UserPtRegs) -> i64 {
    regs.uregs[0] as i32 as i64
}

/// Read the syscall number (`r7` = `uregs[7]`) at a syscall-entry stop.
#[inline]
pub fn syscall_nr(regs: &UserPtRegs) -> u64 {
    regs.uregs[7] as u64
}

/// Read syscall argument `n` (`0..6` → `r0..r5` = `uregs[0..6]`) at a
/// syscall-entry stop.
#[inline]
pub fn nth_syscall_arg(regs: &UserPtRegs, n: usize) -> u64 {
    match n {
        0..=5 => regs.uregs[n] as u64,
        _ => panic!("syscall arg index {n} out of range (0..6)"),
    }
}

/// Point the program counter (`uregs[15]`) at `pc` (truncated to the 32-bit
/// register width) without touching the syscall registers. Used by the
/// trampoline i-cache-sync path, which resumes the tracee at a staged
/// instruction blob and exchanges no syscall arguments.
#[inline]
pub fn set_pc(regs: &mut UserPtRegs, pc: u64) {
    regs.uregs[15] = pc as u32;
}
