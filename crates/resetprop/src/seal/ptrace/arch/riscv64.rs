//! RISC-V 64 register layout and syscall-ABI glue for the ptrace facade —
//! **deferred stub**.
//!
//! The register layout below is the verified NT_PRSTATUS contract; the runtime
//! seal path (gadget staging, Tier A/B) is NOT ported for riscv64. riscv64 is
//! not in the T13 build gate (`aarch64`, `x86_64`, `armv7`, `i686`) and the
//! seal stays gated to aarch64 at the `lib.rs` boundary, so this module exists
//! to keep the facade's `cfg` dispatch total, not to drive a live tracee.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `asm-riscv/asm/ptrace.h:14-47` — `struct user_regs_struct` (32 named
//!   XLEN registers: pc, ra, sp, gp, tp, t0..t6, s0..s11, a0..a7).
//!
//! Syscall ABI (Linux riscv): number in `a7`, args in `a0..a5`, return in `a0`.

/// `ecall` — RISC-V environment call (syscall trap), little-endian word
/// `73 00 00 00`. source: RISC-V Unprivileged ISA, ECALL.
pub const TRAP_INSN: u32 = 0x0000_0073;

/// `ebreak` — RISC-V breakpoint trap, little-endian word `73 00 10 00`.
/// source: RISC-V Unprivileged ISA, EBREAK.
pub const BRK_INSN: u32 = 0x0010_0073;

/// NT_PRSTATUS iovec byte contract for this arch: 32 × `u64` = 256 bytes,
/// matching `sizeof(struct user_regs_struct)` from `asm-riscv/asm/ptrace.h`.
pub const NT_PRSTATUS_SIZE: usize = 256;

/// RISC-V 64 general-purpose register set exchanged via NT_PRSTATUS.
///
/// Field order matches `struct user_regs_struct`: `pc` first, then `ra`, `sp`,
/// `gp`, `tp`, the temporaries and saved registers, and the argument registers
/// `a0..a7`. The kernel fills all 32 on GETREGSET, so the layout must be exact.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub pc: u64,
    pub ra: u64,
    pub sp: u64,
    pub gp: u64,
    pub tp: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub s0: u64,
    pub s1: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
}

const _: () = assert!(core::mem::size_of::<UserPtRegs>() == NT_PRSTATUS_SIZE);

/// Stage `regs` to invoke `syscall_no(args...)` at `pc`: pc, a7=number,
/// a0..a5=args. Provided for facade totality; the riscv64 runtime seal path is
/// deferred (see module note), so this is not exercised against a live tracee.
#[inline]
pub fn set_syscall_args(regs: &mut UserPtRegs, pc: u64, syscall_no: u64, args: [u64; 6]) {
    regs.pc = pc;
    regs.a7 = syscall_no;
    regs.a0 = args[0];
    regs.a1 = args[1];
    regs.a2 = args[2];
    regs.a3 = args[3];
    regs.a4 = args[4];
    regs.a5 = args[5];
}

/// Read the syscall return value (a0) from a post-trap register snapshot.
#[inline]
pub fn get_syscall_return(regs: &UserPtRegs) -> i64 {
    regs.a0 as i64
}

/// Read the syscall number (`a7`) at a syscall-entry stop. Provided for facade
/// totality; the riscv64 runtime path is deferred (see module note).
#[inline]
pub fn syscall_nr(regs: &UserPtRegs) -> u64 {
    regs.a7
}

/// Read syscall argument `n` (`0..6` → `a0..a5`) at a syscall-entry stop.
#[inline]
pub fn nth_syscall_arg(regs: &UserPtRegs, n: usize) -> u64 {
    match n {
        0 => regs.a0,
        1 => regs.a1,
        2 => regs.a2,
        3 => regs.a3,
        4 => regs.a4,
        5 => regs.a5,
        _ => panic!("syscall arg index {n} out of range (0..6)"),
    }
}

/// Point the program counter (`pc`) at `pc` without touching the syscall
/// registers. Provided for facade totality; the riscv64 runtime seal path is
/// deferred (see module note), so this is not exercised against a live tracee.
#[inline]
pub fn set_pc(regs: &mut UserPtRegs, pc: u64) {
    regs.pc = pc;
}
