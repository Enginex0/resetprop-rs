//! AArch64 register layout and syscall-ABI glue for the ptrace facade.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `asm-arm64/asm/ptrace.h:49-54` — `struct user_pt_regs`
//!
//! This module is the byte-identical extraction of the original aarch64-only
//! `ptrace.rs` register layout: the `UserPtRegs` struct, the 272-byte
//! NT_PRSTATUS size contract, and the `svc #0 ; brk #0` instruction encodings.
//! The arch-neutral `set_syscall_args` / `get_syscall_return` helpers fold the
//! per-arch `regs[8]` (x8 syscall number) / `regs[0..6]` (x0..x5 args) /
//! `regs[0]` (x0 return) convention behind one interface so the facade in
//! `ptrace.rs` carries no raw index literals.

/// `svc #0` — AArch64 supervisor call, little-endian bytes `01 00 00 d4`.
/// The syscall-trap instruction the `remote_syscall` stager writes into the
/// tracee's scratch slot. source: ARM ARM C6.2.304; linux-arm64-abi.md §2
pub const TRAP_INSN: u32 = 0xd400_0001;

/// `brk #0` — AArch64 software breakpoint (delivers SIGTRAP),
/// little-endian bytes `00 00 20 d4`. Follows `TRAP_INSN` so the tracee traps
/// back to the tracer after the syscall returns.
/// source: ARM ARM C6.2.41; linux-arm64-abi.md §2
pub const BRK_INSN: u32 = 0xd420_0000;

/// NT_PRSTATUS iovec byte contract for this arch: `31*8` GP regs + sp + pc +
/// pstate = 272 bytes. Exposed so the facade's compile-time tripwire and any
/// caller staging an iovec share one source of truth.
pub const NT_PRSTATUS_SIZE: usize = 272;

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
// bytes (31*8 regs + sp + pc + pstate). The size is layout-invariant under
// `#[repr(C)]`, so the assertion is sound on any host that compiles this
// module in (only aarch64 selects it as the active facade arch).
const _: () = assert!(core::mem::size_of::<UserPtRegs>() == NT_PRSTATUS_SIZE);

/// Stage `regs` to invoke `syscall_no(args...)` at `pc`: pc, x8=syscall number,
/// x0..x5=args. sp/pstate/lr are left untouched — the kernel uses its own
/// stack across the `svc`. Mirrors the aarch64 arm of ReZygisk's
/// `remote_syscall` reg setup (`loader/src/ptracer/utils.c:905-916`).
#[inline]
pub fn set_syscall_args(regs: &mut UserPtRegs, pc: u64, syscall_no: u64, args: [u64; 6]) {
    regs.pc = pc;
    regs.regs[8] = syscall_no;
    regs.regs[0..6].copy_from_slice(&args);
}

/// Read the syscall return value (x0) from a post-trap register snapshot.
#[inline]
pub fn get_syscall_return(regs: &UserPtRegs) -> i64 {
    regs.regs[0] as i64
}

/// Read the syscall number (`x8`) at a syscall-entry stop. `x8` is preserved
/// across the syscall, so it is also valid at the exit stop.
#[inline]
pub fn syscall_nr(regs: &UserPtRegs) -> u64 {
    regs.regs[8]
}

/// Read syscall argument `n` (`0..6` → `x0..x5`) at a syscall-entry stop.
#[inline]
pub fn nth_syscall_arg(regs: &UserPtRegs, n: usize) -> u64 {
    match n {
        0..=5 => regs.regs[n],
        _ => panic!("syscall arg index {n} out of range (0..6)"),
    }
}

/// Point the program counter (`pc`) at `pc` without touching the syscall
/// registers. Used by the trampoline i-cache-sync path, which resumes the
/// tracee at a staged instruction blob and exchanges no syscall arguments.
#[inline]
pub fn set_pc(regs: &mut UserPtRegs, pc: u64) {
    regs.pc = pc;
}
