//! x86-64 register layout and syscall-ABI glue for the ptrace facade.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `asm-x86/asm/ptrace.h:34-56` — `struct pt_regs` (x86_64 arm), matching the
//!   `struct user_regs_struct` ordering the NT_PRSTATUS regset exchanges.
//!
//! Syscall ABI (SysV / Linux x86-64): number in `rax`, args in
//! `rdi, rsi, rdx, r10, r8, r9`, return in `rax`. See injectrc
//! `init_injector/ptrace_utils.hpp:25-34` and ReZygisk
//! `loader/src/ptracer/utils.c:936-953`.
//!
//! NOTE (T13 scope): the trampoline encoder in `seal::hook` emits AArch64
//! opcodes only, so the seal stays gated to aarch64 at the `lib.rs` boundary.
//! This module supplies the register glue that lets the crate compile for
//! x86_64; the runtime seal path is not exercised here.

/// `syscall` — x86-64 fast system call, bytes `0f 05`. Packed into the low
/// half of a `u32` (high byte unused) so the facade's `u32`-typed instruction
/// constants stay uniform across arches. source: Intel SDM Vol 2B SYSCALL.
pub const TRAP_INSN: u32 = 0x0000_050f;

/// `int3` — one-byte breakpoint trap, byte `cc`. Delivers SIGTRAP after the
/// syscall returns. source: Intel SDM Vol 2A INT3.
pub const BRK_INSN: u32 = 0x0000_00cc;

/// NT_PRSTATUS iovec byte contract for this arch: 27 × `u64` = 216 bytes,
/// matching `sizeof(struct user_regs_struct)` from the NDK x86_64 sysroot.
pub const NT_PRSTATUS_SIZE: usize = 216;

/// x86-64 general-purpose register set exchanged via NT_PRSTATUS.
///
/// Field order matches `struct user_regs_struct` (`<sys/user.h>`): the kernel
/// fills every field on GETREGSET, so the layout must be exact.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

const _: () = assert!(core::mem::size_of::<UserPtRegs>() == NT_PRSTATUS_SIZE);

/// Stage `regs` to invoke `syscall_no(args...)` at `pc`: rip, rax=number,
/// rdi/rsi/rdx/r10/r8/r9=args. Mirrors the x86_64 arm of ReZygisk's
/// `remote_syscall` reg setup (`loader/src/ptracer/utils.c:936-953`).
#[inline]
pub fn set_syscall_args(regs: &mut UserPtRegs, pc: u64, syscall_no: u64, args: [u64; 6]) {
    regs.rip = pc;
    regs.rax = syscall_no;
    regs.rdi = args[0];
    regs.rsi = args[1];
    regs.rdx = args[2];
    regs.r10 = args[3];
    regs.r8 = args[4];
    regs.r9 = args[5];
}

/// Read the syscall return value (rax) from a post-trap register snapshot.
#[inline]
pub fn get_syscall_return(regs: &UserPtRegs) -> i64 {
    regs.rax as i64
}

/// Point the program counter (`rip`) at `pc` without touching the syscall
/// registers. Used by the trampoline i-cache-sync path, which resumes the
/// tracee at a staged instruction blob and exchanges no syscall arguments.
#[inline]
pub fn set_pc(regs: &mut UserPtRegs, pc: u64) {
    regs.rip = pc;
}
