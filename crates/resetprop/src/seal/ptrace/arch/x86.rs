//! x86 (i386) register layout and syscall-ABI glue for the ptrace facade.
//!
//! Sources (verified verbatim against AOSP `bionic/libc/kernel/uapi/`):
//! - `asm-x86/asm/ptrace.h:14-32` — `struct pt_regs` (i386 arm), matching the
//!   `struct user_regs_struct` ordering the NT_PRSTATUS regset exchanges.
//!
//! Syscall ABI (Linux i386): number in `eax`, args in
//! `ebx, ecx, edx, esi, edi, ebp`, return in `eax`. See injectrc
//! `init_injector/ptrace_utils.hpp:35-42` and ReZygisk
//! `loader/src/ptracer/utils.c:954-971`.
//!
//! NOTE (T13 scope): seal stays gated to aarch64 at the `lib.rs` boundary; this
//! module supplies only the register glue that lets the crate compile for i686.

/// `int $0x80` — i386 syscall trap, bytes `cd 80`, packed into the low half of
/// a `u32` (high bytes unused) to keep the facade's instruction constants
/// `u32`-typed across arches. source: Intel SDM Vol 2A INT n.
pub const TRAP_INSN: u32 = 0x0000_80cd;

/// `int3` — one-byte breakpoint trap, byte `cc`. source: Intel SDM Vol 2A INT3.
pub const BRK_INSN: u32 = 0x0000_00cc;

/// NT_PRSTATUS iovec byte contract for this arch: 17 × `u32` = 68 bytes,
/// matching `sizeof(struct user_regs_struct)` from the NDK i686 sysroot.
pub const NT_PRSTATUS_SIZE: usize = 68;

/// i386 general-purpose register set exchanged via NT_PRSTATUS.
///
/// Field order matches `struct user_regs_struct` (`<sys/user.h>`). Every field
/// is a 32-bit kernel `long`; the NT_PRSTATUS regset is filled in full.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xds: u32,
    pub xes: u32,
    pub xfs: u32,
    pub xgs: u32,
    pub orig_eax: u32,
    pub eip: u32,
    pub xcs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub xss: u32,
}

const _: () = assert!(core::mem::size_of::<UserPtRegs>() == NT_PRSTATUS_SIZE);

/// Stage `regs` to invoke `syscall_no(args...)` at `pc`: eip, eax=number,
/// ebx/ecx/edx/esi/edi/ebp=args. Args are truncated to the 32-bit register
/// width. Mirrors the i386 arm of ReZygisk's `remote_syscall` reg setup
/// (`loader/src/ptracer/utils.c:954-971`).
#[inline]
pub fn set_syscall_args(regs: &mut UserPtRegs, pc: u64, syscall_no: u64, args: [u64; 6]) {
    regs.eip = pc as u32;
    regs.eax = syscall_no as u32;
    regs.ebx = args[0] as u32;
    regs.ecx = args[1] as u32;
    regs.edx = args[2] as u32;
    regs.esi = args[3] as u32;
    regs.edi = args[4] as u32;
    regs.ebp = args[5] as u32;
}

/// Read the syscall return value (eax) from a post-trap register snapshot,
/// sign-extended to `i64` so `-errno` values are preserved.
#[inline]
pub fn get_syscall_return(regs: &UserPtRegs) -> i64 {
    regs.eax as i32 as i64
}

/// Point the program counter (`eip`) at `pc` (truncated to the 32-bit
/// register width) without touching the syscall registers. Used by the
/// trampoline i-cache-sync path, which resumes the tracee at a staged
/// instruction blob and exchanges no syscall arguments.
#[inline]
pub fn set_pc(regs: &mut UserPtRegs, pc: u64) {
    regs.eip = pc as u32;
}
