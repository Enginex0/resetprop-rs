//! Per-arch encoding smoke test for the x86 (i386) ptrace facade.
//!
//! Sibling of `ptrace_core_smoke.rs` (the aarch64 live SEIZE round-trip).
//! Where that file forks a tracee and round-trips `getpid()`, this file
//! asserts the *static* arch contract the `remote_syscall` stager depends on:
//! the syscall-trap / breakpoint instruction encodings, the NT_PRSTATUS regset
//! byte size, and the Linux i386 syscall-ABI register wiring. These are
//! compile-time-constant assertions plus one pure register-staging round-trip,
//! so the test needs no ptrace, no fork, and no `#[ignore]`.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "x86")]`. The constants under test
//! (`resetprop::seal::ptrace::{TRAP_INSN, BRK_INSN, NT_PRSTATUS_SIZE,
//! UserPtRegs, set_syscall_args, get_syscall_return}`) are re-exported from the
//! `cfg`-selected active arch module, so they hold the i386 values only when
//! the crate is built for x86. On any other host this file compiles to an empty
//! test binary, reporting `0 passed; 0 failed; 0 ignored`.
//!
//! Encoding sources (mirrored from
//! `crates/resetprop/src/seal/ptrace/arch/x86.rs`, grounded against injectrc
//! `init_injector/ptrace_utils.hpp:35-42` REG_* macros):
//!   - `int $0x80` (`cd 80`) → TRAP_INSN == 0x0000_80cd  (Intel SDM Vol 2A)
//!   - `int3`      (`cc`)    → BRK_INSN  == 0x0000_00cc  (Intel SDM Vol 2A)
//!   - regset = sizeof(struct user_regs_struct) == 68 bytes
//!
//! Runner invocation:
//!   cargo test -p resetprop --target i686-linux-android \
//!       --test ptrace_core_smoke_x86

#![cfg(target_arch = "x86")]

use resetprop::seal::ptrace::{
    get_syscall_return, set_syscall_args, UserPtRegs, BRK_INSN, NT_PRSTATUS_SIZE, TRAP_INSN,
};

/// The i386 trap/breakpoint encodings the gadget stages: `int $0x80` (`cd 80`)
/// then `int3` (`cc`). Pinned little-endian into the low half of the `u32`
/// instruction constants per `arch/x86.rs`.
#[test]
fn x86_trap_brk_encodings() {
    assert_eq!(
        TRAP_INSN, 0x0000_80cd,
        "i386 `int $0x80` must encode as cd 80"
    );
    assert_eq!(BRK_INSN, 0x0000_00cc, "i386 `int3` must encode as cc");
}

/// The NT_PRSTATUS iovec contract: `UserPtRegs` is exactly
/// `sizeof(struct user_regs_struct)` == 68 bytes (17 * u32), so a GETREGSET
/// iovec staged from this layout reads the full kernel regset without
/// truncation.
#[test]
fn x86_regset_byte_contract() {
    assert_eq!(NT_PRSTATUS_SIZE, 68, "i386 NT_PRSTATUS regset is 17 * u32");
    assert_eq!(
        core::mem::size_of::<UserPtRegs>(),
        NT_PRSTATUS_SIZE,
        "UserPtRegs must match the NT_PRSTATUS byte contract",
    );
}

/// The Linux i386 syscall ABI wiring: number in `eax`, args in
/// `ebx, ecx, edx, esi, edi, ebp`, return read back from `eax`. Args are
/// truncated to the 32-bit register width. Staging then reading round-trips the
/// syscall number through `eax` and confirms each arg lands in its ABI
/// register.
#[test]
fn x86_syscall_abi_register_wiring() {
    let mut regs = UserPtRegs::default();
    let args = [11, 22, 33, 44, 55, 66];
    set_syscall_args(&mut regs, 0xdead_beef, 20, args);

    assert_eq!(regs.eip, 0xdead_beef, "pc -> eip");
    assert_eq!(regs.eax, 20, "syscall number -> eax");
    assert_eq!(regs.ebx, 11, "arg0 -> ebx");
    assert_eq!(regs.ecx, 22, "arg1 -> ecx");
    assert_eq!(regs.edx, 33, "arg2 -> edx");
    assert_eq!(regs.esi, 44, "arg3 -> esi");
    assert_eq!(regs.edi, 55, "arg4 -> edi");
    assert_eq!(regs.ebp, 66, "arg5 -> ebp");

    // Post-trap, the kernel writes the return value into eax; the helper reads
    // it back sign-extended to i64 so `-errno` returns survive.
    regs.eax = (-14_i32) as u32;
    assert_eq!(
        get_syscall_return(&regs),
        -14,
        "return read from eax, sign-extended"
    );
}
