//! Per-arch encoding smoke test for the x86-64 ptrace facade.
//!
//! Sibling of `ptrace_core_smoke.rs` (the aarch64 live SEIZE round-trip).
//! Where that file forks a tracee and round-trips `getpid()`, this file
//! asserts the *static* arch contract the `remote_syscall` stager depends on:
//! the syscall-trap / breakpoint instruction encodings, the NT_PRSTATUS regset
//! byte size, and the SysV/Linux x86-64 syscall-ABI register wiring. These are
//! compile-time-constant assertions plus one pure register-staging round-trip,
//! so the test needs no ptrace, no fork, and no `#[ignore]`.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "x86_64")]`. The constants under test
//! (`resetprop::seal::ptrace::{TRAP_INSN, BRK_INSN, NT_PRSTATUS_SIZE,
//! UserPtRegs, set_syscall_args, get_syscall_return}`) are re-exported from the
//! `cfg`-selected active arch module, so they hold the x86-64 values only when
//! the crate is built for x86-64. On any other host this file compiles to an
//! empty test binary, reporting `0 passed; 0 failed; 0 ignored`.
//!
//! Encoding sources (mirrored from
//! `crates/resetprop/src/seal/ptrace/arch/x86_64.rs`, grounded against injectrc
//! `init_injector/ptrace_utils.hpp:25-34` REG_* macros):
//!   - `syscall` (`0f 05`)  → TRAP_INSN == 0x0000_050f   (Intel SDM Vol 2B)
//!   - `int3`    (`cc`)     → BRK_INSN  == 0x0000_00cc   (Intel SDM Vol 2A)
//!   - regset = sizeof(struct user_regs_struct) == 216 bytes
//!
//! Runner invocation:
//!   cargo test -p resetprop --target x86_64-linux-android \
//!       --test ptrace_core_smoke_x86_64

#![cfg(target_arch = "x86_64")]

use resetprop::seal::ptrace::{
    get_syscall_return, set_syscall_args, UserPtRegs, BRK_INSN, NT_PRSTATUS_SIZE, TRAP_INSN,
};

/// The x86-64 trap/breakpoint encodings the gadget stages: `syscall` (`0f 05`)
/// then `int3` (`cc`). Pinned little-endian into the low half of the `u32`
/// instruction constants per `arch/x86_64.rs`.
#[test]
fn x86_64_trap_brk_encodings() {
    assert_eq!(
        TRAP_INSN, 0x0000_050f,
        "x86-64 `syscall` must encode as 0f 05"
    );
    assert_eq!(BRK_INSN, 0x0000_00cc, "x86-64 `int3` must encode as cc");
}

/// The NT_PRSTATUS iovec contract: `UserPtRegs` is exactly
/// `sizeof(struct user_regs_struct)` == 216 bytes, so a GETREGSET iovec staged
/// from this layout reads the full kernel regset without truncation.
#[test]
fn x86_64_regset_byte_contract() {
    assert_eq!(
        NT_PRSTATUS_SIZE, 216,
        "x86-64 NT_PRSTATUS regset is 27 * u64"
    );
    assert_eq!(
        core::mem::size_of::<UserPtRegs>(),
        NT_PRSTATUS_SIZE,
        "UserPtRegs must match the NT_PRSTATUS byte contract",
    );
}

/// The SysV/Linux x86-64 syscall ABI wiring: number in `rax`, args in
/// `rdi, rsi, rdx, r10, r8, r9`, return read back from `rax`. Staging then
/// reading round-trips the syscall number through `rax` and confirms each arg
/// lands in its ABI register.
#[test]
fn x86_64_syscall_abi_register_wiring() {
    let mut regs = UserPtRegs::default();
    let args = [11, 22, 33, 44, 55, 66];
    set_syscall_args(&mut regs, 0xdead_beef, 39, args);

    assert_eq!(regs.rip, 0xdead_beef, "pc -> rip");
    assert_eq!(regs.rax, 39, "syscall number -> rax");
    assert_eq!(regs.rdi, 11, "arg0 -> rdi");
    assert_eq!(regs.rsi, 22, "arg1 -> rsi");
    assert_eq!(regs.rdx, 33, "arg2 -> rdx");
    assert_eq!(regs.r10, 44, "arg3 -> r10");
    assert_eq!(regs.r8, 55, "arg4 -> r8");
    assert_eq!(regs.r9, 66, "arg5 -> r9");

    // Post-trap, the kernel writes the return value into rax; the helper reads
    // it back as a signed i64 so `-errno` returns survive.
    regs.rax = (-14_i64) as u64;
    assert_eq!(
        get_syscall_return(&regs),
        -14,
        "return read from rax as i64"
    );
}
