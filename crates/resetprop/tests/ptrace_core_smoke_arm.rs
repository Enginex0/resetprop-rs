//! Per-arch encoding smoke test for the 32-bit ARM (AArch32) ptrace facade.
//!
//! Sibling of `ptrace_core_smoke.rs` (the aarch64 live SEIZE round-trip).
//! Where that file forks a tracee and round-trips `getpid()`, this file
//! asserts the *static* arch contract the `remote_syscall` stager depends on:
//! the syscall-trap / breakpoint instruction encodings, the NT_PRSTATUS regset
//! byte size, and the Linux EABI syscall-ABI register wiring. These are
//! compile-time-constant assertions plus one pure register-staging round-trip,
//! so the test needs no ptrace, no fork, and no `#[ignore]`.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "arm")]`. The constants under test
//! (`resetprop::seal::ptrace::{TRAP_INSN, BRK_INSN, NT_PRSTATUS_SIZE,
//! UserPtRegs, set_syscall_args, get_syscall_return}`) are re-exported from the
//! `cfg`-selected active arch module, so they hold the AArch32 values only when
//! the crate is built for arm. On any other host this file compiles to an empty
//! test binary, reporting `0 passed; 0 failed; 0 ignored`.
//!
//! Encoding sources (mirrored from
//! `crates/resetprop/src/seal/ptrace/arch/arm.rs`, grounded against injectrc
//! `init_injector/ptrace_utils.hpp:51-64` REG_* macros):
//!   - `svc #0`  (ARM enc, `00 00 00 ef`) → TRAP_INSN == 0xef00_0000  (ARM ARM A8.8.361)
//!   - `bkpt #0` (ARM enc, `70 00 20 e1`) → BRK_INSN  == 0xe120_0070  (ARM ARM A8.8.24)
//!   - regset = sizeof(struct pt_regs { long uregs[18]; }) == 72 bytes
//!
//! Runner invocation:
//!   cargo test -p resetprop --target armv7-linux-androideabi \
//!       --test ptrace_core_smoke_arm

#![cfg(target_arch = "arm")]

use resetprop::seal::ptrace::{
    get_syscall_return, set_syscall_args, UserPtRegs, BRK_INSN, NT_PRSTATUS_SIZE, TRAP_INSN,
};

/// The AArch32 trap/breakpoint encodings the gadget stages: `svc #0` then
/// `bkpt #0` (ARM-mode encodings). Pinned little-endian per `arch/arm.rs`.
/// Thumb-mode handling is deferred with the rest of the armv7 runtime port.
#[test]
fn arm_trap_brk_encodings() {
    assert_eq!(
        TRAP_INSN, 0xef00_0000,
        "ARM `svc #0` must encode as 00 00 00 ef"
    );
    assert_eq!(
        BRK_INSN, 0xe120_0070,
        "ARM `bkpt #0` must encode as 70 00 20 e1"
    );
}

/// The NT_PRSTATUS iovec contract: `UserPtRegs` is exactly
/// `sizeof(struct pt_regs)` == 72 bytes (18 * u32), so a GETREGSET iovec staged
/// from this layout reads the full kernel regset without truncation.
#[test]
fn arm_regset_byte_contract() {
    assert_eq!(NT_PRSTATUS_SIZE, 72, "ARM NT_PRSTATUS regset is 18 * u32");
    assert_eq!(
        core::mem::size_of::<UserPtRegs>(),
        NT_PRSTATUS_SIZE,
        "UserPtRegs must match the NT_PRSTATUS byte contract",
    );
}

/// The Linux EABI syscall ABI wiring: pc in `uregs[15]`, number in `r7`
/// (`uregs[7]`), args in `r0..r5` (`uregs[0..6]`), return read back from `r0`
/// (`uregs[0]`). Args are truncated to the 32-bit register width. Staging then
/// reading round-trips the syscall number through `r7` and confirms each arg
/// lands in its ABI register.
#[test]
fn arm_syscall_abi_register_wiring() {
    let mut regs = UserPtRegs::default();
    let args = [11, 22, 33, 44, 55, 66];
    set_syscall_args(&mut regs, 0xdead_beef, 20, args);

    assert_eq!(regs.uregs[15], 0xdead_beef, "pc -> uregs[15]");
    assert_eq!(regs.uregs[7], 20, "syscall number -> r7 (uregs[7])");
    for (i, want) in args.iter().enumerate() {
        assert_eq!(regs.uregs[i], *want as u32, "arg{i} -> uregs[{i}]");
    }

    // Post-trap, the kernel writes the return value into r0; the helper reads
    // it back sign-extended to i64 so `-errno` returns survive.
    regs.uregs[0] = (-14_i32) as u32;
    assert_eq!(
        get_syscall_return(&regs),
        -14,
        "return read from r0, sign-extended"
    );
}
