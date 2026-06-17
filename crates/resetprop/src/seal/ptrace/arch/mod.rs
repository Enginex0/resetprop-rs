//! Per-arch register-layout modules and the `cfg`-selected active arch.
//!
//! Each submodule exports the same arch-neutral interface — `UserPtRegs`,
//! `TRAP_INSN`, `BRK_INSN`, `NT_PRSTATUS_SIZE`, `set_syscall_args`,
//! `get_syscall_return` — with a per-arch `NT_PRSTATUS_SIZE` size assert
//! verified against the UAPI headers. `ptrace.rs` re-exports the active arch's
//! interface so its body carries no raw register-index literals.
//!
//! Only the target's own arch module is compiled in (so its unused-on-other-
//! arches helpers raise no `dead_code`), and that one module is re-exported as
//! `active`. A target whose arch has no register layout here fails to compile
//! rather than silently selecting the wrong one.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as active;

#[cfg(target_arch = "arm")]
pub mod arm;
#[cfg(target_arch = "arm")]
pub use arm as active;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64 as active;

#[cfg(target_arch = "x86")]
pub mod x86;
#[cfg(target_arch = "x86")]
pub use x86 as active;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as active;
