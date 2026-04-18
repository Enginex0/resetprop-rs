//! Seal feature root — module tree for Tier A (arena-level) and Tier B (per-prop hook) seals.
//!
//! NOTE: Public re-exports of `maps::*` and `ptrace::*` are intentionally deferred.
//! P01 Task 1 ships the submodule declarations and public types only; the
//! `pub use` re-exports will be added incrementally by P01 Task 2 (`maps`)
//! and P01 Task 3/4 (`ptrace`) when the corresponding items land.

use std::path::PathBuf;
use std::time::SystemTime;

pub mod maps;
pub mod ptrace;

/// Process identifier alias matching the libc type used by ptrace/waitpid.
pub type Pid = libc::pid_t;

/// In-memory record describing a single sealed property or arena.
///
/// Populated by P02 (Tier A — arena-level records) and P04 (Tier B — per-prop records).
#[derive(Debug, Clone)]
pub struct SealRecord {
    pub name: String,
    pub arena_path: PathBuf,
    pub tier: SealTier,
    pub sealed_at: SystemTime,
}

/// Tier classifier for a [`SealRecord`].
///
/// - `Arena` — Tier A: arena-level `MAP_PRIVATE|MAP_FIXED` remap (P02).
/// - `Prop`  — Tier B: per-prop `__system_property_update` hook (P04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealTier {
    Arena,
    Prop,
}

pub use maps::{MapEntry, parse_maps};
pub use ptrace::{
    UserPtRegs,
    ptrace_seize, ptrace_interrupt, wait_stop,
    getregset, setregset, ptrace_detach,
    remote_syscall,
};
