//! Seal feature root — module tree for Tier A (arena-level) and Tier B (per-prop hook) seals.

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

pub mod arena;
pub mod elf;
pub mod hook;
pub mod maps;
pub mod ptrace;

/// Process identifier alias matching the libc type used by ptrace/waitpid.
pub type Pid = libc::pid_t;

/// Android init's fixed pid — the only Tier A / Tier B target in v1.
/// Extracted so future refactors touch one line, not N call sites.
pub(crate) const INIT_PID: Pid = 1;

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

pub use arena::{seal_arena, seal_arena_with_mirror, unseal_arena, unseal_arena_with_mirror};
pub use maps::{parse_maps, MapEntry};
pub use ptrace::{
    getregset, ptrace_detach, ptrace_interrupt, ptrace_peektext, ptrace_poketext, ptrace_seize,
    remote_syscall, setregset, wait_stop, UserPtRegs,
};

/// Process-wide in-memory registry of active seals.
///
/// P02 populates `SealTier::Arena` records; P04 will populate `SealTier::Prop`.
/// The registry is intentionally ephemeral per REGISTRY §1
/// "Persistence: Deferred for v1 — in-memory `SealRecord` only"; it is
/// rebuilt on every resetprop-cli invocation.
static SEALS: OnceLock<Mutex<Vec<SealRecord>>> = OnceLock::new();

/// Lazily-initialized accessor for the seal registry.
/// P02/P04/P05 all go through this function — do not expose `SEALS` directly.
pub fn seals_registry() -> &'static Mutex<Vec<SealRecord>> {
    SEALS.get_or_init(|| Mutex::new(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `OnceLock<Mutex<Vec<SealRecord>>>` round-trip semantics without
    /// depending on the full `PropSystem` plumbing. Uses unique per-test name
    /// prefixes so parallel tests do not interfere with each other's entries.
    #[test]
    fn seal_record_roundtrip() {
        const NAME_A: &str = "T4_ROUNDTRIP_ALPHA";
        const NAME_B: &str = "T4_ROUNDTRIP_BETA";

        let registry = seals_registry();
        let mut guard = registry
            .lock()
            .expect("registry mutex must not be poisoned");
        let baseline = guard.len();

        guard.push(SealRecord {
            name: NAME_A.to_string(),
            arena_path: PathBuf::from("/dev/__properties__/alpha"),
            tier: SealTier::Arena,
            sealed_at: SystemTime::now(),
        });
        guard.push(SealRecord {
            name: NAME_B.to_string(),
            arena_path: PathBuf::from("/dev/__properties__/beta"),
            tier: SealTier::Arena,
            sealed_at: SystemTime::now(),
        });
        assert_eq!(guard.len(), baseline + 2);

        guard.retain(|r| r.name != NAME_A);
        assert_eq!(guard.len(), baseline + 1);

        // Clean up the second record so we leave the registry as we found it.
        guard.retain(|r| r.name != NAME_B);
        assert_eq!(guard.len(), baseline);
    }

    /// Exercises the retain-predicate in isolation: removing a name that does
    /// not exist leaves the registry untouched.
    #[test]
    fn unseal_returns_false_when_not_sealed() {
        const MISSING: &str = "T4_UNSEAL_MISSING_NAME";

        let registry = seals_registry();
        let mut guard = registry
            .lock()
            .expect("registry mutex must not be poisoned");
        let before = guard.len();

        guard.retain(|r| !(r.name == MISSING && r.tier == SealTier::Arena));
        assert_eq!(guard.len(), before);
    }

    /// Tripwire for path-derivation bugs: the `properties_serial` guard relies
    /// on `Path::file_name().and_then(|n| n.to_str())` returning exactly
    /// `"properties_serial"` for the canonical arena path. If this breaks,
    /// `PropSystem::seal_arena` would silently admit the forbidden arena.
    #[test]
    fn seal_arena_rejects_properties_serial() {
        use std::path::Path;

        let path = Path::new("/dev/__properties__/properties_serial");
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("properties_serial"),
            "canonical properties_serial path must be recognised by the guard",
        );
    }
}
