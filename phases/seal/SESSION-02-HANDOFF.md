# Session 02 Handoff — P02 Tier A (T1-T4 shipped, T5 + Gate 2 pending)

> Read this FIRST on next session start. Then follow the Session Start Protocol in `.claude/system-prompt.md`.

## State at handoff (2026-04-18)

### Branch

`feat/P02-tier-a` — cut from `feat/P01-foundation` (the P01 tip `24c7cd1`). 5 feature commits ahead of that tip, 27+ commits ahead of `main`. Do NOT rebase, do NOT merge to main yet. Next session appends T5 + checklist refresh + Gate 2 audit commits.

### Commits on branch (oldest first, P02 only)

```text
690e606 feat(seal): add arena mapping lookup
d96d68c refactor(seal): adopt null_mut and Error::other
8ff023b feat(seal): add ptrace poketext staging
cb65fad feat(seal): add remote arena remap primitive
bd1c7d6 feat(seal): wire tier A into PropSystem API
```

Plus the closing S01 commit that appends this handoff and updates REGISTRY §4 / §7.

### Task progress (REGISTRY §4 row P02)

Note: the session restructured T2-T4 mid-flight after discovering P01's shipped surface did not include `ptrace_poketext`/`peektext` (required to stage into `r-xp` libc.text). Task boundaries were adjusted to keep the 5-task-per-session cap while adding the required primitives. End-state unchanged.

| Session task | Shipped content | Self-Audit Gate | Commit |
|--------------|-----------------|-----------------|--------|
| T1 | `find_arena_mapping` + `find_arena_mapping_in` + 3 unit tests + `pub mod arena` in seal/mod.rs | Gate 1 filled | `690e606` |
| T2 | `refactor(seal)` clippy cleanup (9 P01-handoff warnings: 7× `zero_ptr`, 2× `io_other_error`) + `PTRACE_PEEKDATA`/`POKEDATA` constants + `ptrace_peektext`/`ptrace_poketext` pub primitives + `read_remote`/`write_remote` bumped to `pub(crate)` + `ARM64_NOP` + `find_nop_slide` in arena.rs + 4 new unit tests | Gate 2a + Gate 2b (split) filled | `d96d68c` + `8ff023b` |
| T3 | `RemoteAttach` RAII detach guard + `RemapFlags {Private, Shared}` + `remote_remap_private` (libc.text NOP-slide bootstrap → POKEDATA svc+brk → mmap RWX anon page → openat/mmap/close via remote_syscall → bootstrap page intentionally leaked) + 3 unit tests | Gate 3 filled | `cb65fad` |
| T4 | `seal_arena`/`unseal_arena`/`_with_mirror` thin orchestrators + `OnceLock<Mutex<Vec<SealRecord>>>` registry in seal/mod.rs + `seals_registry()` accessor + `PropSystem::seal_arena` + `PropSystem::unseal_arena` with `properties_serial` guard using existing `SERIAL_FILE` constant + REGISTRY-locked mirror path convention + 3 unit tests + duplicate-name refresh semantics + `pub use seal::{SealRecord, SealTier}` at lib.rs | Gate 4 filled | `bd1c7d6` |
| T5 | Integration smoke test `tests/tier_a_child_smoke.rs` | Gate 5 empty | PENDING |
| Checklist refresh | File:line citations updated to match landed code; REGISTRY §4 P02 row → SEGMENT_COMPLETE once T5 lands | — | PENDING |
| Gate 2 adversarial | code-reviewer (sonnet) + critic (opus) in parallel, reports to `phases/seal/audits/P02-audit.md`, `External API Verification: YES` | — | PENDING |

### Test baseline

`cargo test -p resetprop` reports `75 passed; 0 failed` on x86_64-linux (63 P01 baseline + 12 new P02 tests). Gate against regression: T5 must preserve 75 lib tests; T5 adds 1 `#[ignore]`-gated integration test that is compiled out on non-aarch64 hosts OR compiled in but ignored by default.

### Clippy / fmt state

- `cargo clippy -p resetprop --no-deps --lib -- -D warnings` is CLEAN on HEAD. T2's refactor commit closed the 9 pre-existing P01 warnings. New code added zero new warnings.
- `cargo fmt --check` on P02-touched files (arena.rs, ptrace.rs, mod.rs, lib.rs) passes. Pre-existing drift in `trie.rs`, `seal/maps.rs`, `propdetect/heuristics.rs`, `resetprop-cli/src/main.rs` is out of P02 scope.

### Design decisions locked this session

1. **Bootstrap: POKEDATA-first, not mprotect.** `process_vm_writev` respects VMA write bits; libc.text is `r-xp`. `PTRACE_POKEDATA` bypasses VMA write protection. P01 shipped readers/writers via `process_vm_*` only — T2 added the two POKE/PEEK word-granularity primitives specifically for this bootstrap. Consequence: P03/P04 inherit the same primitive for their own chicken-and-egg when installing the `__system_property_update` trampoline.
2. **`RemoteAttach` owns detach, `remote_syscall` owns scratch restore.** Two RAII concerns, two owners. The bootstrap stage in T3 manually restores its POKEDATA-staged bytes before any error `?` so libc.text is always left pristine — the guard does not re-do that work. Agent-named the type `RemoteAttach` (not spec-suggested `RemoteSyscallGuard`) to match single-responsibility.
3. **Bootstrap RWX page intentionally leaked.** Munmap'ing the bootstrap page would require a second POKEDATA bootstrap (the only remaining scratch is libc.text `r-xp`, which `process_vm_writev`-based `remote_syscall` cannot stage into). 4 KiB per seal/unseal call is bounded; seals are rare operator-triggered events, not hot-path. Documented inline at the tail of `remote_remap_private`.
4. **`HookInstallFailed(String)` chosen over adding `ArenaRemapFailed`.** Zero REGISTRY churn. REGISTRY §1 row 35's "Error surface" variant count stays at 9. Error messages include `mmap returned {actual}, expected {start}` which is specific enough for CLI triage.
5. **Mirror path via convention, not via `appcompat.rs` accessor.** `AppcompatAreas` does not expose paths (would require touching `appcompat.rs`, which AS-06 forbids). Mirror path derived as `primary.parent().join("appcompat_override").join(filename)` — the exact string REGISTRY §1 "Appcompat mirror path convention" locks. Existence still probed via `appcompat.mirror_for(filename).is_some()`.
6. **Registry is a Vec, not a HashMap.** Per REGISTRY §1 Persistence row (deferred v1, in-memory only); expected seal count < 20; linear scan is fine. `OnceLock<Mutex<Vec<SealRecord>>>`. Poisoned mutex is recovered via `.into_inner()` with a logged warning, not panic.

### Environment facts verified this session

- Host is x86_64 Linux; `ptrace_scope = 0`. T5's `#[ignore]`-gated smoke test CAN run on this host via `--ignored --test-threads=1` once shipped.
- AOSP headers at `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h` verified: `PTRACE_PEEKDATA` at line 12, `PTRACE_POKEDATA` at line 15 (agent corrected the task's placeholder line numbers).
- T2's `peek_poke_roundtrip_on_self` test is `#[cfg(target_arch = "aarch64")]` gated — compiled out on this x86_64 host. Running it requires an aarch64 Linux host with `ptrace_scope ≤ 1`.

## Next session — start sequence

1. Read `.claude/system-prompt.md` (governance), `phases/seal/REGISTRY-P.md` §1-§4 + §7 latest row, `phases/seal/P02-tier-a.md` (spec), `phases/seal/checklists/P02-checklist.md` (gates 1-4 already filled).
2. Read this handoff file in full.
3. Verify branch: `git branch --show-current` should report `feat/P02-tier-a`.
4. Verify baseline: `cargo test -p resetprop` → 75 passed; `cargo clippy -p resetprop --no-deps --lib -- -D warnings` clean.
5. Dispatch T5 (integration smoke test) using a rust-engineer agent with the prompt shell already drafted in the previous session's task list.
6. Audit T5, fill Self-Audit Gate 5, commit as `test(seal): add tier A child isolation smoke test`.
7. Refresh the checklist: file:line citations to real landed line numbers, canonical-values table verified-at anchors, FR/TC checkboxes ticked. Commit as `docs(seal): refresh P02 checklist pre-Gate-2`.
8. Run Gate 2 adversarial audit — TWO agents IN PARALLEL in a single message: `oh-my-claudecode:code-reviewer` (sonnet) + `oh-my-claudecode:critic` (opus), personas verbatim from `.claude/system-prompt.md`, `External API Verification: YES`, both write to `phases/seal/audits/P02-audit.md`.
9. If either emits `VERDICT: NEEDS_FIX`, fix all CRITICAL + MAJOR findings, then re-dispatch both in parallel.
10. On BOTH verdicts `PASS`: flip REGISTRY §4 P02 row to `COMPLETE`, append §7 session log with audit verdict summary, commit as `docs(seal): close P02 with Gate 2 PASS`. Phase done.

## Known open items (to address in next session or flagged for later)

- **m7 (this session)**: Checklist file:line citations in P02-checklist.md still reference the task renumbering this session produced (T2 was recast from `remote_remap_private` to `ptrace_poketext` + clippy cleanup; T3 became `remote_remap_private` + guard). Gate 5 block is empty. Checklist refresh commit addresses both.
- **m8 (this session)**: `#[cfg(target_arch = "aarch64")]` gating on T2's `peek_poke_roundtrip_on_self` means the primitive's remote behavior has NOT been exercised on this x86_64 dev host. If T5's x86_64 run fails in a way that implicates POKEDATA, escalate to an aarch64 device run before declaring the smoke test broken.
- **M1 carried from P01 Gate 2 round 1** (already resolved in P01 but worth a compact reminder): `PTRACE_SEIZE` passes `PTRACE_O_TRACESYSGOOD` so multi-threaded tracee syscall-stops remain distinguishable. T3's `RemoteAttach` correctly composes `ptrace_seize` → `ptrace_interrupt` → `wait_stop(PTRACE_EVENT_STOP)`.

## Cross-session directive — stay inside scope

P05 will wire the CLI flags. Do NOT add CLI surface in T5 or in any P02 cleanup pass. Do NOT touch `resetprop-cli/src/main.rs`. AS-04 and AS-09 are bright-line anti-scope items; breaching them turns a tight phase into a sprawl.

If the T5 agent reports that the fork+seal smoke test blocks on something deeper than the `#[ignore]` gate can paper over (e.g., remote `read_remote` fails because the forked child's libc is statically linked and has no `r-xp` mapping), STOP and surface the finding. Tier A's smoke test pattern was designed around a child that `libc::mmap`'s the tempfile; the seal operates on init (PID 1) in production, not the fork child. If the test architecture needs rework, update the spec before improvising.
