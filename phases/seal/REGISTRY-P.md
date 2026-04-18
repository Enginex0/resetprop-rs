# resetprop-rs Seal — Implementation Registry

> Read this FIRST every session. Then read your assigned phase spec.
> NEVER modify [LOCKED] sections. Append-only to the session log.
> Hard rules (per `/Advanced-planning` SKILL.md): max 5 tasks per session, self-audit between tasks, Gate 2 at phase end.

## 1. Locked Decisions [LOCKED]

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language / edition | Rust 2021, stable toolchain | Matches existing workspace (`Cargo.toml:1-4`); no proc-macro deps |
| Runtime deps | `libc = "0.2"` only (prod); `tempfile = "3"` dev-dep | Plan §Implementation — single-dep policy; preserves ~320 KB binary footprint |
| Forbidden crates | `nix`, `goblin`, `object`, `serde`, `anyhow`, `dynasm` | Single-dep policy; hand-roll ELF parser + ARM64 encoder |
| Target platforms | Android 10–15, ARM64 primary; ARMv7/x86/x86_64 via existing cross-compile | Matches README §Compatibility |
| Root requirement | Any root (KSU, Magisk, APatch, bare `su`) with CAP_SYS_PTRACE on PID 1 | Plan §Context — init is PID 1; ptrace is the remote-work lever |
| Seal mechanisms shipped | Tier A (arena-level MAP_PRIVATE\|MAP_FIXED) AND Tier B (per-prop hook on `__system_property_update`) | Plan §Recommended Approach — user locked both tiers |
| `-sl` / `--seal` default | Tier B per-prop hook | Plan §CLI — per-prop precision keeps neighbor props live |
| `-sla` / `--seal-arena` | Tier A arena-level fallback | Fallback when Tier B's ELF/hook path refuses on a libc build |
| `-st` / `--stealth` | Unchanged — pure stealth set, no ptrace, no hook | Back-compat for user's existing telephony scripts |
| Scope of v1 arenas | `/dev/__properties__/u:object_r:telephony_prop:s0` + its `appcompat_override` mirror if present | Plan §Scope — locked by user during interview |
| Arenas NOT to touch | `/dev/__properties__/properties_serial` | Global futex wake channel (system_properties.cpp:325-333); privatizing it breaks system-wide notifications |
| File permissions | Never modified — arenas stay root:root 0644 | `map_fd_ro` rejects on st_uid!=0, st_gid!=0, or group/other write (prop_area.cpp:111-138); init aborts on EACCES (prop_area.cpp:63-68) |
| Persistence | Deferred for v1 — in-memory `SealRecord` only | Plan §Decisions locked — user re-runs on every boot |
| prop_info layout | 96 bytes fixed, name at offset 96 | `static_assert(sizeof(prop_info) == 96)` at `prop_info.h:89` |
| Serial bit layout | bit 0 dirty, bit 16 LONG_FLAG, top byte = value length | `SERIAL_DIRTY` / `SERIAL_VALUE_LEN` macros in `system_properties.cpp:52-53` |
| prop_area magic / version / size | `0x504f5250` / `0xfc6ed0ab` / 128 KB (`PA_SIZE`) | `prop_area.cpp:47-50` |
| Hook page | 4 KB RWX anonymous mmap injected into init | Plan §Tier B — holds lock-list + hook body |
| Hook target symbol | `__system_property_update` exported from init's libc.so | Plan §Tier B — libc C wrapper for `SystemProperties::Update` (system_properties.cpp:270) |
| Trampoline | 16 bytes at symbol entry: `ldr x16, [pc, #8]; br x16; <u64 target>` | References §arm64-a64-encoding — `trampoline_to()` helper |
| ELF parsing path | Hand-rolled ELF64 walker in `seal/elf.rs` (PT_DYNAMIC → DT_SYMTAB/DT_STRTAB/DT_GNU_HASH) | Plan §Module layout; references §android-libc-elf |
| Symbol lookup | GNU_HASH primary; linear-scan fallback | References §android-libc-elf §5–6 |
| ARM64 encoder | Hand-rolled `const fn` encoders in `seal/hook.rs` | References §arm64-a64-encoding |
| Remote syscall path | ptrace SEIZE + INTERRUPT; stage `svc #0 ; brk #0` in rx scratch; GETREGSET/SETREGSET with NT_PRSTATUS iovec | References §linux-arm64-abi §7 |
| I-cache coherence after hook write | Remote `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)` (primary); `isb` staging (fallback) | References §linux-arm64-abi + §arm64-a64-encoding |
| Error surface | Typed `enum Error` (existing pattern); 9 new variants in `error.rs`: `PtraceAttach(io::Error)` (seize/detach attach-phase), `PtraceOp(io::Error)` (post-attach ptrace / process_vm_* operation failures), `PtraceUnexpectedStatus(i32)` (wait-status mismatch carrying raw status bits), `PtraceScope`, `ArenaAlreadySealed(PathBuf)`, `ArenaNotMapped(PathBuf)`, `ElfParse(String)`, `SymbolNotFound(String)`, `HookInstallFailed(String)`. No `anyhow`; matches `error.rs:5-22`. [Amended S02 2026-04-18 per Gate 2 critic M2: split the original `PtraceAttach` catch-all into three semantically-distinct variants so the CLI and P02/P04 can match-on-variant for hint logic.] |
| Threat model | Adversary without root. Rooted self-inspection (reading `/proc/1/maps`) CAN detect seal | Plan §Known Trade-offs — acceptable |
| propdetect integration | New heuristic for Tier A + Tier B signatures (future) | Plan §Touchpoints for propdetect — noted, not scoped to v1 |
| Appcompat mirror path convention | `/dev/__properties__/appcompat_override/<filename equal to primary context file>` | Plan §Implementation — Internal flow in `seal()`; AOSP system_properties.cpp:278-296 |
| `SealRecord` and `SealTier` types created by P01 | Types defined in `crates/resetprop/src/seal/mod.rs` (P01 scope); P02 populates `SealTier::Arena` records, P04 populates `SealTier::Prop` records | Avoids ownership ambiguity between P01/P02/P04 |
| `SealRecord` fields | `{ name: String, arena_path: PathBuf, tier: SealTier, sealed_at: SystemTime }` | Plan §New public API |
| `SealTier` variants | `SealTier::Arena`, `SealTier::Prop` | Plan §New public API |
| Trampoline LDR opcode for `ldr x16, [pc, #8]` | `LDR_X16_PC8 = 0x58000050` | references/arm64-a64-encoding.md §trampoline_to |
| `properties_serial` name guard applies to BOTH tiers | `PropSystem::seal` (Tier B) AND `PropSystem::seal_arena` (Tier A) must reject any name that resolves to the `properties_serial` file | Extends REGISTRY §1 existing rule — confirmed by auditors |

## 2. Coding Conventions [LOCKED]

| Domain | Convention |
|--------|-----------|
| Crate structure | `crates/resetprop/` (lib) + `crates/resetprop-cli/` (bin named `resetprop`) — workspace members per root `Cargo.toml:3` |
| Module naming | `snake_case`; seal feature lives under `crates/resetprop/src/seal/` |
| Type naming | `PascalCase` (`SealRecord`, `HookHandle`, `SealTier`) |
| Constants | `SCREAMING_SNAKE` at module top, behind `pub const` when shared |
| Branch per phase | `feat/P##-short-name` (one branch even if multi-segment) |
| Commit scopes | `feat(seal):`, `fix(seal):`, `test(seal):`, `docs(seal):`, `refactor(seal):`, `chore(seal):` |
| Commit subject | Imperative mood, ≤50 chars; body wraps at 72; no trailing period |
| Test naming | `fn test_<module>_<condition>_<expected>()` (matches existing style) |
| Integration test location | `crates/resetprop/tests/` (per-crate) or `tests/` (workspace-level) |
| CLI error output | `eprintln!("resetprop: {e}")` pattern (matches `main.rs:10`) |
| `repr(C)` structs | Used for ELF64 / pt_regs layouts; annotated with `#[repr(C)]` and a size `const _: () = assert!(mem::size_of::<T>() == N)` check |
| Unsafe policy | `unsafe` blocks allowed; each block has a `// SAFETY:` comment explaining the invariant |
| Feature flags | None introduced; seal is always built |
| MSRV | Follows workspace; no explicit pin |
| Log format | No log crate. `eprintln!` for errors, conditional on `-v` flag per `main.rs:162` |
| Binary size target | ≤400 KB arm64 release (baseline ~320 KB); `opt-level=s`, LTO, `panic=abort`, strip |

## 3. Domain Ownership [LOCKED]

| Component | Owned Domains |
|-----------|---------------|
| `crates/resetprop/src/seal/mod.rs` | seal orchestration, `SealRecord`, `SealTier`, `PropSystem` glue API |
| `crates/resetprop/src/seal/ptrace.rs` | ptrace attach/detach, register snapshot, remote syscall injector. Shared by Tier A + B |
| `crates/resetprop/src/seal/maps.rs` | `/proc/<pid>/maps` parser |
| `crates/resetprop/src/seal/arena.rs` | Tier A: remote `openat` + `mmap(MAP_PRIVATE\|MAP_FIXED)` + `close` on target arena file |
| `crates/resetprop/src/seal/elf.rs` | ELF64 walker, symbol resolution (GNU_HASH + linear fallback) |
| `crates/resetprop/src/seal/hook.rs` | Tier B: hook page alloc, ARM64 encoder, trampoline install, lock-list mechanics |
| `crates/resetprop/src/lib.rs` | `PropSystem::seal`, `seal_arena`, `unseal`, `unseal_arena`, `seals` public API |
| `crates/resetprop/src/error.rs` | 7 new error variants + `Display` + `Error::source` impls |
| `crates/resetprop-cli/src/main.rs` | CLI parsing, dispatch, `print_usage` additions for `-sl`, `-sla`, `--seals`, `--unseal`, `--unseal-arena` |
| `README.md` | User-facing docs — new "Seal" subsection + CLI reference table rows |
| `tests/device-stress-test.sh` | Test 21 (Tier B with neighbor verification) + Test 22 (Tier A arena stress) |
| `crates/resetprop/tests/tier_a_child_smoke.rs` | Off-device Tier A integration test (fork + mmap MAP_SHARED + remap) |
| `crates/resetprop/tests/tier_b_child_smoke.rs` | Off-device Tier B integration test (fork + fake `__system_property_update` + hook install) |
| Shared references | `phases/seal/references/*.md` — immutable hot-load context for every session |

## 4. Phase Progress

One row per segment. Phases without segmentation use a single row with Segment = "—".

| Phase | Segment | Tasks | Status | Branch | Session(s) | Notes |
|-------|---------|-------|--------|--------|------------|-------|
| P01 — Foundation: ptrace + maps | — | 5 | COMPLETE | feat/P01-foundation | S01 + S02 (2026-04-18) | All 5 tasks shipped with self-audit gates filled. Gate 2 adversarial audit PASS from both code-reviewer (Sonnet) and critic (Opus) after one fix cycle. 63 unit tests + 1 on-device integration test (aarch64 Android 15, 3 consecutive `1 passed` runs at 0.06s each) verify the full ptrace+maps+remote_syscall stack. Error surface grew from 7 to 9 variants per Gate 2 M2 split. |
| P02 — Tier A: arena-level seal | — | 5 | IN_PROGRESS | feat/P02-tier-a | S01 (2026-04-18) | T1-T4 shipped with self-audit gates filled. T5 integration smoke test + checklist refresh + Gate 2 adversarial audit pending for S02. 75 lib tests pass, clippy clean on HEAD. See `phases/seal/SESSION-02-HANDOFF.md`. |
| P03 — Tier B pt1: ELF + hook page | — | 5 | NOT_STARTED | feat/P03-tier-b-part1 | — | — |
| P04 — Tier B pt2: trampoline + lock-list | — | 5 | NOT_STARTED | feat/P04-tier-b-part2 | — | — |
| P05 — CLI + docs + on-device | — | 5 | NOT_STARTED | feat/P05-cli-docs | — | — |

Status values:

- `NOT_STARTED` — no work begun
- `IN_PROGRESS` — tasks partially done within a segment
- `BLOCKED` — prerequisite not met
- `SEGMENT_COMPLETE` — all tasks in segment done with self-audit Notes filled
- `COMPLETE` — final segment done AND Gate 2 PASS from BOTH agents
- `NEEDS_FIX` — self-audit caught issue OR Gate 2 reported CRITICAL/MAJOR

## 5. Dependency Graph

```text
                    ┌── P02 (Tier A) ─────────────────┐
P01 (foundation) ───┤                                 ├── P05 (CLI + docs + on-device)
                    └── P03 (Tier B pt1) ── P04 ──────┘
```

Parallel tracks after P01:

- Track A: P02 (one session)
- Track B: P03 → P04 (two sessions)

P05 joins both tracks — requires P02 and P04 both COMPLETE.

## 6. Key Paths

| Artifact | Path |
|----------|------|
| Phase specs | `phases/seal/` |
| Phase checklists | `phases/seal/checklists/` |
| Audit reports | `phases/seal/audits/` |
| Hot-load references | `phases/seal/references/` |
| Session prompt | `.claude/system-prompt.md` |
| Source plan | `~/.claude/plans/i-was-wondering-can-bubbly-duckling.md` |
| Library source | `crates/resetprop/src/` |
| CLI source | `crates/resetprop-cli/src/` |
| Per-crate tests | `crates/resetprop/tests/` |
| On-device harness | `tests/device-stress-test.sh` |
| Build script | `build.sh` |
| Docs | `README.md`, `.analysis/`, `phases/seal/references/` |
| AOSP source tree | `/home/president/aosp-android15/` (read-only reference) |

## 7. Session Log [APPEND-ONLY]

| Date | Session | Phase.Segment | Outcome | Artifacts |
|------|---------|---------------|---------|-----------|
| 2026-04-18 | S01 — "fire up P01" | P01 / — | IN_PROGRESS (3 of 5 tasks complete) | Branch `feat/P01-foundation` 9 commits ahead of `main`. T1 shipped seal module skeleton + 7 error variants + SealRecord/SealTier (65b5a25, b0917f2, 07d9238). T2 shipped `/proc/pid/maps` parser + 3 unit tests (fa02dc3, 2ad4557). T3 shipped ptrace constants + UserPtRegs (272 B, aarch64-asserted) + ptrace_seize/interrupt/wait_stop/getregset/setregset/ptrace_detach with yama EPERM classification + 6/6 SAFETY pairing (3477933, 0d30d9f). Self-audit gates 1–3 filled with Optimality/Completeness/Correctness notes (6982944, 67b9848, plus this commit). 63 unit tests pass; zero regressions vs T0 baseline 58. Handoff: next session begins at T4 (`remote_syscall` injector) per `phases/seal/SESSION-01-HANDOFF.md`. |
| 2026-04-18 | S01 — "fire up P02" | P02 / — | IN_PROGRESS (4 of 5 tasks complete) | Branch `feat/P02-tier-a` cut from P01 tip `24c7cd1`. Five commits shipped: T1 `find_arena_mapping` + 3 unit tests (690e606); T2 refactor clippy cleanup (d96d68c) + `ptrace_peektext`/`ptrace_poketext` + `ARM64_NOP` + `find_nop_slide` + `read_remote`/`write_remote` viz bump + 4 tests (8ff023b); T3 `RemoteAttach` RAII detach guard + `RemapFlags` + `remote_remap_private` bootstrap flow (libc.text NOP slide → POKEDATA svc+brk → MAP_PRIVATE\|MAP_ANON RWX page → openat/mmap/close via `remote_syscall` with intentional bootstrap page leak) + 3 tests (cb65fad); T4 thin orchestrators `seal_arena`/`unseal_arena`/`_with_mirror` + `OnceLock<Mutex<Vec<SealRecord>>>` registry + `PropSystem::seal_arena`/`unseal_arena` with `properties_serial` guard reusing `SERIAL_FILE` constant + mirror path via REGISTRY-locked convention + `pub use seal::{SealRecord, SealTier}` + 3 unit tests (bd1c7d6). Mid-session restructure: P02 spec's T2/T3 wording assumed P01 shipped `attach`/`stage_svc`/`restore_scratch` helpers; actual P01 surface exposes 6 primitives + `remote_syscall` with internal svc+brk staging. Task boundaries rebalanced to add POKEDATA path (user-approved option) without exceeding the 5-task cap. All SAFETY pairings filled, zero new error variants, zero `chmod`/`fchmod`/`fchown`/`ftruncate` calls verified via grep, 75 lib tests pass (63 P01 baseline + 12 P02), `cargo clippy -p resetprop --no-deps --lib -- -D warnings` clean. REGISTRY §1 row 35 variant count unchanged at 9. Next session picks up at T5 integration smoke test, then checklist refresh, then Gate 2 adversarial audit. See `phases/seal/SESSION-02-HANDOFF.md`. |
| 2026-04-18 | S02 — "close P01 to COMPLETE" | P01 / — | COMPLETE | T4 shipped `remote_syscall` 9-step injector with 12/12 SAFETY pairing + `read_remote`/`write_remote` partial-transfer loops (e9da006, 2cfb549, f91ea5b). T5 shipped `ptrace_core_smoke.rs` integration test — gated `#![cfg(target_arch = "aarch64")]` because the test executes real ARM64 `svc #0 ; brk #0` bytecode that cannot run on x86_64 hosts; verified on-device (aarch64 Android 15, `u:r:su:s0` root, no yama) with 3 consecutive `1 passed` runs at 0.06s each, zero flakiness (77839ec, aa7835e, 9fab6f8). Gate 2 round 1 surfaced 4 distinct MAJOR findings across code-reviewer + critic: `PTRACE_O_TRACESYSGOOD` missing on SEIZE, `wait_stop` lacks event-byte validation at the contract boundary, `Error::PtraceAttach` overloaded as catch-all, ARM64/NR constants leaked as `pub` — all addressed in fix commits 684f551 (REGISTRY amendment: 7→9 error variants), 6fc6b48 (ptrace hardening: TRACESYSGOOD + wait_stop(pid, expected_event) + PtraceAttach/PtraceOp/PtraceUnexpectedStatus split + visibility downgrade + write_remote SAFETY fix), 3843209 (maps.rs path whitespace preservation via splitn). Gate 2 round 2 PASS from both agents; 2 new MINORs (m5 stale checklist citations, m6 `linux-arm64-abi.md:213` VMA claim) fixed in phase-close docs commit. Branch `feat/P01-foundation` 22+ commits ahead of `main`. TC-01..TC-09 green, FR-01..FR-29 annotated. Next: P02 (Tier A arena-level seal) OR P03 (Tier B pt1 ELF+hook page) — both can proceed in parallel per §5 dependency graph. |
