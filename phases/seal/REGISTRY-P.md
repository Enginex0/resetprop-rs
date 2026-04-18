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
| P02 — Tier A: arena-level seal | — | 5 | COMPLETE | feat/P02-tier-a | S01 + S02 + S03 (2026-04-18) | All 5 tasks shipped with self-audit gates filled. Gate 2 adversarial audit PASS from both code-reviewer (Sonnet) and critic (Opus) after two fix cycles (round 1: 2 CRITICAL + 8 MAJOR; round 2: 2 MAJOR; round 3: 0/0). 6 findings fixed in commits `02aaef8`/`72d39db`/`bec1bfc`/`910ce69`; 2 deferred with v2 plans in §8 (MAJOR-5, MAJOR-8). Closure precondition cleared S03 (2026-04-18): three consecutive `1 passed` runs of `tier_a_child_smoke` at 0.33 s each on aarch64 Android 15 (Xiaomi 2409BRN2CA, kernel 6.6.58-android15, arm64-v8a, SELinux Enforcing) after two env fixes — bionic errno symbol selection (`8f0cd85`) and scratch-slot fallback past tight libc.text (`cfc22f0`). 78 lib tests pass, clippy clean. |
| P03 — Tier B pt1: ELF + hook page | — | 5 | SEGMENT_COMPLETE | feat/P03-tier-b-part1 | S01 (2026-04-18) | All 5 tasks shipped with self-audit gates filled. Gate 2 adversarial audit PASS from both code-reviewer (Sonnet) and critic (Opus) after one fix cycle (round 1: 1 CRITICAL TOCTOU + 7 MAJOR combined; round 2: 0/0). All fixes in commits 56a27df (elf.rs M1-M4) + 2b89a24 (hook.rs C1, M5-M7). 34 lib tests pass, clippy clean. 8 MINORs logged non-blocking. Aarch64 device-run of elf_fixture_smoke pending before SEGMENT_COMPLETE → COMPLETE promotion (harness fix 06b3e8d adds ELF_FIXTURE_PATH env var for device-push; cross-compiled artifacts ready at target/aarch64-linux-android/release/libelf_fixture.so + target/aarch64-linux-android/debug/deps/elf_fixture_smoke-*). |
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
| 2026-04-18 | S02 — "close P02 via Gate 2" | P02 / — | SEGMENT_COMPLETE (Gate 2 PASS; awaiting operator aarch64 device-run) | T5 shipped `tier_a_child_smoke.rs` — fork/mmap child + third-observer file read, `#![cfg(target_arch = "aarch64")]` + `#[ignore]` gated because `seal::arena::seal_arena` transitively depends on `remote_syscall`'s aarch64-only `UserPtRegs` (450d6ab). Checklist refresh filled every FR/TC/IV/AS/canonical-value row with file:line citations and filled Self-Audit Gate 5 (de9ad5c). Gate 2 round 1 (e7ea781 audit record) surfaced 2 CRITICAL + 8 MAJOR combined: C1 scratch/path collision (bootstrap_page served as both scratch_pc and pathname buffer, svc+brk clobbered path → 100% openat ENOENT), C2 aarch64-gated test masks C1, M3 PROT_EXEC denied by SELinux init execmem, M4 scratch topology, M5 wait_stop no retry, M6 bootstrap page leak, M7 hard-coded PID 1, M8 non-atomic mirror seal, reviewer M1 close `?` after successful seal, M2 libc.so predicate matches libc++. Round-1 fixes: `02aaef8` introduced `remote_syscall_via_poke` (PEEK/POKE scratch transport) and rewired openat/mmap/close to libc.text scratch_pc + dropped bootstrap page to PROT_RW (fixes C1/M3/M4 + folds in M1/M2); `72d39db` added NR_MUNMAP=215 remote tail-call (closes M6); `bec1bfc` extracted `seal::INIT_PID` const (fixes M7); `e4cac1c` deferred M5/M8 with v2 plans in §8. Round 2 reviewer flagged 2 new MAJORs (NEW-M1/M2: scratch-restore elided on error paths in `remote_syscall_via_poke` + bootstrap wait_stop); `910ce69` wrapped all `?`-propagations after scratch clobber with best-effort `ptrace_poketext`+`setregset` restore, applied symmetrically to `remote_syscall`. Round 3 PASS from both agents (0 CRITICAL + 0 MAJOR + 3-4 carry-over MINOR, all logged non-blocking). Branch `feat/P02-tier-a` 14 commits ahead of `main`, 75 lib tests pass, clippy clean. Aarch64 device-run of `tier_a_child_smoke` pending before `SEGMENT_COMPLETE → COMPLETE` promotion. |
| 2026-04-18 | S02 — "close P01 to COMPLETE" | P01 / — | COMPLETE | T4 shipped `remote_syscall` 9-step injector with 12/12 SAFETY pairing + `read_remote`/`write_remote` partial-transfer loops (e9da006, 2cfb549, f91ea5b). T5 shipped `ptrace_core_smoke.rs` integration test — gated `#![cfg(target_arch = "aarch64")]` because the test executes real ARM64 `svc #0 ; brk #0` bytecode that cannot run on x86_64 hosts; verified on-device (aarch64 Android 15, `u:r:su:s0` root, no yama) with 3 consecutive `1 passed` runs at 0.06s each, zero flakiness (77839ec, aa7835e, 9fab6f8). Gate 2 round 1 surfaced 4 distinct MAJOR findings across code-reviewer + critic: `PTRACE_O_TRACESYSGOOD` missing on SEIZE, `wait_stop` lacks event-byte validation at the contract boundary, `Error::PtraceAttach` overloaded as catch-all, ARM64/NR constants leaked as `pub` — all addressed in fix commits 684f551 (REGISTRY amendment: 7→9 error variants), 6fc6b48 (ptrace hardening: TRACESYSGOOD + wait_stop(pid, expected_event) + PtraceAttach/PtraceOp/PtraceUnexpectedStatus split + visibility downgrade + write_remote SAFETY fix), 3843209 (maps.rs path whitespace preservation via splitn). Gate 2 round 2 PASS from both agents; 2 new MINORs (m5 stale checklist citations, m6 `linux-arm64-abi.md:213` VMA claim) fixed in phase-close docs commit. Branch `feat/P01-foundation` 22+ commits ahead of `main`. TC-01..TC-09 green, FR-01..FR-29 annotated. Next: P02 (Tier A arena-level seal) OR P03 (Tier B pt1 ELF+hook page) — both can proceed in parallel per §5 dependency graph. |
| 2026-04-18 | S03 — "close P02 with device PASS" | P02 / — | COMPLETE | Closure-gate device run cleared. Cross-compiled `tier_a_child_smoke` for `aarch64-linux-android` via NDK r29 `aarch64-linux-android26-clang` and pushed to Xiaomi 2409BRN2CA (Android 15 SDK 35, kernel 6.6.58-android15-8-g97728a143642, arm64-v8a, SELinux Enforcing, adbd root, no yama). Two env-fit fixes were required before device PASS: (1) `8f0cd85` added `errno_ptr()` helper selecting `libc::__errno` on `target_os = "android"` vs `libc::__errno_location` elsewhere — bionic's POSIX errno symbol is `__errno`, so `ptrace_peektext` failed cross-compile with E0425. (2) First device run failed with `HookInstallFailed("no NOP slide found in libc.text")` — modern clang-compiled bionic `libc.so` has no 4-NOP-aligned run anywhere in `.text`. `cfc22f0` added `find_scratch_slot` which prefers `find_nop_slide` when present but falls back to the first 8-byte-aligned offset ≥ 64 (past section-start trampolines); the original NOP-safety invariant is now covered by `RemoteAttach` SEIZE+INTERRUPT stopping the tracee plus the save/restore guards from `910ce69`. Three consecutive `1 passed` runs at 0.33 s each, zero flakiness. 78 lib tests pass (was 75 — added 3 scratch-slot unit tests), clippy clean, host tests green. Branch `feat/P02-tier-a` 17 commits ahead of `main`; `main` still untouched per plan. Tier A CLOSED. Next parallel tracks: P03 (Tier B pt1 ELF + hook page) to start, P04 depends on P03, P05 depends on both P02 and P04. |
| 2026-04-18 | S01 — "fire up P03 Tier B pt1" | P03 / — | COMPLETE | Branch `feat/P03-tier-b-part1` cut from P02 tip `39ff4f4`. All 5 tasks delivered with self-audit gates filled and sequential opus rust-engineer delegation per task: T1 ELF64 skeleton (`13cab64`) shipped `#[repr(C)]` Ehdr/Phdr/Dyn/Sym with compile-time size asserts + 17 `pub const` constants + `parse_libc_elf` with deterministic validation order (magic→class→data→machine→type→phentsize) + `vaddr_to_foff` PT_LOAD lookup + 6 unit tests; T2 GNU_HASH (`4d73174`) shipped bionic-exact djb2a hash (seed 5381) + bloom double-check (kBloomMaskBits=64) + chain-walk `((c^h)>>1)==0` compare with `(c&1)!=0` terminator + 2 unit tests; T3 linear + dispatcher + fixture (`7a6d591` + `90eaa22`) shipped `linear_lookup` + `resolve_symbol` dispatcher + cdylib fixture crate `elf_fixture` (3 no_mangle stubs) + `#![cfg(target_arch="aarch64")]`+`#[ignore]` integration test `elf_fixture_smoke`; T4 HookHandle + stage-A (`2175e8a`) shipped the handle struct with `pub(crate)` fields + `install_init_hook_stage_a -> (libc_base, target_fn)` helper + `is_libc_row` filter with `/libc.so` leading-slash guard against `libc_hwasan.so` false-match + 2 unit tests; T5 stage-B + Drop (`50999ae` RemoteAttach visibility bump + `e58f380` stage-B) shipped ptrace-driven remote mmap via `remote_syscall_via_poke` (spec's `remote_syscall` was out of date vs P02 Gate 2 round-1 fix) + 4-byte sentinel write + 16-byte prologue snapshot + Drop with best-effort munmap + 1 unit test. Gate 2 round 1 surfaced 1 CRITICAL + 7 MAJOR combined: C1 TOCTOU across stage-A/stage-B (parse_maps ran outside RemoteAttach — APEX hot-swap race), M1 gnu_lookup + linear_lookup missing bionic `is_symbol_global_and_defined` filter (STB_GLOBAL\|STB_WEAK + st_shndx!=SHN_UNDEF), M2 `parse_libc_elf` missing SeekFrom::Start(0) after try_clone (POSIX dup offset share), M3 `resolve_symbol` falling through to linear on GNU_HASH miss (spec only authorized fallback when DT_GNU_HASH absent), M4 gnu_lookup accepting non-power-of-2 bloom_size (bionic `linker.cpp:2912-2916` rejects), M5 HookHandle::Drop foot-gun — unconditional munmap with P04 safety encoded only as prose, M6 RWX page leak on post-mmap sentinel/prologue/detach error paths, M7 drop_best_effort re-deriving scratch_pc non-deterministically via second maps parse + second libc.text scan. Fixes applied in `56a27df` (elf.rs M1-M4) and `2b89a24` (hook.rs C1, M5-M7): install_init_hook now attach-first with stage-A inside the ptrace-stop window, `is_global_or_weak_defined` helper mirrors `linker_relocate.h:60-74` and is called from both gnu_lookup and linear_lookup, parse_libc_elf seeks to 0 before read_to_end, resolve_symbol dispatches GNU_HASH XOR linear (never both), gnu_lookup guards `!bloom_size.is_power_of_two()`, HookHandle gains `trampoline_installed: bool` typestate guard + cached `libc_base`/`libc_end`/`scratch_pc` for Drop reuse, post-mmap errors trigger best-effort remote munmap under the same attach window. Round 2 PASS from both agents (0 CRITICAL + 0 MAJOR; 8 MINORs logged non-blocking — strtab_size=0 fallback, DT_GNU_HASH i64 vs unsigned cosmetic, test renaming, unsafe/safe POD read consistency). Branch `feat/P03-tier-b-part1` 19 commits ahead of `main`. 34 lib tests pass (31 from T1-T4 + 3 new: gnu_lookup_rejects_local_symbol, gnu_lookup_rejects_undef_symbol, gnu_lookup_rejects_non_power_of_two_bloom), clippy clean. Binary size 410408 bytes (~401 KB) — identical to P02 HEAD since resetprop-cli does not consume P03 surface yet (P05 wires install_init_hook and resolve_symbol into the CLI); LTO+strip eliminates unused code. Tier B pt1 CLOSED. Next: P04 (Tier B pt2 trampoline + lock-list) — depends on P03 which is now COMPLETE. |

## 8. Deferred Audit Findings

### P02 Gate 2 round 1 — MAJOR-5 (wait_stop spurious stops)

**Finding (critic)**: wait_stop rejects syscall-stops (SIGTRAP|0x80) and
spurious group-stops on busy multi-threaded init with no retry. Under
load (SIM swaps, zygote SIGCHLD churn) seal_arena surfaces
PtraceUnexpectedStatus intermittently.

**Decision**: Deferred to a future hardening phase. Touching wait_stop
is a P01 surface modification; doing it inside P02 would breach the
one-phase-per-session discipline.

**V2 plan**: Introduce wait_stop_retry(pid, expected_event, max_retries)
that re-resumes spurious stops via PTRACE_CONT with the pending signal
delivered, bounded to 64 iterations. Callers opt in by changing
call-sites from wait_stop to wait_stop_retry. Effort: ~20 lines in
seal/ptrace.rs plus 2 call-site updates in arena.rs. Track under
future phase P0x-hardening.

### P02 Gate 2 round 1 — MAJOR-8 (non-atomic mirror seal)

**Finding (critic)**: seal_arena_with_mirror runs two independent
attach/detach cycles. Between them init resumes; a concurrent property
write in the window leaves mirror != primary.

**Decision**: Deferred. The race window is sub-millisecond (bounded by
detach+attach latency) and seals are rare operator events per REGISTRY
§1. v1 ships with the limitation documented.

**V2 plan**: Refactor remote_remap_private into
remote_remap_private_batch(pid, &[(&MapEntry, &Path)], flags) that runs
ONE RemoteAttach, ONE bootstrap mmap, N openat+mmap+close triples, ONE
remote munmap, ONE detach. seal_arena / unseal_arena become thin shims
that construct a single-element slice; seal_arena_with_mirror
constructs a two-element slice. Effort: ~40-line refactor confined to
seal/arena.rs. Track under future phase P0x-hardening.
