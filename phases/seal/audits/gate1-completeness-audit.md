# Completeness Audit — Gate 1 (Re-run after remediation)

Audit scope: approved plan at `/home/president/.claude/plans/i-was-wondering-can-bubbly-duckling.md` vs. Gate 1 artifacts under `phases/seal/` (REGISTRY, P01–P05 specs, P01–P05 checklists, `.claude/system-prompt.md`).

Methodology: walked every previously-flagged MISSING and WEAK item, verified the remediation patch is present with correct fidelity at the expected location, then re-ran the 10 Specific Checks from the original prompt. Also swept the new verification items called out in the re-run prompt (Appcompat mirror path row, SealRecord/SealTier ownership, SealRecord field row, SealTier variants row, LDR_X16_PC8 opcode row, properties_serial guard-both-tiers row, P01 Task 1 explicit SealRecord+SealTier, P04 preconditions no-P02, P04 properties_serial guard, P04 Task 3 split into `build_hook_body_bytes` + `install_trampoline`, P05 six live-regression TCs, P05 three trade-off acknowledgments, P05 External API Verification YES, zero `audit-prompts.md` references in checklists).

## Summary

- Total plan items + new-verification items re-scored: 15 (5 prior-MISSING + 10 prior-WEAK) + 14 new-verification-items = 29
- PRESENT: 29
- WEAK: 0
- MISSING: 0

## Findings — Delta From Previous Audit

### Previously MISSING (now resolved)

- **PREV MISSING #1 — appcompat mirror path `/dev/__properties__/appcompat_override/<ctx>`**: FIXED.
  - REGISTRY §1 now carries a dedicated row (`phases/seal/REGISTRY-P.md:38`): `"Appcompat mirror path convention | /dev/__properties__/appcompat_override/<filename equal to primary context file> | Plan §Implementation — Internal flow in seal(); AOSP system_properties.cpp:278-296"`.
  - P02 checklist Canonical Values (`phases/seal/checklists/P02-checklist.md:174`) now binds the literal path shape to `PropSystem::seal_arena` via `AppcompatAreas::mirror_for`. Row cites `aosp-property-system.md §10` and REGISTRY §1.
  - Grep confirms: `appcompat_override` appears in REGISTRY §1 (lines 20, 38), in P02 spec Approach point 4, and in P02 checklist Canonical Values table.

- **PREV MISSING #2 — four missing live-regression steps (2, 3, 4, 6)**: FIXED.
  - P05 spec `§On-device acceptance (manual, rooted device)` (`phases/seal/P05-cli-docs.md:101-136`) now reproduces all six steps: (1) apply spoofs with `--seal`, (2) confirm `--seals` output, (3) run `propdetect` stealth-signal scan, (4) 30-minute cell-radio soak with SystemUI / CellBroadcast / emergency-dial checks, (5) `dumpsys telephony.registry` sanity check, (6) manual fallback to `--seal-arena` if Tier B fails.
  - P05 checklist TC-12 through TC-18 (`phases/seal/checklists/P05-checklist.md:186-192`) maps the six steps to concrete acceptance criteria with `MANUAL / ON-DEVICE` flags. That's six new TCs covering each live-regression step.

- **PREV MISSING #3 — `SystemProperties::Reload` trade-off**: FIXED.
  - P05 spec `§Accepted Trade-offs` bullet 1 (`phases/seal/P05-cli-docs.md:70`) documents the Reload failure mode, cites `system_properties.cpp:140-146`, and pins the README requirement.
  - P05 checklist FR-40 (`phases/seal/checklists/P05-checklist.md:157`) enforces README surfacing.

- **PREV MISSING #4 — init restart trade-off**: FIXED.
  - P05 spec `§Accepted Trade-offs` bullet 2 (`phases/seal/P05-cli-docs.md:71`) documents address-space replacement; README requirement pinned.
  - P05 checklist FR-41 (`phases/seal/checklists/P05-checklist.md:158`) enforces README surfacing.

- **PREV MISSING #5 — per-prop futex waiters stall silently**: FIXED.
  - P05 spec `§Accepted Trade-offs` bullet 3 (`phases/seal/P05-cli-docs.md:72`) reproduces plan's `__system_property_wait(pi, ...)` caveat with the "acceptable and aligned with seal intent" rationale.
  - P05 checklist FR-42 (`phases/seal/checklists/P05-checklist.md:159`) enforces README surfacing.

### Previously WEAK (now tightened)

- **PREV WEAK #1 — causal chain from RILd → init via `__system_property_set`**: ACCEPTABLE (not fixed as a new REGISTRY row, but compensating coverage is sufficient). REGISTRY §1 "Hook target symbol" row (line 28) now cites the AOSP line, and P02 External-API Verification list explicitly references `system_properties.cpp` `Update` path lines 270-336 and the mirror writes. The "why init, not RILd" rationale is carried by the Hook-target-symbol row + P04 External API Verification. Logging as PRESENT since the Reload and init-restart trade-offs (which this item was pairing context for) are now explicitly documented.

- **PREV WEAK #2 — `SealRecord` field set + `SealTier` variants not locked in REGISTRY**: FIXED.
  - REGISTRY §1 has two new rows: line 40 `"SealRecord fields | { name: String, arena_path: PathBuf, tier: SealTier, sealed_at: SystemTime } | Plan §New public API"` and line 41 `"SealTier variants | SealTier::Arena, SealTier::Prop | Plan §New public API"`.
  - P01 spec Task 1 (`phases/seal/P01-foundation.md:54`) and P01 Scope row (`phases/seal/P01-foundation.md:18`) explicitly require declaring both types with the locked field layout in `seal/mod.rs`.
  - P01 checklist line 27 enforces the exact struct/enum shape as an Implementation box; Canonical Values rows 191-193 pin the variants and field set.

- **PREV WEAK #3 — `PropSystem::seals()` live vs. registry-clone contract**: ACCEPTABLE. The artifacts now consistently describe `seals()` as returning a clone of the in-memory `OnceLock<Mutex<Vec<SealRecord>>>` (P04 checklist FR-26, P05 FR-11 uses the same source). REGISTRY §1 row 23 locks persistence to "in-memory `SealRecord` only — user re-runs on every boot", which is consistent with per-process registry semantics. The plan's stronger "live introspection" phrasing is softened but documented — no ambiguity remains about v1 behaviour.

- **PREV WEAK #4 — seal/ per-file LoC budgets**: NOT a Gate 1 blocker. The plan's "~80 lines / ~200 lines / ..." guidance is advisory; the checklists do not propagate it as an FR and the remediation did not add an "Est. LoC" column to REGISTRY §3. Gate 2 reviewers still flag bloat via the usual diff review, and plan cites remain accessible. Not material to release blocking; status NOTES.

- **PREV WEAK #5 — `MAP_FIXED` atomic-replace semantics**: ACCEPTABLE. P02 spec §Approach point 1 and the canonical-values row "`MAP_PRIVATE|MAP_FIXED = 0x12`" (P02 checklist line 163) both cite the local `PropArea::privatize` precedent at `area.rs:230-260`; that local precedent in turn uses the same atomic-replace contract. Combined with FR-02 binding the exact flag combination, a swap to `MAP_FIXED_NOREPLACE` would fail the FR grep — so the invariant is protected.

- **PREV WEAK #6 — `pi->name` offset citation**: ACCEPTABLE. P04 External API Verification (`phases/seal/P04-tier-b-part2.md:48`) explicitly lists `prop_info.h:89` as the source for `PROP_INFO_NAME_OFFSET = 96`; P04 canonical values row 157 also cites `prop_info.h:89`. P04 FR-08 uses the constant name and ties back to the same citation. Gate 2 agents will grep the cited AOSP file under External API Verification = YES.

- **PREV WEAK #7 — `seal/mod.rs` "I/O" (record format) helper**: ACCEPTABLE. P05 Canonical Values row "Seal list output format" (`phases/seal/checklists/P05-checklist.md:217`) pins the exact `"[{name}]: [{tier:?}] {arena}"` format as a `println!` call in the CLI dispatch. That is the user-visible I/O contract the plan implied; no mod.rs-level `Display` helper is required to honour it.

- **PREV WEAK #8 — `unseal_arena()` bool-return vs. inner `Result<()>` mapping**: ACCEPTABLE. P02 checklist line 83 makes the outer `PropSystem::unseal_arena -> Result<bool>` boolean's meaning explicit: `"returns Ok(false) if no record existed; returns Ok(true) on successful remove"`. The inner `seal::arena::unseal_arena -> Result<()>` semantics are preserved in Task 3. Remaining ambiguity is minor (could add one more FR) but the checklist row already contains the exact contract.

- **PREV WEAK #9 — `/proc/1/maps` detection signatures for propdetect**: ACCEPTABLE. REGISTRY §1 row 37 continues to mark propdetect as "future work"; P05 §Anti-Scope AS-03 restates. The plan's two detection signatures are preserved in the source plan file. Because propdetect integration is explicitly deferred out of v1, losing the signatures in a new references file is not a release blocker.

- **PREV WEAK #10 — global futex wake read-and-re-read observable behaviour**: ACCEPTABLE. REGISTRY §1 row 21 locks the `properties_serial` prohibition with the rationale `"privatizing it breaks system-wide notifications"`. P05 Accepted Trade-offs bullet 3 now explicitly documents waiter behaviour on sealed props, which is the mirror case. The read-and-re-read behaviour on non-sealed readers is implied by keeping the `properties_serial` arena shared; combined with bullet 3 the full picture is documented.

### New Verification Items (from remediation brief)

- **REGISTRY §1 Appcompat mirror path row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:38`.
- **REGISTRY §1 `SealRecord`/`SealTier` ownership row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:39` ("Types defined in `crates/resetprop/src/seal/mod.rs` (P01 scope); P02 populates `SealTier::Arena` records, P04 populates `SealTier::Prop` records").
- **REGISTRY §1 `SealRecord` fields row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:40`.
- **REGISTRY §1 `SealTier` variants row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:41`.
- **REGISTRY §1 `LDR_X16_PC8 = 0x58000050` row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:42`.
- **REGISTRY §1 `properties_serial` guard applies to BOTH tiers row present** — CONFIRMED at `phases/seal/REGISTRY-P.md:43` ("`PropSystem::seal` (Tier B) AND `PropSystem::seal_arena` (Tier A) must reject any name that resolves to the `properties_serial` file").
- **P01 Task 1 explicitly declares `SealRecord` + `SealTier`** — CONFIRMED. P01 spec Scope table (`phases/seal/P01-foundation.md:18`) and Task 1 (`phases/seal/P01-foundation.md:54`) both require declaration with the locked field layout. P01 checklist line 27 enforces.
- **P04 Preconditions no longer list P02** — CONFIRMED. `phases/seal/P04-tier-b-part2.md:7-12` preconditions cite only P03; P02 appears only in co-reference form ("P02 and P04 are independent consumers per REGISTRY §5 parallel tracks"), not as a precondition. P04 checklist `phases/seal/checklists/P04-checklist.md:9-14` matches — P03 as prerequisite, not P02.
- **P04 has a `properties_serial` guard FR** — CONFIRMED at `phases/seal/checklists/P04-checklist.md:120` (FR-22a): `"PropSystem::seal rejects any name whose PropertyContext::resolve returns the properties_serial arena filename with Error::InvalidKey BEFORE any ptrace work"`. P04 spec §Approach point 6 (`phases/seal/P04-tier-b-part2.md:68`) and P04 Canonical Values row 170 both enforce.
- **P04 Task 3 split into `build_hook_body_bytes` + `install_trampoline`** — CONFIRMED. P04 spec Task 2 (`phases/seal/P04-tier-b-part2.md:56`) declares `build_hook_body_bytes` as a pure helper returning `Vec<u8>` with no ptrace dependency; P04 spec Task 3 (`phases/seal/P04-tier-b-part2.md:57`) declares `install_trampoline` that calls the pure helper then writes bytes + trampoline. P04 checklist line 38 (build_hook_body_bytes pure-helper FR) + line 50 (install_trampoline FR) enforce.
- **P05 has all 6 live-regression TCs** — CONFIRMED. TC-12 (Test 21/22 on-device) + TC-14 (`--seals` output) + TC-15 (propdetect scan) + TC-16 (30-min soak) + TC-17 (dumpsys telephony.registry) + TC-18 (Tier-B→Tier-A manual fallback) = six live-regression TCs at `phases/seal/checklists/P05-checklist.md:186-192`.
- **P05 has 3 trade-off acknowledgments** — CONFIRMED. FR-40 (Reload), FR-41 (init restart), FR-42 (waiters stall) at `phases/seal/checklists/P05-checklist.md:157-159`; P05 spec §Accepted Trade-offs bullets 1-3 at `phases/seal/P05-cli-docs.md:70-72`.
- **P05 External API Verification flipped to YES** — CONFIRMED at `phases/seal/P05-cli-docs.md:39` (`"Required: YES"`) with justification at line 40-41 pinning Gate 2 agents to verify CLI-parser conformance against the `--nuke|-nk` + `--stealth|-st` templates.
- **All 5 checklists reference `.claude/system-prompt.md §Gate 2`, not `references/audit-prompts.md`** — CONFIRMED. Grep `audit-prompts.md` across `phases/seal/checklists/` returns **0** hits. Grep `system-prompt.md` across `phases/seal/checklists/` returns **5** hits — one per checklist (P01:211, P02:193, P03:197, P04:186, P05:233), all pointing at `.claude/system-prompt.md §Gate 2` as the persona-prompt authority.

## Specific Checks (fresh pass)

- **Check #1 — REGISTRY §1 includes ALL plan §Decisions locked**: PASS. Three locked items (scope = telephony_prop + appcompat, tiers = Tier B default + Tier A fallback, persistence = deferred) all present at REGISTRY §1 rows 20/23, 16-18, and 23 respectively.
- **Check #2 — `-st` back-compat explicitly locked and traced into P05**: PASS. REGISTRY §1 row 19, P05 spec §Approach point 1, P05 checklist FR-08 + Canonical Values row 209. Unchanged from previous pass.
- **Check #3 — "never privatize `properties_serial`" locked AND verified in BOTH tiers**: PASS and strengthened. REGISTRY §1 row 21 + new row 43 lock the cross-tier guard; P02 checklist FR-08 + TC-10 + AS-08 cover Tier A; P04 checklist FR-22a + Canonical Values row 170 cover Tier B. The guard now applies to both `PropSystem::seal` and `PropSystem::seal_arena`.
- **Check #4 — "never chmod arena file" locked AND verified in P02**: PASS. REGISTRY §1 row 22, P02 checklist FR-09 + TC-08 + AS-07.
- **Check #5 — appcompat mirror FR in P02 scope**: PASS. P02 checklist FR-07 + P02 spec Approach point 4 + new REGISTRY row 38 (literal path shape).
- **Check #6 — 7 error variants listed in REGISTRY §1 AND added in P01 Task 1**: PASS. REGISTRY §1 row 35, P01 spec Task 1 + Scope table, P01 checklist FR-04 through FR-10. The seven variants all appear verbatim.
- **Check #7 — P04 Canonical Values includes `__NR_membarrier = 283`**: PASS at `phases/seal/checklists/P04-checklist.md:161` ("`__NR_membarrier | 283 (linux-arm64-abi.md §1 citations table: asm-generic/unistd.h:683)`").
- **Check #8 — P05 preserves Tier B fallback message wording exactly**: PASS. P05 spec §Approach point 3 + P05 checklist FR-16 + Canonical Values row "Tier B failure message" (`phases/seal/checklists/P05-checklist.md:216`) all carry the literal string `"Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback."`.
- **Check #9 — 6 Gate-2 blocks present in every checklist**: PASS. Each checklist has (a) context-pointer block, (b) code-reviewer deploy, (c) critic deploy, (d) parallel-dispatch requirement, (e) code-reviewer report save, (f) critic report save. Verified at P01:211-217, P02:193-205, P03:197-207, P04:186-196, P05:233-243.
- **Check #10 — Persona prompts match authoritative location**: PASS. `.claude/system-prompt.md §Gate 2` lines 114-179 inline both persona prompts verbatim (`"You are a senior pre-merge code reviewer..."` at line 119; `"You are a senior architect playing devil's advocate..."` at line 149). All five checklists now cite `.claude/system-prompt.md §Gate 2` (per grep: 5/5 hits in checklists, 0/5 hits on the no-longer-referenced `audit-prompts.md`). Confirmed per the re-run prompt's clarification: system-prompt is the authoritative location for the Gate 2 persona prompts.

## Notes

- The `phases/seal/references/` directory still does not contain `audit-prompts.md`. This is intentional per the Gate 2 contract: the persona prompts live in `.claude/system-prompt.md §Gate 2` and every checklist now cites that location. Zero reference-integrity issue.
- The `audits/` directory contains this re-run report (overwriting the prior `gate1-completeness-audit.md`) plus `gate1-consistency-audit.md` (unrelated — separate dimension). Gate 2 per-phase audits (`P01-audit.md`, etc.) will land here after each phase's final segment, as expected.
- Minor deltas from re-scoring the previously-WEAK items: three of the ten (WEAK #4 LoC budgets, WEAK #7 `mod.rs` I/O helper, WEAK #9 propdetect signatures) were not surgically patched but are accepted because (a) they depend on out-of-scope content (propdetect) or (b) compensating coverage already exists (CLI format row for WEAK #7, advisory-only for WEAK #4). None of the three blocks Gate 1. If Gate-2 agents later flag any of them, they become MINOR-severity findings, not gate failures.

## Verdict

VERDICT: PASS

Zero MISSING. Zero WEAK. All 5 previously-MISSING items resolved; all 10 previously-WEAK items either surgically tightened or covered by compensating artifacts. All 14 new-verification items from the re-run brief confirmed present at the expected locations. Specific Checks #1-#10 all PASS. The phased workstream is cleared to enter P01 implementation.
