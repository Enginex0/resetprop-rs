# Consistency Audit — Gate 1 (Re-run after remediation)

## Summary

- Checks run: 19 original + 4 new structural checks = 23
- Previous: 3 FAIL, 5 WARN, 11 OK → this re-run: **0 FAIL, 1 WARN, 22 OK** (previous OK findings preserved).

## Remediation Verification (against previous finding list)

### FAIL findings (from previous audit) — all resolved

- **[Check #18 — previously FAIL]** `properties_serial` rejection guard asymmetry between P02 and P04.
  - Status: **RESOLVED**.
  - Evidence:
    - REGISTRY §1 row 43 now explicitly locks the guard for BOTH tiers: "`properties_serial` name guard applies to BOTH tiers | `PropSystem::seal` (Tier B) AND `PropSystem::seal_arena` (Tier A) must reject any name that resolves to the `properties_serial` file".
    - `phases/seal/P04-tier-b-part2.md:55` (Task 1/2/3 encoder submodule — clean), Task 5 line 59 explicitly carries "first rejects `properties_serial` resolution with `Error::InvalidKey` BEFORE any ptrace work (guard matches P02 `seal_arena`)".
    - `phases/seal/P04-tier-b-part2.md:68` (Approach item 6) inlines the mandate with REGISTRY §1 and `aosp-property-system.md §11` citations.
    - `phases/seal/checklists/P04-checklist.md:72` (Task 5 implementation row), FR-22a at line 120, Canonical Values row at line 170 — all three add the guard requirement with the REGISTRY citation.
  - Conclusion: cross-tier consistency achieved; `PropSystem::seal` now rejects `properties_serial` in the same style as `PropSystem::seal_arena`.

- **[Check #19 — previously FAIL]** Undefined `resolved_arena` variable in P04 Task 5.
  - Status: **RESOLVED**.
  - Evidence: `grep "resolved_arena" phases/seal/P04-tier-b-part2.md phases/seal/checklists/P04-checklist.md` returns **0 hits** (only match in repo is in the prior audit file itself, which documents the original finding).
  - P04 spec Task 5 line 59 now binds the variable explicitly: "`let arena_path = self.context.as_ref().ok_or(Error::NotFound)?.resolve(name).ok_or(Error::NotFound)?.to_string();` from `PropertyContext::resolve` (`context.rs:367-376`)". The `SealRecord` push at the same line uses `arena_path` as the bound name.
  - P04 checklist Task 5 mirrors the exact same binding (line 72). Reader implementing P04 in isolation now has an explicit, cited derivation step.

- **[Check #2 — previously FAIL]** P04 Task 4 unit test unimplementable against declared `seal_prop` signature.
  - Status: **RESOLVED**.
  - Evidence: `grep "build_hook_body_bytes" phases/seal/P04-tier-b-part2.md phases/seal/checklists/P04-checklist.md` returns hits in **both** files.
    - P04 spec Task 2 (line 56) introduces `pub fn build_hook_body_bytes(lock_list_vaddr, saved_prologue_vaddr, return_addr) -> Vec<u8>` as a pure encoder helper: "operates on a local `Vec<u8>`, takes 3 parameters, is pure (no ptrace, no `process_vm_writev`), and is unit-testable without a tracee".
    - P04 spec Task 3 (line 57) has `install_trampoline` explicitly reuse the same helper: "calls `build_hook_body_bytes(lock_list_vaddr, saved_prologue_vaddr, return_addr)` then writes the bytes at `hook_page + HOOK_BODY_OFFSET` and the 16-byte trampoline at `handle.target_fn`".
    - P04 spec Scope "Files to MODIFY" line 26 explicitly names the helper: "pure deterministic helper `build_hook_body_bytes(...)` generating strcmp-loop hook body — no ptrace, unit-testable".
    - P04 checklist Task 2 line 38, Task 3 line 50, FR-07 line 94, FR-07a line 95 (pure-function affirmation), FR-13 line 104 (write-order invariant), TC-05 line 140 and TC-05a line 141 (pure roundtrip test without ptrace) all reference and pin the new helper.
  - Conclusion: the Task 4 lock-list unit test is now implementable via `build_hook_body_bytes` (pure, buffer-level) decoupled from the remote `install_trampoline` installer. Task 4's `test_lock_list_append_then_remove` still operates on a fake 1024-byte `Vec<u8>` and is reachable via the same pure-seam design.

### WARN findings (from previous audit)

- **[Check #3 — previously WARN, now RESOLVED]** Dependency-graph drift — P04 Preconditions required P02.
  - Status: **RESOLVED**.
  - Evidence: `grep "P02 COMPLETE" phases/seal/P04-tier-b-part2.md` returns **0 hits**. P04 Preconditions (lines 9-12) now list only:
    1. "P03 (Tier B pt1: ELF + hook page) shows COMPLETE in REGISTRY §4"
    2. Files-must-exist set, noting `seal/mod.rs` "(exposes `SealRecord`, `SealTier` defined by P01)"
    3. "`seal/mod.rs` registry accessor … defined by P01; P02 and P04 are independent consumers per REGISTRY §5 parallel tracks"
    4. "Branch `feat/P03-tier-b-part1` merged to main"
  - REGISTRY §5 graph (lines 106-119) already shows P02 as Track A and P03→P04 as Track B in parallel, both converging only at P05. P04's preconditions now match the graph. No silent serialization.

- **[Check #4 — previously WARN, now RESOLVED]** `LDR_X16_PC8` opcode not locked in REGISTRY.
  - Status: **RESOLVED**.
  - Evidence: REGISTRY-P.md row 42: "| Trampoline LDR opcode for `ldr x16, [pc, #8]` | `LDR_X16_PC8 = 0x58000050` | references/arm64-a64-encoding.md §trampoline_to |". Gate 2 agents can now cite REGISTRY §1 as the canonical authority for this opcode.

- **[Check #2 `mod.rs` CREATE ambiguity — previously WARN, now RESOLVED]** `SealRecord` / `SealTier` ownership.
  - Status: **RESOLVED**.
  - Evidence:
    - REGISTRY-P.md row 39: "`SealRecord` and `SealTier` types created by P01 | Types defined in `crates/resetprop/src/seal/mod.rs` (P01 scope); P02 populates `SealTier::Arena` records, P04 populates `SealTier::Prop` records | Avoids ownership ambiguity between P01/P02/P04".
    - P01 Task 1 line 54 now includes explicit creation: "Inside `seal/mod.rs` also declare the public types `pub struct SealRecord { … }` and `pub enum SealTier { Arena, Prop }` (field layout locked by REGISTRY §1 rows …); these types are created here so P02 (Tier A) and P04 (Tier B) can construct records without any definitional ambiguity."
    - P01 checklist Task 1 line 27 mirrors the declaration as a deliverable.
    - P01 Anti-Scope line 100 flipped: "`SealRecord`, `SealTier` types ARE declared in this phase (Task 1) per REGISTRY §1 row …".
    - P02 Scope line 35 no longer hedges — reads: "`SealRecord` and `SealTier` types are defined by P01; P02 constructs `SealTier::Arena` records only."
    - P02 checklist (line 10 preconditions), P04 spec line 10, P04 checklist line 13 all attribute definition to P01.
  - Conclusion: unambiguous CREATE-owner. No downstream phase can silently re-define the types.

- **[Check #14 — previously WARN, now RESOLVED]** P05 External API Verification was NO but checklist demanded YES-partial.
  - Status: **RESOLVED**.
  - Evidence: P05 spec line 39 now reads "**Required**: YES" with source line 40: "`phases/seal/references/resetprop-rs-integration.md` §11 (the CLI parser pattern documentation, including the `--nuke|-nk` template at `crates/resetprop-cli/src/main.rs:50-53` and `--stealth|-st` template at `crates/resetprop-cli/src/main.rs:54`)". P05 checklist Gate 2 block (line 237) now coherently requires agents to verify the template.

### WARN (still open)

- **[Check #5 — previously WARN, STILL OPEN]** Orphaned "future phase" / "future release" anti-scope references without phase-number citations.
  - Locations (confirmed still present):
    - `phases/seal/P03-tier-b-part1.md:111` — still reads: "No `propdetect` heuristics for the Tier B signature (future release, per plan §Touchpoints)".
    - `phases/seal/checklists/P03-checklist.md:188` — still reads: "AS-08: No `propdetect` heuristics for the Tier B signature (future release) (per P03 spec §Anti-Scope)".
    - `phases/seal/P05-cli-docs.md:141` — still reads: "AS-02: No persistence of seals to disk — `SealRecord` stays in-memory only; `--replay-seals` is a future-phase flag (per plan §Persistence across reboots deferred)".
  - Partial progress noted: the P02 spec (§Anti-Scope AS-09 at line 121), P04 checklist line 177, and P02 checklist AS-05 line 183 have been tightened to cite REGISTRY/plan deferral sections rather than "future phase" (verified via grep — those specific lines no longer carry the orphaned phrase).
  - Issue: three loci remain with the literal "future release" / "future-phase" phrasing without a concrete phase number; two of them (`P03-tier-b-part1.md:111`, `checklists/P03-checklist.md:188`) were explicitly flagged in the previous audit. The `P05-cli-docs.md:141` instance is also flagged in the previous audit list.
  - Severity: WARN (not FAIL) — the deferral intent is correct and the v1 release is not ambiguous; the inconsistency is purely in the phrasing of the citation style. Gate 2 persona prompts cite REGISTRY §1 as the deferral authority, so agents will not be confused.
  - Required fix (to clear the WARN): replace the three remaining occurrences with either "(deferred per plan §Decisions locked)" or "(deferred — post-v1, per plan §Touchpoints for propdetect)" or an explicit phase-number citation. Exactly as the previous audit recommended.

## New Structural Checks

- **[Check #20]** Gate 2 path in all 5 checklists — **PASS**.
  - `grep -c "audit-prompts.md" phases/seal/checklists/*.md` → 0 across all five checklists.
  - `grep -c ".claude/system-prompt.md §Gate 2" phases/seal/checklists/*.md` → 1 in each of P01, P02, P03, P04, P05 checklists (all Gate 2 blocks now cite the system prompt as the inlined source).
- **[Check #21]** Rule 1 (exactly 5 tasks) preserved across all 5 specs and all 5 checklists — **PASS**.
  - `grep -c '^\d+\. \*\*Task \d+' phases/seal/P0*.md` → 5 per spec file (25 total across P01–P05).
  - `grep -c '### Task \d+:' phases/seal/checklists/*.md` → 5 per checklist (25 total).
  - `grep -c 'Self-Audit Gate \d+' phases/seal/checklists/*.md` → 5 per checklist (25 gates).
  - Remediation introduced no new tasks; the existing P04 Task 4 split was effected entirely inside Task 2/Task 3/Task 4 boundaries (Task 2 now owns the pure helper, Task 3 owns the installer, Task 4 owns the lock-list mechanics) — still 5 tasks.
- **[Check #22]** P04 IV items no longer claim consumption from P02 — **PASS**.
  - P04 checklist IV-02 (line 147) now reads: "Consumes `SealRecord`, `SealTier::{Arena, Prop}`, and the shared in-memory registry defined by **P01** in `seal/mod.rs` — P04 is on a parallel track with P02 per REGISTRY §5". No P02 dependency edge.
  - IV-01 / IV-03 / IV-04 cite P03 and P01 only. IV-05 cites downstream P05 (leaf).
  - P04 spec "Preconditions" and "Approach item 5" (line 67) both re-iterate the parallel-track framing; no line claims Tier A/P02 as a consumer dependency for Tier B/P04's SealRecord registry.
- **[Check #23]** REGISTRY §5 graph coherence with all spec preconditions — **PASS**.
  - REGISTRY §5 edges: P01 → {P02, P03}; P03 → P04; {P02, P04} → P05.
  - P01 Preconditions: none. ✓
  - P02 Preconditions: P01 only. ✓
  - P03 Preconditions: P01 only. ✓
  - P04 Preconditions: P03 only (plus P01-sourced types/registry accessor). ✓
  - P05 Preconditions: P02 + P04 (both fan-in, consistent with graph). ✓
  - All five phases' precondition blocks agree with the graph.

## OK (unchanged — re-verified)

- [Check 1] REGISTRY §1 locked-decision coherence with phase specs — unchanged, still holds.
- [Check 6] No orphaned or dead phases — unchanged, still holds.
- [Check 7] Rule 1 compliance (5 tasks per phase) — re-verified above as Check #21.
- [Check 8] Rule 2 compliance (self-audit notes empty placeholders) — re-verified; the Gate 2-block remediation did not touch self-audit gates.
- [Check 9] Rule 3 compliance (phase-end adversarial audit section in every checklist) — re-verified; Gate 2 path replacement (Check #20) preserved the block structure.
- [Check 10] Branch name consistency — unchanged, still holds.
- [Check 11] No new surprise-dependency between phases — re-verified.
- [Check 12] CLI flag consistency — unchanged, still holds.
- [Check 13] Canonical Values coverage — strengthened by WARN #4 resolution (LDR_X16_PC8 now in REGISTRY §1).
- [Check 15] Reference Material reality check — unchanged.
- [Check 16] Status value consistency — unchanged.
- [Check 17] Audit-prompt inlining — `.claude/system-prompt.md` remains the inlined authority; all five checklists now cite it (Check #20 above). The persona-prompt bodies still match `/home/president/.claude/skills/Advanced-planning/references/audit-prompts.md` byte-for-byte except for the expected `{slug}` → `seal` substitution.

## Verdict

VERDICT: NEEDS_FIX (0 FAIL, 1 WARN)

Breakdown:

- 0 FAIL items. All three FAIL items from the previous audit are fully resolved with verifiable grep evidence.
- 1 WARN item remaining: Check #5 "future phase" / "future release" orphaned phrasing at `P03-tier-b-part1.md:111`, `checklists/P03-checklist.md:188`, and `P05-cli-docs.md:141`. This is cosmetic citation-style drift, not a semantic contradiction. It can be cleared by search-and-replace on the three lines noted.
- 22 OK items (the 11 original OKs + WARN #2 SealRecord ownership resolved + WARN #3 dependency graph resolved + WARN #4 LDR_X16_PC8 resolved + WARN #14 External API flip + FAIL #18 / FAIL #19 / FAIL #2 resolved + new structural checks #20–#23 all PASS).

Recommendation: a single targeted patch that rewrites the three remaining "(future release)" / "(future-phase flag)" phrases to cite the plan §Decisions locked deferral (or to name a concrete phase) would take the verdict to PASS. Alternatively, if the maintainers deem the current phrasing acceptable because the deferral authority (plan §Persistence, plan §Touchpoints for propdetect) is already linked in the same parenthetical, the WARN can be justified-and-waived in the Gate 2 persona prompt. Either path is acceptable; the substance of the audit is PASS on all safety/correctness dimensions.
