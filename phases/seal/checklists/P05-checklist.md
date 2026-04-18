# P05 — CLI, Docs, and On-Device Acceptance — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [ ] P02 (Tier A: arena-level seal) shows COMPLETE in REGISTRY §4
- [ ] P04 (Tier B pt2: trampoline + lock-list) shows COMPLETE in REGISTRY §4
- [ ] `PropSystem::seal_arena` and `PropSystem::unseal_arena` exist in `crates/resetprop/src/lib.rs` (from P02)
- [ ] `PropSystem::seal`, `PropSystem::unseal`, `PropSystem::seals` exist in `crates/resetprop/src/lib.rs` (from P04)
- [ ] `SealRecord` and `SealTier` types exist and are re-exported from `crates/resetprop/src/lib.rs` (from P02/P04)
- [ ] Error variants `HookInstallFailed`, `ElfParse`, `SymbolNotFound` exist in `crates/resetprop/src/error.rs` (from P03/P04)
- [ ] `crates/resetprop-cli/src/main.rs`, `README.md`, `tests/device-stress-test.sh` all exist

(Source: P05 spec, Preconditions; REGISTRY §5)

## Branch

- [ ] Branch `feat/P05-cli-docs` created (or resumed) from latest main
- [ ] All commits follow `feat(seal):` / `docs(seal):` / `test(seal):` scope prefix per REGISTRY §2

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: Parser arms — add five new match cases and five new locals in `crates/resetprop-cli/src/main.rs`

- [ ] Implementation: Five new locals declared near the top of `run()` — `seal: Option<String>`, `seal_arena: Option<String>`, `unseal: Option<String>`, `unseal_arena: Option<String>`, `list_seals: bool` — all defaulting to `None`/`false`
- [ ] Implementation: Five new parser arms inserted inside the `while i < args.len()` loop (after `"--stealth" | "-st"` at line 54): `"--seal" | "-sl"`, `"--seal-arena" | "-sla"`, `"--unseal"`, `"--unseal-arena"`, `"--seals"`
- [ ] Implementation: Flag→value binding uses `arg_val(&args, i, "<flag>")?` for the four arms that carry a string argument; the `i += 1` increment precedes the `arg_val` call (mirrors `--nuke|-nk` pattern at lines 50-53)
- [ ] Implementation: `--seals` arm sets `list_seals = true;` (mirrors `--compact` bool arm at line 55)
- [ ] Test: `cargo build -p resetprop-cli` exits 0
- [ ] Test: `grep -E '"-sl"|"-sla"|"--seals"' crates/resetprop-cli/src/main.rs` returns non-empty
- [ ] Test: `grep -c 'let mut seal' crates/resetprop-cli/src/main.rs` returns ≥4 (four new `Option<String>` locals)

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [ ] **Optimality** — Considered using a single `enum SealAction` instead of five flat locals? Rejected because existing flags (`nuke`, `delete`, `hexpatch`, `wait_name`) are also flat locals; matching the existing style keeps the diff minimal and readable. Notes: ___________________________
- [ ] **Completeness** — All five flags parse: `-sl`, `--seal`, `-sla`, `--seal-arena`, `--unseal`, `--unseal-arena`, `--seals`? Short and long forms both present? Notes: ___________________________
- [ ] **Correctness** — Edge cases walked through: `-sl` without a NAME (should surface `arg_val` error `"--seal requires a value"`); `-sl NAME` without a VALUE (caught in dispatch, Task 2); `-sl NAME VALUE --seals` (both flags parsed; dispatch handles `list_seals` first, which `returns` — seal not executed; accepted because `--seals` is a list-op, not a write-op). Notes: ___________________________

### Task 2: Dispatch block — insert BEFORE the positional handler at line 138

- [ ] Implementation: Dispatch block inserted between the `--wait` handling (line ~137) and the `match positional.len()` at line 138
- [ ] Implementation: `list_seals` branch prints each `SealRecord` as `"[{name}]: [{tier:?}] {arena}"` via `sys.seals()?` iteration, then `return Ok(());`
- [ ] Implementation: `unseal` branch calls `sys.unseal(&name)` and reports via `bool_op(..., "unseal", verbose)`, then `return`
- [ ] Implementation: `unseal_arena` branch calls `sys.unseal_arena(&name)` and reports via `bool_op(..., "unseal-arena", verbose)`, then `return`
- [ ] Implementation: `seal` branch reads VALUE from `positional[0]` (error if `positional.is_empty()` with a helpful message `"--seal NAME VALUE: missing VALUE"`), calls `sys.seal(&name, &value)`; on `Err(Error::HookInstallFailed | Error::ElfParse | Error::SymbolNotFound)` surfaces `Err(format!("Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback."))`; on success returns `Ok(())` (optionally logs `eprintln!("seal: [{}]=[{}]", name, value)` when verbose)
- [ ] Implementation: `seal_arena` branch symmetric to `seal` but calls `sys.seal_arena(&name, &value)` and does NOT carry the Tier-B fallback message
- [ ] Test: `cargo build -p resetprop-cli` exits 0
- [ ] Test: `./target/release/resetprop --seals 2>&1` exits 0 (may print nothing when no seals exist)
- [ ] Test: `./target/release/resetprop --unseal ro.nonexistent.prop 2>&1` returns a clean error (not a panic)

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [ ] **Optimality** — Considered matching on `(seal, seal_arena, unseal, unseal_arena, list_seals)` tuple instead of sequential `if let`s? Rejected because flat `if let ... { return ... }` matches the existing style at lines 87-98 (`persist_read`, `hexpatch`) and makes each branch self-contained. Notes: ___________________________
- [ ] **Completeness** — All five dispatch branches present? Tier B fallback message present ONLY on `seal` branch, not on `seal_arena`? `run()` signature preserved (`Result<(), String>`)? Notes: ___________________________
- [ ] **Correctness** — Edge cases: `-sl NAME` with no positional (dispatch returns `Err("--seal NAME VALUE: missing VALUE")`); `-sl NAME VALUE EXTRA` (positional has 2 items; take `positional[0]` as VALUE and ignore extras — matches how `-st` handles positionals in the existing `2 => { ... }` arm); `--unseal NAME` (no positional expected — dispatch does not touch `positional`); `--seals` combined with `-sl` (list_seals branch returns first, so seal is not executed — acceptable). Notes: ___________________________

### Task 3: `print_usage()` update — add rows for new flags

- [ ] Implementation: In the "Usage" block (lines 258-277), five new rows inserted after the `--stealth|-st -p` row: `--seal|-sl NAME VALUE`, `--seal-arena|-sla NAME VALUE`, `--unseal NAME`, `--unseal-arena NAME`, `--seals`
- [ ] Implementation: In the "Options" block (lines 279-287), five new rows inserted after the `--stealth, -st` row: `--seal, -sl`, `--seal-arena, -sla`, `--unseal NAME`, `--unseal-arena NAME`, `--seals`
- [ ] Implementation: Column alignment preserved (existing format uses 2-space indent + flag column + space + description)
- [ ] Test: `./target/release/resetprop -h 2>&1 | grep -c -E -- '--seal|--unseal|--seals'` returns ≥10 (five in Usage + five in Options)
- [ ] Test: `./target/release/resetprop --help 2>&1 | grep -q 'Tier B'` (seal description mentions Tier B)
- [ ] Test: `./target/release/resetprop --help 2>&1 | grep -q 'Tier A'` (seal-arena description mentions Tier A)

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [ ] **Optimality** — Considered compressing the five seal options into a single multi-line description? Rejected because each flag deserves its own searchable `grep -h` line and the existing block uses one row per flag. Notes: ___________________________
- [ ] **Completeness** — Both Usage block AND Options block updated? Short+long forms shown where applicable (e.g., `--seal|-sl`)? No other existing rows accidentally modified? Notes: ___________________________
- [ ] **Correctness** — Edge case: `resetprop -h` output width stays readable (no line exceeds ~88 chars including leading indent); help text flows naturally when grouped with other write modifiers (persist, stealth, init). Notes: ___________________________

### Task 4: README.md updates — new "Seal" subsection + CLI-reference rows

- [ ] Implementation: New `**Seal**` subsection inserted in `README.md` AFTER the existing Stealth subsection ends (line 94 — the `**Arena compaction**` bullet)
- [ ] Implementation: Seal subsection explains five points: (a) seal = stealth + ptrace-driven lock; (b) `-sl` / `--seal` is the default (Tier B per-prop hook); (c) `-sla` / `--seal-arena` is the Tier A arena-level fallback; (d) `-st` / `--stealth` remains unchanged (back-compat); (e) seals do NOT persist across reboots — user must re-run
- [ ] Implementation: Five new rows in the CLI-reference Options table (lines 232-248), each using the `| Flag | Description |` pipe-delimited Markdown format: `--seal|-sl NAME VALUE`, `--seal-arena|-sla NAME VALUE`, `--unseal NAME`, `--unseal-arena NAME`, `--seals`
- [ ] Implementation: New rows grouped adjacent to the existing `--stealth, -st` row (line 236) for topical discoverability
- [ ] Test: `grep -c '^\*\*Seal\*\*' README.md` returns ≥1
- [ ] Test: `grep -c -E -- '--seal\|-sl|--seal-arena\|-sla|--seals|--unseal' README.md` returns ≥5
- [ ] Test: `grep -c -i 'reboot' README.md | awk '$1 > 0 {print "ok"}'` prints `ok` (reboot-persistence note present somewhere in the new subsection)

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [ ] **Optimality** — Considered adding a full worked example (like the Stealth section has)? Partial rejection: added a minimal one-liner example inside the subsection (`$RESETPROP -sl ro.telephony.default_network 0`) but left deep examples for a future `examples/` doc. Notes: ___________________________
- [ ] **Completeness** — All five behavioural points present? Five Options table rows present with correct short+long forms? Tier A / Tier B terminology used consistently with REGISTRY §1? Notes: ___________________________
- [ ] **Correctness** — Edge case: the "back-compat: `-st` unchanged" note appears explicitly so that users doing `grep -n stealth README.md` can confirm their existing scripts are safe; the "does not persist" caveat is in BOTH the subsection body AND the Options-table descriptions, so there is no way to miss it. Notes: ___________________________

### Task 5: device-stress-test.sh — append Test 21 and Test 22

- [ ] Implementation: Test 21 (Tier B) appended after the last existing test block, mirroring the Test 18 stress pattern (lines 253-276)
- [ ] Implementation: Test 21 declares `TEL_PROP="ro.telephony.default_network"`, `NEIGHBOR_PROP="ro.telephony.call_ring.delay"`, and saves `ORIG` / `NEIGHBOR_ORIG` before any mutation
- [ ] Implementation: Test 21 runs `$RP -sl "$TEL_PROP" "0"`, loops 50× `setprop "$TEL_PROP" "99"; sleep 0.05`, then reads `SEALED_FINAL` and separately sets+reads `NEIGHBOR_FINAL` after a `setprop "$NEIGHBOR_PROP" "7"`
- [ ] Implementation: Test 21 PASS condition is `"$SEALED_FINAL" = "0"` AND `"$NEIGHBOR_FINAL" = "7"` (the conjunction is what proves per-prop precision)
- [ ] Implementation: Test 21 restores both props via `$RP --unseal "$TEL_PROP"; setprop "$TEL_PROP" "$ORIG"; setprop "$NEIGHBOR_PROP" "$NEIGHBOR_ORIG"`
- [ ] Implementation: Test 22 (Tier A) appended after Test 21, saves `ORIG`, runs `$RP -sla "$TEL_PROP" "0"`, loops 50×, reads `ARENA_FINAL`
- [ ] Implementation: Test 22 PASS condition is `"$ARENA_FINAL" = "0"` only (no neighbor check because the whole arena is privatized — documented Tier A trade-off per plan §Granularity trade-off)
- [ ] Implementation: Test 22 restores via `$RP --unseal-arena "$TEL_PROP"; setprop "$TEL_PROP" "$ORIG"`
- [ ] Implementation: Both tests use the existing `pass`/`fail` helper functions (PASS/FAIL counters are auto-incremented; no manual tally edits)
- [ ] Test: `bash -n tests/device-stress-test.sh` exits 0 (syntax OK)
- [ ] Test: `grep -c 'Test 21:' tests/device-stress-test.sh` returns ≥1
- [ ] Test: `grep -c 'Test 22:' tests/device-stress-test.sh` returns ≥1
- [ ] Test: `grep -c -E 'NEIGHBOR_PROP|NEIGHBOR_FINAL' tests/device-stress-test.sh` returns ≥2 (Test 21 neighbor-check present)
- [ ] Test (ON-DEVICE, MANUAL, requires rooted device): push binary and script to device, run `sh tests/device-stress-test.sh`, confirm `Test 21: seal (Tier B) ... PASS` and `Test 22: seal (Tier A) ... PASS` both appear; confirm `dmesg | tail` shows no init SIGSEGV; device remains responsive

#### Self-Audit Gate 5 (MANDATORY before Phase-End Audit)

- [ ] **Optimality** — Considered parameterizing the 50-iteration count? Kept at 50 to exactly match Test 18's proven cadence — deviation would invalidate the comparison baseline. Notes: ___________________________
- [ ] **Completeness** — Tests 21 AND 22 present? Neighbor check ONLY on Test 21 (Tier B precision claim)? Restore logic present on BOTH tests to leave the device in a clean state? Notes: ___________________________
- [ ] **Correctness** — Edge cases: device lacks `ro.telephony.call_ring.delay` (fallback: any other `telephony_prop` neighbor works; we document that `NEIGHBOR_PROP` is illustrative and the test-writer can substitute); `$RP --unseal` on a prop that was never sealed (Tier B `unseal` returns `Ok(false)` per plan §lib.rs — acceptable, `bool_op` turns it into a "not found" message which the test ignores via `2>/dev/null`); `sleep 0.05` resolution varies by shell — acceptable at ×50 because even with lower resolution the total window exceeds init's write latency. Notes: ___________________________

## Functional Requirements (subsystem-level)

### CLI Parser (per P05 spec §Tasks 1-2 and plan §New CLI surface)

- [ ] FR-01: Parser accepts `-sl NAME VALUE` and stores `seal = Some(NAME)` (per plan §CLI lines 186-188)
- [ ] FR-02: Parser accepts `--seal NAME VALUE` as the long form of `-sl` (per plan §CLI line 187)
- [ ] FR-03: Parser accepts `-sla NAME VALUE` and stores `seal_arena = Some(NAME)` (per plan §CLI line 189)
- [ ] FR-04: Parser accepts `--seal-arena NAME VALUE` as the long form of `-sla` (per plan §CLI line 190)
- [ ] FR-05: Parser accepts `--unseal NAME` and stores `unseal = Some(NAME)` (per plan §CLI line 191)
- [ ] FR-06: Parser accepts `--unseal-arena NAME` and stores `unseal_arena = Some(NAME)` (per plan §CLI line 192)
- [ ] FR-07: Parser accepts `--seals` and sets `list_seals = true` (per plan §CLI line 190)
- [ ] FR-08: `-st` / `--stealth` behaviour is unchanged — pure stealth write, no ptrace, no hook (per REGISTRY §1 back-compat lock and plan §New CLI surface line 195)
- [ ] FR-09: `cargo build -p resetprop-cli` exits 0 with the new parser arms present (per P05 spec §Validation)
- [ ] FR-10: Unknown flags starting with `-` still trigger the existing `return Err(format!("unknown flag: {s}"))` at main.rs:81 (no regression)

### CLI Dispatch (per P05 spec §Task 2 and plan §New CLI surface)

- [ ] FR-11: `--seals` prints each active `SealRecord` via `sys.seals()?` in the format `[{name}]: [{tier:?}] {arena}` (per P05 spec §Approach point 5)
- [ ] FR-12: `--unseal NAME` calls `sys.unseal(&NAME)` and reports via `bool_op` (per P05 spec §Task 2)
- [ ] FR-13: `--unseal-arena NAME` calls `sys.unseal_arena(&NAME)` and reports via `bool_op` (per P05 spec §Task 2)
- [ ] FR-14: `-sl NAME VALUE` calls `sys.seal(&NAME, &VALUE)` — VALUE taken from `positional[0]` (per P05 spec §Task 2 and plan §New CLI surface line 199)
- [ ] FR-15: `-sla NAME VALUE` calls `sys.seal_arena(&NAME, &VALUE)` — VALUE from `positional[0]` (per P05 spec §Task 2)
- [ ] FR-16: On Tier B install failure (`Error::HookInstallFailed` / `Error::ElfParse` / `Error::SymbolNotFound`), CLI surfaces `Err("Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback.")` and exits non-zero (per plan §New CLI surface line 201 and P05 spec §Approach point 3)
- [ ] FR-17: CLI does NOT silently downgrade Tier B to Tier A on failure (per plan §New CLI surface line 201)
- [ ] FR-18: Dispatch block runs BEFORE the `match positional.len()` at line 138 — seal operations `return` and never enter positional match (per P05 spec §Task 2)

### `print_usage()` (per P05 spec §Task 3)

- [ ] FR-19: `resetprop -h` output contains a "Usage" row for `--seal|-sl NAME VALUE` (per P05 spec §Task 3)
- [ ] FR-20: `resetprop -h` output contains a "Usage" row for `--seal-arena|-sla NAME VALUE` (per P05 spec §Task 3)
- [ ] FR-21: `resetprop -h` output contains a "Usage" row for `--seals` (per P05 spec §Task 3)
- [ ] FR-22: `resetprop -h` output contains a "Usage" row for `--unseal NAME` (per P05 spec §Task 3)
- [ ] FR-23: `resetprop -h` output contains a "Usage" row for `--unseal-arena NAME` (per P05 spec §Task 3)
- [ ] FR-24: `resetprop -h` "Options" block contains rows for `--seal, -sl`, `--seal-arena, -sla`, `--unseal`, `--unseal-arena`, `--seals` with Tier A/Tier B terminology (per P05 spec §Task 3)

### README.md Docs (per P05 spec §Task 4)

- [ ] FR-25: New `**Seal**` subsection exists in `README.md` after the Stealth subsection (per P05 spec §Task 4 a-e)
- [ ] FR-26: Subsection explains `-sl` / `--seal` is the Tier B default (per plan §CLI line 187 and REGISTRY §1)
- [ ] FR-27: Subsection explains `-sla` / `--seal-arena` is the Tier A arena-level fallback (per REGISTRY §1)
- [ ] FR-28: Subsection explicitly states `-st` / `--stealth` remains unchanged for back-compat (per REGISTRY §1 and plan §New CLI surface line 195)
- [ ] FR-29: Subsection explicitly states seals do NOT persist across reboots — user must re-run (per plan §Persistence across reboots deferred)
- [ ] FR-30: CLI-reference Options table has five new rows for `--seal|-sl`, `--seal-arena|-sla`, `--unseal`, `--unseal-arena`, `--seals` with Tier A/Tier B terminology (per P05 spec §Task 4)
- [ ] FR-40: README.md Seal subsection explicitly documents that `SystemProperties::Reload` (init re-initializing its contexts on signal) drops the seal and the user must re-run the `-sl` / `-sla` command (per plan §Known Trade-offs bullet 3 and P05 spec §Accepted Trade-offs bullet 1)
- [ ] FR-41: README.md Seal subsection explicitly documents that an init restart drops the seal along with init's address space and the user must re-run the seal command (per plan §Known Trade-offs bullet 4 and P05 spec §Accepted Trade-offs bullet 2)
- [ ] FR-42: README.md Seal subsection explicitly documents that per-prop futex waiters on sealed props stall silently — `__system_property_wait(pi, ...)` waits on `&pi->serial` in the caller's mapping while init's bump happens in init's private copy, so waiters on sealed prop_info serials are never woken; includes the rationale that this is acceptable and aligned with seal intent (per plan §Known Trade-offs bullet 8 and P05 spec §Accepted Trade-offs bullet 3)

### Device Stress Test (per P05 spec §Task 5 and plan §Verification)

- [ ] FR-31: Test 21 (Tier B) present in `tests/device-stress-test.sh` (per plan §Verification lines 280-306)
- [ ] FR-32: Test 21 writes via `$RP -sl`, loops 50× `setprop ... 99`, asserts `SEALED_FINAL = "0"` (per plan §Verification lines 286-302)
- [ ] FR-33: Test 21 ALSO asserts `NEIGHBOR_FINAL = "7"` — proves per-prop precision (per plan §Verification lines 294-302 and P05 spec §Approach point 8)
- [ ] FR-34: Test 21 restores both props to their original values via `$RP --unseal` + `setprop ... $ORIG` + `setprop ... $NEIGHBOR_ORIG` (per plan §Verification lines 303-305)
- [ ] FR-35: Test 22 (Tier A) present in `tests/device-stress-test.sh` (per plan §Verification lines 308-324)
- [ ] FR-36: Test 22 writes via `$RP -sla`, loops 50× `setprop ... 99`, asserts `ARENA_FINAL = "0"` (per plan §Verification lines 311-321)
- [ ] FR-37: Test 22 does NOT include a neighbor check because Tier A privatizes the whole arena (per plan §Granularity trade-off and P05 spec §Approach point 8)
- [ ] FR-38: Test 22 restores the sealed prop via `$RP --unseal-arena` + `setprop ... $ORIG` (per plan §Verification lines 322-323)
- [ ] FR-39: Both tests use the existing `pass` / `fail` helper functions (no changes to PASS/FAIL tally logic) (per P05 spec §Task 5)

## Test Criteria

- [ ] TC-01: `cargo build -p resetprop-cli` exits 0 (per P05 spec §Validation)
- [ ] TC-02: `cargo build --release -p resetprop-cli` exits 0 — release-profile build with LTO/strip succeeds (per P05 spec §Validation)
- [ ] TC-03: `bash -n tests/device-stress-test.sh` exits 0 — shell script syntax valid (per P05 spec §Validation)
- [ ] TC-04: `./target/release/resetprop --help 2>&1 | grep -E -- '--seal(\s|\|)'` matches ≥1 line (per P05 spec §Validation)
- [ ] TC-05: `./target/release/resetprop --help 2>&1 | grep -E -- '-sl|-sla'` matches ≥1 line (per P05 spec §Validation)
- [ ] TC-06: `./target/release/resetprop --help 2>&1 | grep -- '--seals'` matches ≥1 line (per P05 spec §Validation)
- [ ] TC-07: `./target/release/resetprop --help 2>&1 | grep -- '--unseal'` matches ≥1 line (per P05 spec §Validation)
- [ ] TC-08: `grep -c '^\*\*Seal\*\*' README.md` returns ≥1 (per P05 spec §Validation)
- [ ] TC-09: `grep -c -E -- '--seal\|-sl|--seal-arena\|-sla|--seals' README.md` returns ≥3 (per P05 spec §Validation)
- [ ] TC-10: `grep -c 'Test 21:' tests/device-stress-test.sh` returns ≥1 (per P05 spec §Validation)
- [ ] TC-11: `grep -c 'Test 22:' tests/device-stress-test.sh` returns ≥1 (per P05 spec §Validation)
- [ ] TC-12: **MANUAL / ON-DEVICE** — `sh tests/device-stress-test.sh` on a rooted Android device reports `Test 21: seal (Tier B) ... PASS` and `Test 22: seal (Tier A) ... PASS`; `dmesg | tail` shows no init SIGSEGV; device remains responsive 30 seconds after test completes (per plan §On-device acceptance tests and P05 spec §Validation; documented as `#[manual]` in spirit per P05 spec §Approach point 9)
- [ ] TC-13: No pre-existing tests in `tests/device-stress-test.sh` regress — Tests 1-20 still PASS on the same device run (regression check per P05 spec §Approach point 6)
- [ ] TC-14: **MANUAL / ON-DEVICE** — after Test 21 + Test 22 setup, `./resetprop-rs --seals` output lines match the expected sealed prop names in the format `[{name}]: [{tier:?}] {arena}` (per plan §Live regression step 2 and P05 spec §On-device acceptance step 2)
- [ ] TC-15: **MANUAL / ON-DEVICE** — after Test 21 setup, `propdetect --scan telephony_prop` reports 0 anomalies — stealth signals (zero serial, no futex wake) still read clean (per plan §Live regression step 3 and P05 spec §On-device acceptance step 3)
- [ ] TC-16: **MANUAL / ON-DEVICE** — 30-minute soak with live cell radio: sealed prop values do not drift (re-read via `getprop` at 30-minute mark matches spoofed value); `dmesg` shows no init SIGSEGV; SystemUI, CellBroadcast, and emergency dial remain functional (per plan §Live regression step 4 and P05 spec §On-device acceptance step 4)
- [ ] TC-17: **MANUAL / ON-DEVICE** — `adb shell dumpsys telephony.registry` output reports sane state despite frozen props: valid service state, valid cell info, no stacktrace, no `null` fields where valid data is expected (per plan §Live regression step 5 and P05 spec §On-device acceptance step 5)
- [ ] TC-18: **MANUAL / ON-DEVICE** — fallback retry documented: if Tier B refused to install on the device's libc build OR if step 4/step 5 shows breakage traceable to neighbor freeze, re-run with `--seal-arena` and repeat the 30-minute soak (per plan §Live regression step 6 and P05 spec §On-device acceptance step 6)

## Integration Verification

- [ ] IV-01: Consumes `PropSystem::seal_arena` from P02 (per P05 spec §Preconditions and REGISTRY §5)
- [ ] IV-02: Consumes `PropSystem::unseal_arena` from P02 (per P05 spec §Preconditions and REGISTRY §5)
- [ ] IV-03: Consumes `PropSystem::seal` from P04 (per P05 spec §Preconditions and REGISTRY §5)
- [ ] IV-04: Consumes `PropSystem::unseal` from P04 (per P05 spec §Preconditions and REGISTRY §5)
- [ ] IV-05: Consumes `PropSystem::seals` from P04 (per P05 spec §Preconditions and REGISTRY §5)
- [ ] IV-06: Consumes `SealRecord` and `SealTier` types from P02/P04 for `--seals` output formatting (per plan §New public API)
- [ ] IV-07: Consumes `Error::HookInstallFailed`, `Error::ElfParse`, `Error::SymbolNotFound` from P03/P04 for the Tier-B fallback message pattern (per plan §Error variants and P05 spec §Task 2)
- [ ] IV-08: Downstream: No consumers — P05 is the LEAF phase per REGISTRY §5 dependency graph. The end user is the CLI caller (rooted Android shell user). All outputs are user-visible artifacts (CLI help text, README docs, on-device test harness)

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `-st` / `--stealth` semantics | UNCHANGED — pure stealth write, no ptrace, no hook (REGISTRY §1 "back-compat for user's existing telephony scripts") | `crates/resetprop-cli/src/main.rs:54` (arm preserved verbatim) |
| `-sl` / `--seal` → default tier | Tier B per-prop hook on `__system_property_update` (REGISTRY §1 "`-sl` / `--seal` default" row) | `crates/resetprop-cli/src/main.rs` dispatch block (calls `sys.seal`, which is Tier B) |
| `-sla` / `--seal-arena` → tier | Tier A arena-level MAP_PRIVATE\|MAP_FIXED (REGISTRY §1 "`-sla` / `--seal-arena`" row) | `crates/resetprop-cli/src/main.rs` dispatch block (calls `sys.seal_arena`, which is Tier A) |
| Parser arm insertion point | Inside `while i < args.len()` loop at `crates/resetprop-cli/src/main.rs:54` (immediately after `"--stealth" \| "-st"`) (references/resetprop-rs-integration.md §11 "New Seal Flags (insertion points) — After line 54 (`--stealth\|-st`)") | `crates/resetprop-cli/src/main.rs:55-65` (new arms after preservation of line 54) |
| Dispatch block insertion point | BEFORE `match positional.len()` at `crates/resetprop-cli/src/main.rs:138` (references/resetprop-rs-integration.md §11 "Dispatch Insertions (before line 138)") | `crates/resetprop-cli/src/main.rs` (dispatch block ends immediately before line 138) |
| README "Seal" subsection location | AFTER the "Stealth" subsection ending at `README.md:94` (P05 spec §Task 4; plan §Files modified line 239 "a 'Seal' subsection after 'Stealth' (around current line 82)") | `README.md` (new subsection header `**Seal**` placed after line 94) |
| Device-stress-test.sh append pattern | Mirror Test 18 stress block at `tests/device-stress-test.sh:253-276` (references/resetprop-rs-integration.md §12 "Test 18: Stress Block (lines 253-276)") | `tests/device-stress-test.sh` (Test 21 and Test 22 appended using the same 50-iteration `seq 1 50` loop with `sleep 0.05`) |
| Tier B failure message | Exactly `"Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback."` (P05 spec §Task 2 and §Approach point 3; plan §New CLI surface line 201 — "surfaces a clear error and suggests `-sla` as the fallback rather than silently downgrading") | `crates/resetprop-cli/src/main.rs` (dispatch block, `seal` branch error arm) |
| Seal list output format | Exactly `"[{name}]: [{tier:?}] {arena}"` (P05 spec §Task 2 and §Approach point 5) | `crates/resetprop-cli/src/main.rs` (dispatch block, `list_seals` branch `println!` call) |

## Anti-Scope (explicitly excluded)

- AS-01: No new core seal logic — `PropSystem::seal`, `seal_arena`, `unseal`, `unseal_arena`, `seals` owned by P01-P04, consumed unchanged here (per P05 spec)
- AS-02: No persistence of seals to disk — `SealRecord` stays in-memory; `--replay-seals` is a future flag (per P05 spec §Anti-Scope and plan §Persistence across reboots deferred)
- AS-03: No changes to `propdetect` heuristics for Tier A / Tier B signatures (per P05 spec §Anti-Scope; REGISTRY §1 notes future work)
- AS-04: No changes to `-st` / `--stealth` semantics — REGISTRY §1 back-compat lock (per P05 spec §Anti-Scope)
- AS-05: No new library modules — the seal/ tree is owned by P01-P04 (per P05 spec §Anti-Scope; REGISTRY §3)
- AS-06: No new error variants — the seven seal variants are introduced by P02/P04 (per P05 spec §Anti-Scope; REGISTRY §1)
- AS-07: No changes to `Cargo.toml` dependencies — single-dep policy holds (per P05 spec §Anti-Scope; REGISTRY §1)

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment completes (P05 has a single segment, so this runs after Task 5 self-audit).

- [ ] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template) with: phase spec path (`phases/seal/P05-cli-docs.md`), checklist path (`phases/seal/checklists/P05-checklist.md`), REGISTRY path (`phases/seal/REGISTRY-P.md`), code file paths (`crates/resetprop-cli/src/main.rs`, `README.md`, `tests/device-stress-test.sh`), branch name (`feat/P05-cli-docs`), External API Verification flag (YES) and source (`phases/seal/references/resetprop-rs-integration.md` §11 — CLI parser template at `crates/resetprop-cli/src/main.rs:50-53` for `--nuke|-nk` and `crates/resetprop-cli/src/main.rs:54` for `--stealth|-st`)
- [ ] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block
- [ ] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block
- [ ] Both agents dispatched IN PARALLEL (single message, two Agent tool calls)
- [ ] External API Verification is YES per spec: agents MUST verify that the CLI parser additions (new flags `-sl`, `-sla`, `--seal`, `--seal-arena`, `--unseal`, `--unseal-arena`, `--seals`) match the existing `--nuke|-nk` / `--stealth|-st` templates exactly — same short/long pattern, same `arg_val`/`bool_op` helper usage, same insertion point inside the `while i < args.len()` loop at `crates/resetprop-cli/src/main.rs:50-54`
- [ ] code-reviewer report saved at `phases/seal/audits/P05-audit.md` — verdict: {PASS | NEEDS_FIX}
- [ ] critic report saved at `phases/seal/audits/P05-audit.md` — verdict: {PASS | NEEDS_FIX}
- [ ] All CRITICAL findings resolved
- [ ] All MAJOR findings resolved
- [ ] MINOR findings logged (not blocking)
- [ ] Re-ran both agents after fixes; both emitted `VERDICT: PASS`

## Acceptance Gate

- [ ] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes on Optimality / Completeness / Correctness for every gate)
- [ ] All 42 FR items verified
- [ ] All 18 TC items verified (TC-12 and TC-14 through TC-18 are manual/on-device — require rooted device; documented proof via log/screenshot attached to session log)
- [ ] All 8 IV items verified
- [ ] No regressions in prerequisite phases: `cargo test -p resetprop` passes (P01-P04 unit tests unchanged); `cargo build --release --workspace` exits 0
- [ ] Branch `feat/P05-cli-docs` commits clean; conventional commits with `feat(seal):` / `docs(seal):` / `test(seal):` prefix per REGISTRY §2
- [ ] All canonical values verified against REGISTRY §1 and the line-numbered references
- [ ] Gate 2 reports PASS from BOTH code-reviewer (Sonnet) AND critic (Opus) agents
- [ ] REGISTRY §4 updated: P05 row → COMPLETE
- [ ] REGISTRY §7 session log appended with: date, session ID, `P05.—`, outcome (COMPLETE), artifacts (`phases/seal/P05-cli-docs.md`, `phases/seal/checklists/P05-checklist.md`, `phases/seal/audits/P05-audit.md`, commit SHA), Gate 2 verdict (both PASS)
