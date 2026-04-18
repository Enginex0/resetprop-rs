# P05 Gate 2 Audit Reports

Branch: `feat/P04-tier-b-part2` @ `150aade`
Scope: P05 T1..T5 (commits `4e78f8e` feat(cli), `70ce2bb` docs(readme), `8a9567d` test(device))

---

## P05 Gate 2 round-1 — code-reviewer (sonnet)

**Date**: 2026-04-18
**Branch**: feat/P04-tier-b-part2 @ 150aade
**Scope**: P05 T1–T5 (commits 4e78f8e, 70ce2bb, 8a9567d)

### Verdict: NEEDS_FIX

### Findings

#### CRITICAL

- **C1**: KSU resetprop bypasses the Tier B hook entirely, making Tests 21/22 overstate seal coverage.
  File: `tests/device-stress-test.sh:325` (Test 21), `tests/device-stress-test.sh:348` (Test 22).
  Evidence: The Tier B seal hooks `__system_property_update` inside init's text segment. That function is called by init's property-service socket handler when a `setprop` request arrives. KSU's `resetprop` (`/data/adb/ksu/bin/resetprop`) writes directly to the mmap'd arena pages at `/dev/__properties__/*` without going through the property-service socket — identical write path to resetprop-rs itself. The hook in init is never invoked. Test 21's 50-iteration loop uses only `setprop` (socket path → init → hook fires), so the test passes. On a KSU device the same seal is trivially bypassed by any caller using direct mmap writes, including `ksu_props`, Magisk's resetprop, or resetprop-rs itself invoked again. Tests 21/22 document "Tier B per-prop precision" without exercising this bypass vector at all, so a passing test result misrepresents actual seal coverage.
  Impact: The README states the seal is "a lock that nothing on the device can revert" (`README.md:96`). That claim is false for any direct-mmap writer. The test suite gives a false PASS on the claim it is supposed to validate.
  Proposed fix (two parts, both required):
  1. Add a KSU resetprop probe step to Test 21 immediately after the `setprop` stress loop:
     ```sh
     if [ -x /data/adb/ksu/bin/resetprop ]; then
         /data/adb/ksu/bin/resetprop "$TEL_PROP" "99" 2>/dev/null
         sleep 0.1
         KSU_FINAL=$(getprop "$TEL_PROP")
         if [ "$KSU_FINAL" != "0" ]; then
             log "  WARN Test 21: KSU resetprop bypassed Tier B seal (expected, direct-mmap path)"
         fi
     fi
     ```
     This makes the bypass observable rather than invisible.
  2. Update `README.md:96` to qualify the claim: `"Tier B per-prop hook — blocks init's __system_property_update path; direct-mmap writers (KSU resetprop, Magisk resetprop, resetprop-rs itself) bypass the hook"`. The existing bullet is a strong claim that the device-facing evidence does not support.

#### MAJOR

- **M1**: `--seal NAME1` combined with `--seal-arena NAME2` on the same invocation silently executes only `--seal` and drops `--seal-arena` without error.
  File: `crates/resetprop-cli/src/main.rs:176,201`.
  Evidence: Both arms are independent `Option<String>` locals. The parser increments `i` and stores each NAME independently. The dispatch block checks `seal` first (line 176); once it returns `Ok(())`, the `seal_arena` block (line 201) is never reached. The user gets no warning that `--seal-arena NAME2` was silently ignored.
  Impact: User intent is ambiguous; silently ignoring one of two conflicting seal commands is worse than an error because the user may believe both applied. P05 spec Approach §6 says "no changes to existing behaviour" but does not address this conflict case; the natural contract is an error, not a silent drop.
  Proposed fix: Add a conflict check at the top of the seal dispatch block:
  ```rust
  if seal.is_some() && seal_arena.is_some() {
      return Err("--seal and --seal-arena are mutually exclusive".to_string());
  }
  ```

- **M2**: Test 21's neighbor-prop assertion will produce a false FAIL on SELinux-enforcing production devices.
  File: `tests/device-stress-test.sh:329-333`.
  Evidence: The neighbor assertion writes `setprop "$NEIGHBOR_PROP" "7"` where `NEIGHBOR_PROP="ro.telephony.call_ring.delay"`. `ro.*` property names map to the `telephony_prop` SELinux label. On a production device with SELinux in enforcing mode, the property-service rejects writes to `ro.*` props from any context that is not `u:r:init:s0`. The `setprop` call silently fails (exit 0, no write). `NEIGHBOR_FINAL` will be the original value (empty string or an integer), not `"7"`. The combined assertion `"$SEALED_FINAL" = "0" && "$NEIGHBOR_FINAL" = "7"` fails, and the test reports FAIL for Tier B even though the seal itself may be working correctly. The failure is in the test probe, not in the seal.
  Impact: Test 21 is the only test that validates Tier B per-prop precision. A systematic false FAIL on the primary validation test makes the device acceptance step unreliable.
  Proposed fix: Replace `ro.telephony.call_ring.delay` with a `persist.*` neighbor in the same arena that the test script itself has permission to write, or check whether `setprop` succeeded before asserting `NEIGHBOR_FINAL`.

#### MINOR

- **m1**: `--unseal NAME` on a name that was never sealed returns `Err("property not found: NAME")` via `bool_op`'s `Ok(false)` branch.
  File: `crates/resetprop-cli/src/main.rs:168-169`. Fix: replace `bool_op` call with custom match that emits `"no seal found for: {name}"` on `Ok(false)`.

- **m2**: Dispatch ordering in implementation differs from spec §11 reference template literal ordering — spec says "BEFORE the positional handler at line 138", but `file` and `wait` dispatches execute before the seal block. Functionally benign (mutually exclusive operations).

- **m3**: Print-usage column alignment for `--seal-arena, -sla` is wider than `--stealth, -st`, breaking the two-column visual alignment. Cosmetic.

- **m4**: `README.md:96` "ptrace-driven lock that nothing on the device can revert" — inaccurate for direct-mmap writers (C1-adjacent).

- **m5**: Test 22 reuses `TEL_PROP` from Test 21's scope without an explicit comment documenting the cross-test dependency. Maintenance readability.

### Positive Observations

- The `e @ (Error::HookInstallFailed(_) | Error::ElfParse(_) | Error::SymbolNotFound(_))` binding-with-or-pattern compiles correctly under edition 2021.
- `cargo build -p resetprop-cli` exits 0. `cargo clippy -p resetprop-cli -- -D warnings` exits 0.
- `bash -n tests/device-stress-test.sh` exits 0.
- All five new parser arms correctly mirror the `--nuke|-nk` template (lines 55-58).
- `--seal` and `--seal-arena` correctly pull VALUE from `positional.first()` matching the `--stealth NAME VALUE` pattern.
- Tier B fallback error message at `main.rs:193-195` is actionable and spec-compliant.
- README trade-offs bullet on futex-waiter stall (`README.md:101`) is technically correct.
- Test 21 correctly asserts both `SEALED_FINAL = "0"` AND `NEIGHBOR_FINAL = "7"` in a single `if`.

### Summary

The implementation is structurally correct and compiles cleanly. The load-bearing defect is **C1**: Tests 21 and 22 exercise only the property-service socket path (`setprop`) and do not probe the direct-mmap write path used by KSU's own `resetprop`. On a KSU device — the primary deployment target per README's KSU binary-naming warning — the Tier B seal is bypassed by any direct-mmap writer, contradicting the README's "nothing on the device can revert" claim. A passing Test 21/22 on a KSU device does not validate that claim. **M1** (silent drop of `--seal-arena` when combined with `--seal`) and **M2** (Test 21 false FAIL on SELinux-enforcing `ro.*` neighbor) are also blocking-quality issues.

---

## P05 Gate 2 round-1 — critic (opus)

**Date**: 2026-04-18
**Branch**: feat/P04-tier-b-part2 @ 150aade
**Scope**: P05 T1–T5 (commits 4e78f8e, 70ce2bb, 8a9567d)

### Verdict: NEEDS_FIX

### Multi-perspective analysis

#### Executor perspective

A rooted operator runs `resetprop-rs -sl ro.telephony.default_network 0`. The CLI parses correctly, `PropSystem::seal` does `set_stealth` first (lib.rs:630) which succeeds, then it calls `install_init_hook` → `install_trampoline`. On the first invocation the operator observes a 15–40 ms stall across the device — per the doc-comment at hook.rs:278-285, every thread that happens to block on init for a property write during that window waits out the full stall, including zygote, system_server, SystemUI, and init-launched daemons. The README does not mention this. The `Seal` subsection markets the feature as "nothing on the device can revert" but never tells the operator that the very first seal freezes user-space for up to 40 ms.

Test 22 (Tier A) runs immediately after Test 21 (Tier B) on the same `TEL_PROP=ro.telephony.default_network` with **no reboot between them** (device-stress-test.sh:318-361). By the time Test 22 starts, Test 21 has left the Tier B trampoline and RWX hook page installed in init. `PropSystem::unseal` at `lib.rs:664-686` only removes the name from the lock list; the `trampoline_installed: true` guard in `hook.rs:158` actively forbids Drop from unmapping the hook page. Test 22 then calls `$RP -sla "$TEL_PROP" "0"` which goes through `PropSystem::seal_arena` in a fresh process (new OnceLock) — but init's address space still has the Tier-B trampoline from the prior process. Test 22 works but for the wrong reason on the first pass (both tiers simultaneously active), and on subsequent reruns the trampoline is still present — meaning Test 21's claim of per-prop precision is no longer falsifiable by the restore step.

#### Stakeholder perspective

A user reads `readme.md:96-101` and sees: "Two-tier seal — stealth write + ptrace-driven lock that nothing on the device can revert." They assume they have sealed a prop against any attacker with root. Then they run KernelSU's own `resetprop` (at `/data/adb/ksu/bin/resetprop`) against the sealed prop. KSU resetprop is a fork of Magisk's resetprop; it does direct mmap writes into `/dev/__properties__/*` from its own process — it does NOT go through init's `__system_property_update`. The Tier B hook never fires. Same for Magisk resetprop. Same for any attacker running `resetprop-rs` itself. The phrase "nothing on the device can revert" overstates Tier B's actual guarantee.

The verbose output format `[{name}]: [{tier:?}] {arena}` (main.rs:163) uses Debug impl emitting literal `Arena` or `Prop`. A first-time user reading `[ro.telephony.default_network]: [Prop] /dev/__properties__/...` has no scaffolding to know that `Prop` means "Tier B per-prop hook" vs `Arena` means "Tier A arena remap". The README never shows an example of the output.

The CLI-reference table describes `--seal-arena` as "Broader blast radius, use when Tier B cannot install." That phrasing implies the CLI may auto-fall-back. It does not — the plan §New CLI surface explicitly rejects silent downgrade. The table should reinforce that the user must manually retry.

#### Skeptic perspective

**Hidden assumption #1 — KSU/Magisk bypass.** The README markets Tier B seal as permanent against device-wide reverts. It isn't — it only blocks the in-init path. Test 21 exclusively uses `setprop` which routes through init.

**Hidden assumption #2 — Tier A against direct mmap.** Tier A's `MAP_PRIVATE|MAP_FIXED` only privatizes init's view of the file. KSU resetprop opens the same arena file with `MAP_SHARED` in its own process and writes bytes — those writes land in the shared inode's page cache, visible to `getprop` in every process **except** init. A direct-mmap attacker wins against Tier A too.

**Hidden assumption #3 — resetprop-rs self-consistency.** `resetprop-rs sealed.prop newvalue` routes through `PropSystem::set` in the invoking process's own address space → writes to its own MAP_SHARED mmap → bypasses both tiers. The most obvious attack from someone with root: just run the same tool against the prop they want to change.

**Hidden assumption #4 — Test 21 neighbor arena co-residence.** The assertion `NEIGHBOR_FINAL == "7"` assumes `ro.telephony.default_network` and `ro.telephony.call_ring.delay` live in the same arena. On current Android 10-15 they do, but the test has no runtime guard: if a future device routes these props to different arenas, the test tautologically passes regardless of whether Tier B is actually per-prop-precise.

**Hidden assumption #5 — Dispatch branch ordering collision.** Parser allows both `--seal NAME` and `--unseal NAME` on the same command line. Dispatch checks `list_seals` → `unseal` → `unseal_arena` → `seal` → `seal_arena`. If a user scripts `rp --seal foo --unseal foo 1`, `unseal` fires, returns success, `--seal` is silently dropped.

### Findings

#### CRITICAL (blocks the phase)

- **C1**: The seal feature's scope is materially misrepresented in `README.md`. Tier B hooks **only** init's `__system_property_update`; Tier A privatizes **only** init's view of the arena. Any direct-mmap writer with the right SELinux context — KSU resetprop (`/data/adb/ksu/bin/resetprop`), Magisk resetprop, or resetprop-rs itself — bypasses both tiers.
  Evidence:
  - `readme.md:96` — "Two-tier seal — stealth write + ptrace-driven lock that **nothing on the device can revert**".
  - `readme.md:97` — Tier B described as "only the sealed prop freezes" without "via init's write path" scoping.
  - `crates/resetprop/src/lib.rs:446-463` — `PropSystem::set` writes via the invoking process's own MAP_SHARED mapping, never through init.
  - `crates/resetprop/src/seal/hook.rs:288-345` + `install_trampoline` at 904 — hook is installed at `target_fn = libc_base + st_value("__system_property_update")` in init; any writer not calling through this symbol is unaffected.

  Impact: A user reads the README and believes they have a lock against any root actor. They deploy this in a spoof-persistence scenario, then get defeated by a single `resetprop ro.telephony.default_network real_value` from the KSU shell — no warning, no error, the seal silently did nothing.

  Proposed fix: Rewrite the Seal subsection to spell out the scope explicitly: *"Seal is scoped to writes routed through init (`init`'s `__system_property_update`), covering `setprop`, `property_service`, and any caller that goes through bionic. It does NOT block direct-mmap writers running from a root process — e.g., KSU's `/data/adb/ksu/bin/resetprop`, Magisk's resetprop, or `resetprop-rs` itself when invoked against a sealed prop. Tier B's guarantee is per-prop precision **within the init-mediated write path**; Tier A's guarantee is arena-level privatization of **init's own view**."*

- **C2**: Test 21 and Test 22 share state across tests with no reboot between them, leaking Tier B residue into the Tier A test. `PropSystem::unseal` at `lib.rs:664-686` only removes the name from the lock list; the trampoline at init's `__system_property_update` remains installed (`hook.rs:158` `trampoline_installed: true` prevents Drop from unmapping the page). Test 22 runs in a new process with a fresh `OnceLock<HookHandle>` — but init still has the prior trampoline pointing at a hook page the previous process allocated.
  Evidence:
  - `tests/device-stress-test.sh:337` — `$RP --unseal "$TEL_PROP" 2>/dev/null` — only removes name from lock list.
  - `crates/resetprop/src/seal/hook.rs:154-158` — Drop MUST NOT unmap hook_page once trampoline_installed.
  - `crates/resetprop/src/lib.rs:664-686` — `unseal()` calls `unseal_prop` which only rewrites the lock list.

  Impact: Test 22's `ARENA_FINAL == "0"` assertion passes because **both** tiers are active simultaneously (leftover Tier-B trampoline + new Tier A privatize). Test does not prove Tier A alone holds the prop. On device reruns of the full stress suite, Test 21's starting `ORIG=$(getprop "$TEL_PROP")` reads a prop still shadowed by prior trampoline state, poisoning subsequent test assertions.

  Proposed fix: Either (a) reboot between Test 21 and Test 22, documented inline; or (b) use a **different** `TEL_PROP` for Test 22 (e.g., `ro.telephony.sms_receive_mode`) so Tier A path acts on a clean init; or (c) add a proper trampoline-revert path (revert 16-byte prologue, munmap hook page) and invoke at end of Test 21. Option (b) is the minimal fix.

#### MAJOR (spec-conforming on the surface but silently wrong)

- **M1**: CLI parser allows `--seal NAME` and `--unseal NAME` on the same invocation; dispatch silently drops `--seal` because `unseal` is checked first.
  Evidence: `main.rs:60-75` (parser accepts both), `main.rs:160-218` (dispatch chain, no conflict check).
  Proposed fix: Pre-dispatch guard: `let flag_count = [seal.is_some(), seal_arena.is_some(), unseal.is_some(), unseal_arena.is_some(), list_seals].iter().filter(|&&b| b).count(); if flag_count > 1 { return Err("conflicting seal flags ...".into()); }`.

- **M2**: README features bullet at `readme.md:96` — same scope lie as C1, needs independent edit so casual feature-list readers aren't misled.
  Proposed fix: Replace `nothing on the device can revert` with `no init-mediated writer can revert`.

- **M3**: README Seal subsection silent on the 15–40 ms init-stall the first `--seal` call causes. Documented at `hook.rs:276-287` but not surfaced.
  Proposed fix: Add a seventh bullet under Seal subsection: *"First `-sl` / `-sla` call stalls user-space briefly — the ptrace install window is typically 15–40 ms on modern ARM64 handsets; any thread that blocks on init for a property write during that window waits out the full stall. Subsequent calls against the already-installed hook are faster (<5 ms)."*

- **M5**: Test 21 does not verify that `TEL_PROP` and `NEIGHBOR_PROP` share an arena. Current Android routes both to `telephony_prop` arena, but the test's per-prop-precision proof is not airtight on future devices.
  Proposed fix: Add an arena co-residence sanity check before the stress loop, or use neighbor props with stronger arena-locality guarantees.

- **M6**: `--seals` output format never demonstrated in README. Users don't know whether Debug emits `Prop`/`Arena` or `TierB`/`TierA`.
  Proposed fix: Add a `$ resetprop-rs --seals` output example under the Seal subsection and clarify `Prop = Tier B per-prop hook; Arena = Tier A arena-level privatize`.

#### MINOR (cosmetic, polish, doc drift)

- **m1**: Verbose seal success output `sealed: [{}] tier={tier:?} arena={arena}` at main.rs:183 — initially flagged MAJOR as drift from listing format, downgraded during Realist Check because it matches the `set{mode}: [{}]=[{}]` pattern at main.rs:256.
- **m2**: `--seal-arena NAME VALUE`, `-sla NAME VALUE` in options table repeats `NAME VALUE` for both long and short forms; cosmetic.
- **m3**: Task 1 verification grep is surface-level string check, not parser-correctness check.
- **m4**: `print_usage` expanded in-place rather than refactored into `usage_seal()` helper; cosmetic.
- **m5**: Checklist planned a `$RESETPROP -sl ro.telephony.default_network 0` example in Seal subsection that did not land; drift from approved checklist.

### What's Missing

- KSU/Magisk bypass acknowledgement in README (see C1).
- Self-bypass acknowledgement (resetprop-rs vs its own sealed prop).
- Attach-window stall documentation (see M3).
- `--seals` output example in README (see M6).
- No Tier B teardown regression test — unseal does not revert trampoline, residue compounds across invocations.
- Reboot discipline documented but not enforced in test script.
- Dispatch-conflict handling — no test for `--seal A --unseal A`.
- No assertion that Test 21's `TEL_PROP` and `NEIGHBOR_PROP` share an arena.

### Load-bearing defect

The single most consequential finding is **C1**: the README's claim that seal creates a lock "that nothing on the device can revert" is false as stated — the seal is bypassed by any direct-mmap writer, and on a real rooted device the most common scenario (user has KSU installed; KSU ships its own `resetprop`; KSU resetprop writes directly to the arena file bypassing init) defeats both Tier B and Tier A. The scope limitation is documented inside `crates/resetprop/src/seal/hook.rs` and `crates/resetprop/src/lib.rs:446-463` but never surfaces in user-facing docs. Ship this as-is and the first bug report will be "I sealed my prop with `-sl` and KSU resetprop wrote over it in two seconds." This is not a code defect — the seal correctly does what it does — it is a documentation defect that misrepresents the feature's threat model.

---

## Consolidated Verdict

**Round-1 Verdict**: NEEDS_FIX (both agents)

**Converging CRITICALs** (both agents, scope-misrepresentation root):
- **C1 (reviewer + critic)**: KSU/Magisk/resetprop-rs-self direct-mmap bypass not documented; README claim "nothing on the device can revert" is false; Tests 21/22 only probe init-mediated path.

**Critic-unique CRITICAL**:
- **C2 (critic)**: Tier B trampoline residue from Test 21 poisons Test 22; unseal does not revert trampoline; Test 22's success is "Tier A + leftover Tier B" not "Tier A alone".

**Converging MAJORs**:
- **M1 (both)**: Parser accepts conflicting seal flags (`--seal + --unseal`) and silently drops one — no conflict check.
- **M2-reviewer / M3-critic**: Test 21 neighbor-prop probe uses `ro.telephony.call_ring.delay`; SELinux-enforcing devices reject `setprop` on `ro.*` from shell context → false FAIL risk.
- **M3 (critic)**: 15–40 ms init-stall on first `-sl` / `-sla` not surfaced in README.

**Critic-unique MAJORs**:
- **M2 (critic)**: README features bullet at line 96 needs same scope-correction as Seal subsection.
- **M5 (critic)**: Test 21 neighbor-arena co-residence not verified at runtime.
- **M6 (critic)**: `--seals` output format never shown in README; `Prop`/`Arena` Debug labels unexplained.

**Both agents converge on**: the seal feature works as implemented, but the documentation over-claims its scope, and the tests only exercise the path where the seal fires — never the path where it bypasses.

**Fix scope estimate**: 5–7 small edits across `README.md`, `tests/device-stress-test.sh`, and `crates/resetprop-cli/src/main.rs`. Achievable in a single P05.2 fix-lane session under the 5-task cap. No code-surface redesign required; mostly documentation honesty + one parser guard + one test prop swap + one test KSU probe step.
