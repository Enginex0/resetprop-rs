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

---

## Addendum — ksu_props empirical analysis (2026-04-18)

**Source**: `https://github.com/Kernel-SU/ksu_props` cloned at `.analysis/ksu_props/`. Two sonnet agents dispatched in parallel (write-path tracer + init-routing verifier) with independent prompts. Both converged with file:line citations.

### Key finding — ksu_props has TWO write paths

The dispatch branch is at `crates/prop-rs-android/src/sys_prop.rs:580`:

```rust
let force_skip = skip_svc || key.starts_with("ro.");
```

| Condition | Write primitive | File:line | Routes through init? | Seal catches? |
|---|---|---|---|---|
| Any `ro.*` key (ALWAYS) | Direct mmap — `core::ptr::copy_nonoverlapping` into MAP_SHARED mmap of `/dev/__properties__/<ctx>` | `mmap_prop_area.rs:277` | NO | **NO** |
| `-n` / `--skip-svc` flag on any key | Direct mmap (same path) | `mmap_prop_area.rs:277` | NO | **NO** |
| Mutable key, no `-n` flag | bionic `__system_property_set` via dlsym | `sys_prop.rs:612` | YES (socket → init → `__system_property_update`) | **YES** |

### Dependencies scanned

`crates/prop-rs-android/Cargo.toml` declares `libc`, `memmap2`, `log` — no Android property-service crate. The only init contact is the dlsym-loaded `__system_property_set` function pointer used conditionally.

### Implication for the C1 finding

My earlier CRITICAL framing ("seal is bypassed by direct-mmap writers") was correct in direction but imprecise on scope. The correct statement:

- The seal IS effective for mutable properties written without the `-n` flag (bionic routing through init).
- The seal is NOT effective for `ro.*` properties (which are the primary spoofing target — fingerprint, serial, telephony identities) because ksu_props unconditionally routes those through direct-mmap regardless of any flag.
- The seal is NOT effective when the `-n` flag is used on any key.

This matters because the property in Test 21 (`ro.telephony.default_network`) is exactly the case that bypasses the seal via ksu_props. A user running `/data/adb/ksu/bin/resetprop ro.telephony.default_network 99` overwrites the sealed prop without triggering the Tier B hook.

### Fix guidance for P05.2 (sharpens the C1 remediation)

1. **README Seal subsection** must enumerate the write paths the seal covers vs bypasses:
   - COVERED: `setprop`, `property_service`, any caller of bionic's `__system_property_set` (socket path)
   - NOT COVERED: ksu_props with `ro.*` keys or `-n` flag, Magisk resetprop (same direct-mmap pattern), resetprop-rs itself (same pattern — `PropSystem::set` at `lib.rs:446-463`)

2. **Test 21 should include a KSU resetprop probe** after the `setprop` loop:
   - Check `[ -x /data/adb/ksu/bin/resetprop ]`
   - Attempt `ksu_props resetprop "$TEL_PROP" "99"` (will take direct-mmap path for the `ro.*` prefix)
   - Log the outcome as `WARN` (not `FAIL`) — documenting the expected bypass
   - Makes the seal's scope limitation empirically observable instead of invisible

3. **The "nothing on the device can revert" phrasing** must be replaced with "no init-mediated writer can revert". The spoof-persistence use case the feature markets itself for needs honest threat-model docs.

### Evidence preserved

The cloned repo at `.analysis/ksu_props/` (scratch, gitignored) retains the source tree for follow-up inspection. Key files for future reference:
- `tools/resetprop/src/main.rs:185` — CLI entry
- `crates/prop-rs-android/src/resetprop.rs:64` — `ResetProp::set` delegates to `sys_prop::set`
- `crates/prop-rs-android/src/sys_prop.rs:580-616` — the dual-path dispatch
- `crates/prop-rs-android/src/mmap_prop_area.rs:274-278` — the `write_bytes_data` primitive (the direct-mmap write)
- `crates/prop-rs-android/src/sys_prop.rs:612` — the bionic `__system_property_set` call site (the init-routed path)

---

## P05 Gate 2 round-2 — code-reviewer (sonnet)

**Date**: 2026-04-19
**Branch**: feat/P04-tier-b-part2 @ ba0e1b4
**Scope**: P05.2 fix-lane commits `75f4e75`, `4ba60ed`, `919a146`, `8e9a4c0`, `ba0e1b4` + round-1 findings verification

### Verdict: NEEDS_FIX

### Round-1 findings verification

| Finding | Status | Evidence |
|---------|--------|----------|
| C1 scope misrepresentation | RESOLVED | `README.md:96` rewritten with scoped claim; `README.md:100` enumerates bypass vectors citing `sys_prop.rs:580` + `mmap_prop_area.rs:277`; `tests/device-stress-test.sh:367-376` adds KSU probe after primary assertion |
| C2 Test 22 Tier B residue | RESOLVED | `tests/device-stress-test.sh:393` swaps to `ro.telephony.sms_receive_mode`; commit `ba0e1b4` message cites `hook.rs:154-158` trampoline invariant |
| M1 parser silent drop | RESOLVED | `main.rs:160-175` boolean-array + filter/count guard covers all 5 flag combinations; fires before any seal dispatch |
| M2 Test 21 SELinux neighbor | RESOLVED | `tests/device-stress-test.sh:333-337` pre-flight writability probe; assertion conditional on `NEIGHBOR_WRITABLE` |
| M3 stall doc gap | RESOLVED | `README.md:102` Attach-window stall bullet with 15-40 ms range matching `hook.rs:276-287` rustdoc |
| M5 arena co-residence | NOT_RESOLVED | No runtime assertion added in either Test 21 or Test 22; both tests rely on an unverified out-of-band invariant |
| M6 `--seals` output example | NOT_RESOLVED | README Seal subsection extended to 8 bullets but no example output shown; `Prop` / `Arena` Debug labels unexplained |

### New findings

#### CRITICAL
None.

#### MAJOR

**N1** — `README.md:102` "Subsequent calls against the already-installed hook complete in under 5 ms" has no source evidence. `hook.rs:276-287` documents the 15-40 ms first-install window only. A subsequent `seal()` call at `lib.rs:623` goes through the `slot.lock()` → `is_some()` fast-path skipping `install_init_hook` and `install_trampoline` (so is indeed faster) but "under 5 ms" is an unsubstantiated specific figure. Factual accuracy defect in user-facing documentation.

**Fix**: Remove the specific latency figure or replace with a qualitative statement grounded in the code path.

#### MINOR

**N2** — Test 22 SKIP branch at `tests/device-stress-test.sh:407` uses plain `log`; neither `PASS` nor `FAIL` incremented. Summary does not reflect skipped tests. Internally consistent (no false PASS) but a `$SKIP` counter would make the summary honest.

**N3** — Test 21/22 restore paths write empty `$NEIGHBOR_ORIG` / `$ORIG_A` via `setprop ... ""`; empty-value semantics are platform-dependent. Inherited pattern, not introduced by P05.2.

**N4** — `tests/device-stress-test.sh:367` gates KSU probe on `[ -x /data/adb/ksu/bin/resetprop ]` — checks executability not identity. If the path holds a non-ksu_props binary the WARN log misattributes the bypass. Cosmetic.

### Positive observations

- `main.rs:160-175` seal_flag_count guard is flat and self-documenting; extends by array rather than or-chained predicates.
- KSU probe placement in Test 21 is well-designed: after `SEALED_FINAL` captured (no primary-assertion contamination), before cleanup (bypass empirically observable on real KSU).
- Test 22 swap (`ro.telephony.sms_receive_mode`) is minimum-code-churn correct fix for C2.
- `README.md:100` bypass-surface bullet cites exact file:line for both dispatch branch and write primitive; scopes threat model correctly.
- `README.md:102` 15-40 ms stall figure faithful to `hook.rs:279-283`.

### Summary

P05.2 resolves all round-1 load-bearing findings (C1, C2, M1, M2, M3) with correct implementations. Two round-1 MAJORs (M5, M6) remain unaddressed. One new MAJOR (N1 unsupported "under 5 ms") requires removal/qualification before close.

---

## P05 Gate 2 round-2 — critic (opus)

**Date**: 2026-04-19
**Branch**: feat/P04-tier-b-part2 @ ba0e1b4

### Verdict: PASS-WITH-RESERVATIONS

### Multi-perspective analysis

#### Executor

Rooted operator runs `$RP -sl ro.telephony.default_network 0` on a KSU device. The `README.md:100` bypass-surface bullet gives concrete disclosure: exact KSU binary path (`/data/adb/ksu/bin/resetprop`), exact dispatch branch (`sys_prop.rs:580`), exact write primitive (`mmap_prop_area.rs:277` `copy_nonoverlapping`), trigger conditions (`ro.*` prefix or `-n` flag). When the operator subsequently runs `/data/adb/ksu/bin/resetprop ro.foo quux`, they are prepared. Not abstract "may be bypassed" — teaches both cause (direct-mmap) and discriminator (prefix/flag). Edge case: Test 22 on a device where `ro.telephony.sms_receive_mode` is absent or read-only — SELinux pre-probe at `tests/device-stress-test.sh:400-404` correctly emits SKIP.

#### Stakeholder

Bypass-surface bullet is #5 under **Seal** (after two-tier summary, Tier B default, Tier A fallback, -st semantics). The lead bullet at `README.md:96` now carries scoped language ("no `setprop`, `property_service`, or bionic `__system_property_set` caller can revert") so the reader is front-loaded with scope before reaching the explicit bypass list. M6 (`--seals` output example) still missing. CLI-reference `--seal-arena` row at `README.md:248` still reads "Broader blast radius, use when Tier B cannot install" — implies auto-fallback; unaddressed in fix lane (round-2 R2-m1).

#### Skeptic

- 15-40 ms claim faithful to `hook.rs:276-287` rustdoc, which explicitly notes "Observed wall-clock on a modern ARM64 handset (Snapdragon-class SoC, bionic libc.so ~1.2 MiB, ~5000 .dynsym entries)". README generalizes to "on modern ARM64 handsets" plural, dropping device-class qualifiers — minor doc drift.
- Test 21 and Test 22 use literal string `"SELINUX_PROBE"` as sentinel. Collision with a real prop value is astronomically unlikely but a randomized sentinel would be bulletproof.
- Empty-ORIG restore at `tests/device-stress-test.sh:404` (`setprop ... ""`) is shell-valid but sets prop to empty string instead of deleting. Pre-existing pattern.
- Permissive-device masking: on permissive/non-enforcing build, pre-probes unconditionally succeed → full assertion fires. Desired behavior, not masking.
- Test 22 swap claims same `telephony_prop` arena but NOT runtime-asserted (exact M5 finding, unaddressed).

#### Realist

All five round-1 blocking-tier findings addressed with evidence in 5 commits. M5 and M6 silently deferred without REGISTRY §8 entry or commit message acknowledging the deferral — future gate reviews may re-flag as new findings. Fix scope was "~5 edits" per `REGISTRY-P.md:97`; author executed within that scope. Severity check: C1 resolution via README bullet + Test 21 WARN probe is sufficient. Seal code unchanged (correctly does what it does); fix is documentation honesty + empirical test surface. No residual risk of data loss, security, or financial impact.

### Round-1 findings verification

Same as reviewer table above. Convergence: C1, C2, M1, M2, M3 RESOLVED; M5, M6 NOT_RESOLVED.

### New findings

#### CRITICAL
None.

#### MAJOR

**R2-M1** — Silent deferral of M5 and M6 without REGISTRY documentation. `REGISTRY-P.md:97` P05 row enumerates round-1 findings C1/C2/M1/M2/M3 as load-bearing but omits M5 and M6. §8 Deferred Audit Findings has entries for P02 MAJOR-5, MAJOR-8, and P04 CRITICAL-2 but nothing for P05. Undocumented deferrals drift into silent tech debt.

**Fix**: Either land M6 (~5 lines: add `$ resetprop-rs --seals` example to README Seal subsection) or add §8 entries documenting the decision to defer with V2 plan.

#### MINOR

**R2-m1** — `README.md:248` CLI-reference `--seal-arena` row still reads "Broader blast radius, use when Tier B cannot install" — implies auto-fallback.

**R2-m2** — `README.md:102` generalizes 15-40 ms to "modern ARM64 handsets" plural while `hook.rs:278-279` rustdoc qualifies to specific device class. Minor doc drift.

**R2-m3** — `tests/device-stress-test.sh:333,400` literal sentinel `"SELINUX_PROBE"` — randomized sentinel would be bulletproof.

**R2-m4** — Empty-ORIG restore inherited from Test 18 pattern. Pre-existing.

**R2-m5** — `main.rs:180` `--seals` Debug output `[{tier:?}]` emits `Arena`/`Prop`. Users have no scaffolding; same root cause as M6 — fix one, both dissolve.

### What's missing

- `--seals` output example in README (M6).
- Arena co-residence runtime assertion in Test 21/22 (M5).
- §8 REGISTRY entry documenting M5/M6 decision.
- CLI-reference "broader blast radius" phrasing (R2-m1).
- Parser-guard unit test for `--seal A --unseal A` rejection.

### Load-bearing defect

None applicable — no CRITICAL or blocking MAJOR. R2-M1 is process hygiene, not technical blocker.

### Summary

P05.2 materially ready to close. 5 commits directly address round-1's load-bearing findings with evidence-backed implementations matching source-of-truth code. Two round-1 findings unaddressed without deferral documentation — minor process gap, not technical blocker. Recommend PASS-WITH-RESERVATIONS + follow-up commit addressing R2-M1.

---

## Consolidated Round-2 Verdict

**Reviewer (sonnet)**: NEEDS_FIX (1 MAJOR + 3 MINOR new; M5/M6 NOT_RESOLVED)
**Critic (opus)**: PASS-WITH-RESERVATIONS (1 MAJOR + 5 MINOR new; M5/M6 NOT_RESOLVED)

**Convergence**: Both agents verify round-1 C1, C2, M1, M2, M3 as RESOLVED with file:line evidence. Both flag M5 (arena co-residence) and M6 (`--seals` output example) as NOT_RESOLVED carryovers.

**Divergence**: Reviewer uniquely flags N1 (under-5-ms unsubstantiated claim in README) as MAJOR. Critic uniquely flags R2-M1 (silent M5/M6 deferral) as MAJOR. Both agents converge on all other findings.

### Closure commits (round-2 follow-up, S07)

- `4fce23c` docs(readme): close P05 Gate 2 round-2 N1 + M6 + R2-m1
  - Removes the unsupported "under 5 ms" figure (closes reviewer N1)
  - Adds `### Sealing properties` subsection with `$ resetprop-rs --seals` example showing `[Prop]`/`[Arena]` Debug labels (closes critic M6)
  - Rewrites CLI-reference `--seal-arena` row to state "no auto-fallback — invoke manually" (closes critic R2-m1)

- This audit append + new `REGISTRY-P.md` §8 entry formally defers M5 (arena co-residence runtime assertion) with V2 plan — closes critic R2-M1.

### Post-closure status

All round-2 load-bearing defects resolved or formally deferred with V2 plans. P05.2 fix-lane SEGMENT_COMPLETE; P05 awaits the aarch64 on-device acceptance run to promote P05 and P04 to COMPLETE per the P04.2 T3 co-closure decision.
