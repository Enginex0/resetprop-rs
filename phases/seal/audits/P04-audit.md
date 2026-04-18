
## code-reviewer report

**Reviewer:** code-reviewer (claude-sonnet-4-6)
**Date:** 2026-04-18
**Branch:** feat/P04-tier-b-part2 (HEAD c0c4226; base P03 tip 6152faf)
**Scope:** Gate 2 adversarial audit — P04-only diff (13 commits)

---

### External API Verification

All mandatory external sources read directly (not from memory):

| Source | Claim | Verified |
|--------|-------|---------|
| system_properties.cpp:270 | `int SystemProperties::Update(prop_info* pi, const char* value, unsigned int len)` — x0=pi*, x1=value, w2=len | PASS |
| prop_info.h:89 | `static_assert(sizeof(prop_info) == 96, ...)` → PROP_INFO_NAME_OFFSET=96, hook word 1 `add x9,x0,#96` correct | PASS |
| linux-arm64-abi.md §1 | `__NR_membarrier = 283` | PASS |
| arm64-a64-encoding.md §Absolute-target trampoline | `LDR_X16_PC8 = 0x58000050`, `BR_X16 = 0xd61f0200` | PASS |
| arm64-a64-encoding.md §i-cache | `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE = 0x80`; **requires REGISTER (0x40) first** | CRITICAL-1 |

---

### Files Reviewed

- `crates/resetprop/src/seal/hook.rs` (full, 1595 lines)
- `crates/resetprop/src/lib.rs` (lines 295-694, P04 additions)
- `crates/resetprop/tests/tier_b_child_smoke.rs` (full, 219 lines)
- `.cargo/config.toml` (full)
- `phases/seal/P04-tier-b-part2.md` (full spec)
- `phases/seal/checklists/P04-checklist.md` (partial)
- `phases/seal/REGISTRY-P.md` (§1 §2 §4 §7 §8)

---

### Issues

---

**[CRITICAL-1]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:871-879]**
**[DEFECT: membarrier primary path omits mandatory REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (cmd=0x40) pre-registration step, guaranteeing EPERM on every call and silently degrading to ISB-only i-cache sync on every trampoline install. ISB-only is documented as unsafe on SMP.]**

EVIDENCE — arm64-a64-encoding.md §i-cache invalidation options (quoted verbatim):
```
"Requires MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE (0x40)
 registration first; kernel ≥ 4.16; still does not invalidate i-cache
 lines — it only synchronises cores"
```
Code path (hook.rs:871-879):
```rust
let membarrier_ret = unsafe {
    remote_syscall_via_poke(
        handle.pid, handle.scratch_pc, NR_MEMBARRIER,
        [MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0, 0, 0, 0],
    )
};
```
Init (the tracee) has never called membarrier(0x40,...) so the kernel returns -EPERM. The fallback at hook.rs:889 executes `execute_remote_isb`. The ISB fallback is documented in arm64-a64-encoding.md §i-cache: "Only synchronises the core that executed it; other cores may still hold stale i-cache lines; unsafe on SMP unless pinned." On Android SMP devices init may fetch the stale pre-trampoline bytes from i-cache on a core that did not execute the ISB, causing the hook to be silently bypassed.

FIX: Before issuing SYNC_CORE (0x80), first issue remote membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE=0x40, 0, 0, 0, 0, 0). If registration returns -EINVAL (kernel < 4.16), skip to ISB fallback. If 0, then issue SYNC_CORE. Alternatively, per the reference recommendation, prefer __clear_cache (full DC CVAU + IC IVAU + DSB + ISB via the kernel's cache-maintenance path).

---

**[MAJOR-1]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:749-751 (execute_remote_isb success path)]**
**[DEFECT: Success-path register + scratch restore is not atomic — if setregset fails, ptrace_poketext to restore the scratch word is never called, leaving `isb;brk` bytes alive at scratch_pc in the running tracee. Violates the P02 Gate 2 round-2 fix pattern (commit 910ce69) that was applied to remote_syscall_via_poke for exactly this reason.]**

EVIDENCE (hook.rs:749-751):
```rust
setregset(pid, &saved_regs)?;         // failure here skips line 750
ptrace_poketext(pid, scratch_pc, saved_word)?; // scratch_pc stays poisoned
Ok(())
```
REGISTRY §7 S02 note: "wrapped all ?-propagations after scratch clobber with best-effort ptrace_poketext+setregset restore, applied symmetrically to remote_syscall_via_poke." execute_remote_isb was written after that fix but did not inherit it on the success path.

FIX:
```rust
let reg_res  = setregset(pid, &saved_regs);
let poke_res = ptrace_poketext(pid, scratch_pc, saved_word);
reg_res?;
poke_res?;
Ok(())
```

---

**[MAJOR-2]**
**[LOCATION: .cargo/config.toml:18-19]**
**[DEFECT: `--export-dynamic` placed under `[build]` (workspace-global scope) applies to all targets including resetprop-cli release binary, causing measured +40 KB (+9.9%) regression from 410408 B to 451072 B. REGISTRY §2 binary-size target is ≤400 KB arm64 release. Arm64 cross-compile size not measured this phase.]**

EVIDENCE (.cargo/config.toml:18-19):
```toml
[build]
rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]
```
REGISTRY §7 S01 note: "host resetprop-cli --release binary grew from P03 baseline 410408 B to 451072 B (+40 KB)... REGISTRY §2 ≤400 KB arm64 release target at risk."

FIX (preferred): Replace workspace rustflag with explicit export at the declaration site in tier_b_child_smoke.rs using `#[used] #[export_name = "__system_property_update"]` and remove the `[build]` rustflags entry entirely. This restores zero binary size impact on release builds. Alternative: emit the flag from a build script only when `cfg(test)`.

---

**[MAJOR-3]**
**[LOCATION: crates/resetprop/tests/tier_b_child_smoke.rs:172-177]**
**[DEFECT: process_vm_readv partial-transfer not handled — asserts n==92 directly, but linux-arm64-abi.md §10 states "Partial transfers possible; loop until complete." A partial read aborts the test with a misleading assert message rather than retrying.]**

EVIDENCE (tier_b_child_smoke.rs:172-177):
```rust
let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
assert_eq!(n, 92, "process_vm_readv: {}", std::io::Error::last_os_error());
```
linux-arm64-abi.md §10: "Return: bytes transferred, or -1 with errno. Partial transfers possible; loop until complete."

FIX: Loop on partial transfers until 92 bytes are read, or assert n>0 (not n==92) and accumulate into a buffer with advancing pointers.

---

**[MAJOR-4]**
**[LOCATION: phases/seal/P04-tier-b-part2.md §Approach item 4]**
**[DEFECT: Spec prose contains the stale contradictory sentence "HOOK_BODY_OFFSET = 4" alongside the correct "first 1024 bytes of the 4 KB hook page for the list". The checklist Canonical Values row was amended (correctly); the spec paragraph was not. Any future session reading only the spec will encounter directly contradictory constants. Defect: spec inconsistency with code and checklist.]**

EVIDENCE (P04-tier-b-part2.md §Approach item 4, verbatim excerpt):
```
"LOCK_LIST_OFFSET = 0, HOOK_BODY_OFFSET = 4 — byte 0 is the initial empty-list
sentinel NUL...P03 reserved the first 1024 bytes of the 4 KB hook page for
the list, leaving 3072 bytes for the ≤176-byte hook body"
```
Code: `HOOK_BODY_OFFSET: u64 = 1024` (hook.rs:81). Checklist Canonical Values: "HOOK_BODY_OFFSET 4 → 1024 (amended)".

FIX: Amend §Approach item 4 to replace "HOOK_BODY_OFFSET = 4" with "HOOK_BODY_OFFSET = 1024" and note the commit 795ca19 correction.

---

**[MAJOR-5]**
**[LOCATION: phases/seal/P04-tier-b-part2.md §Tasks T3]**
**[DEFECT: Task T3 text says "returns Error::SealHookError on all write failures" but this variant does not exist. REGISTRY §1 Error surface row lists Error::HookInstallFailed(String) as the correct variant. The code correctly uses HookInstallFailed throughout. The stale variant name is a documentation defect that misled two spec reviewers.]**

EVIDENCE (P04-tier-b-part2.md §Tasks T3 verbatim):
```
"returns Error::SealHookError on all write failures"
```
REGISTRY §1: "HookInstallFailed(String)" — the actual variant.
hook.rs (all error returns): `Error::HookInstallFailed(format!(...))`.

FIX: Replace "Error::SealHookError" with "Error::HookInstallFailed" in §Tasks T3.

---

### MINOR Issues

**[MINOR-1]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:449]**
`#[allow(dead_code)]` on the entire `encoder` module is now overly broad — T3 and T4 actively use `LDR_X16_PC8`, `BR_X16`, `ISB_SY`, `BRK_0`. Apply dead_code suppression only to the unused helpers individually.

**[MINOR-2]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:596-598 (HOOK_BODY_TEMPLATE doc comment)]**
Comment says "seed them with nop for the prologue mirrors" but the template initialises words 13-16 with `0xd503_201f` (NOP) and words 19-22 with `0x0000_0000`. The comment conflates NOP-seeding with zero-seeding. Clarify: stolen-prologue slots seeded with NOP; literal slots seeded with zero.

**[MINOR-3]**
**[LOCATION: crates/resetprop/tests/tier_b_child_smoke.rs:199-203 and hook.rs:820/1016/1078]**
`install_init_hook`, `install_trampoline`, `seal_prop`, and `unseal_prop` are declared `pub` (not `pub(crate)`), exposing internal hook mechanics as part of the crate's public API. Callers outside the crate can bypass `PropSystem::seal`'s SERIAL_FILE guard and `set_stealth` pre-call. Downgrade to `pub(crate)` and adjust the integration test to use `#[cfg(test)]` visibility or go through the `PropSystem` surface.

**[MINOR-4]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:919-920]**
Vestigial `// Step 10.` comment with no content. Remove.

**[MINOR-5]**
**[LOCATION: crates/resetprop/src/seal/hook.rs:742 (execute_remote_isb wait_stop)]**
`wait_stop(pid, 0)` is called with event=0 expecting a BRK SIGTRAP. In a multi-threaded tracee (init), a group-stop or syscall-stop on another thread could arrive first, causing spurious `PtraceUnexpectedStatus` and leaving the tracee running. This is the same limitation documented in REGISTRY §8 deferred MAJOR-5 for P02. Recommend documenting this limitation for `execute_remote_isb` in §8 alongside the existing entry.

---

### Positive Observations

1. **Atomic-append invariant correctly implemented.** `seal_prop` issues a single `write_remote` covering entry-bytes + entry-NUL + new-sentinel-NUL before advancing `lock_list_len`. The hook body can never observe a half-written entry.

2. **`build_hook_body_bytes` is genuinely pure.** The signature-pinning test proves the function takes no ptrace context, is testable on any host platform, and produces the spec-locked 92-byte output.

3. **HOOK_BODY_TEMPLATE is byte-for-byte correct.** All 23 words match `arm64-a64-encoding.md` §Hook body sketch lines 383-407 exactly. The reference roundtrip test `build_hook_body_bytes_constants_from_reference` pins words 0-5.

4. **Write-order invariant in install_trampoline is correct.** Body bytes written BEFORE trampoline ensures no half-formed state is observable by init's CPU pipeline.

5. **SERIAL_FILE guard fires before ptrace work.** Both lib.rs and hook.rs check reject conditions (interior NUL, SERIAL_FILE) before any `RemoteAttach::new` call.

6. **All 7 opcode constants verified against canonical references.** The `opcodes_match_canonical_values` test pins every REGISTRY §1 constant. No drift detected.

7. **Trampoline encoding is correct.** `word_lo` packs LDR+BR, `word_hi = hook_body_vaddr` is stored as u64 LE via ptrace_poketext at target_fn+8, which places lo32 at +8 and hi32 at +12 matching the reference exactly.

---

### Verdict Summary

| Severity | Count | Findings |
|----------|-------|---------|
| CRITICAL | 1 | C1: membarrier REGISTER omission → guaranteed EPERM → ISB-only → SMP unsafe |
| MAJOR | 5 | M1: execute_remote_isb non-atomic restore; M2: export-dynamic global scope; M3: partial-transfer not retried; M4: spec §Approach typo persists; M5: spec T3 wrong error variant |
| MINOR | 5 | M1–5 as listed above |

**VERDICT: NEEDS_FIX** — 1 CRITICAL + 5 MAJOR blocking findings.

Required before COMPLETE promotion: fix C1 (membarrier registration), M1 (execute_remote_isb restore symmetry), M2 (export-dynamic scope + arm64 size measurement), M3 (partial-transfer retry), M4 (spec §Approach item 4), M5 (spec T3 error variant).

---

## critic report

**Critic:** critic (claude-opus-4-7)
**Date:** 2026-04-18
**Branch:** feat/P04-tier-b-part2 (HEAD c0c4226; base P03 tip 6152faf)
**Scope:** Gate 2 adversarial audit — P04 architectural + correctness review

---

### Critical Findings

**[CRITICAL 1]**
**[DECISION CHALLENGED: `build_hook_body_bytes` does not splice STRCMP_BODY into HOOK_BODY stub slot — word 5 remains `b .advance` stub; hook never compares names]**

WHY IT'S WEAK: Reference `arm64-a64-encoding.md:348` states "The inline strcmp is stubbed with a direct branch; the installer is expected to splice the 13-word STRCMP_BODY". Line 415 lists splice as a mandatory install-time patching rule. `build_hook_body_bytes` (hook.rs:660-687) only patches STOLEN (words 13..=16), RESTORE (19..=20), LOCK_LIST (21..=22). STRCMP_STUB (word 5) is never patched. Trace of executed hook path with lock-list `"a\0"`: word 3 reads 'a' → word 4 not taken (non-zero) → word 5 executes stub `b .advance (+12)` → word 8 `add x10, x10, #1` → word 9 `b .next_entry (-24)` → word 3 reads '\0' → word 4 takes `cbz .fall_through` → stolen prologue + resume. The hook NEVER calls the strcmp comparison. For ANY lock-list content and ANY property name, the hook becomes a pure pass-through with ~20 cycles branch overhead.

WHEN IT MATTERS: Every invocation. The documented success criterion of the phase ("block init's write to sealed properties") is unmet.

BETTER ALTERNATIVE: Rewrite `build_hook_body_bytes` to splice `STRCMP_BODY` over word 5 (pushing words 6..=12 down or restructuring the frame); rewrite "scan past NUL" at word 8 (current `add x10,x10,#1` is wrong — should be `ldrb w11,[x10],#1; cbnz w11,.-4`); rebind x1 to the current lock-list entry pointer before entering the splice (STRCMP_BODY reads `[x0]` vs `[x1]`); add an integration test that actually exercises the hook body against a real call path.

---

**[CRITICAL 2]**
**[DECISION CHALLENGED: `tier_b_child_smoke` test design — child's Rust call to `#[no_mangle] __system_property_update` does not route through the symbol resolved by stage-A's ELF parse; `is_libc_row` filter does not match the test binary]**

WHY IT'S WEAK: Two mutually-reinforcing problems:
(a) Rust/rustc typically resolves the child's direct call via intra-module direct-branch, NOT through the `.dynsym` entry that stage-A patches. Even with `--export-dynamic`, the test binary's compiled call may bypass the patched symbol.
(b) Stage-A's `is_libc_row()` filter (`perms == b"r-xp" && path ends_with "/libc.so"`) does not match the test binary's ELF row. Stage-A either fails with "libc row not found" or, if bionic libc.so is mapped into the test process, patches a symbol the child never calls.

Either path, the assertion `locked_before == locked_after` can pass for the wrong reason (e.g., two snapshots of a 5ms-churning value with identical byte prefixes given the fake's `v{tick}` format).

WHEN IT MATTERS: Gate 2 cannot rely on this integration test as evidence of Tier B function.

BETTER ALTERNATIVE: (a) relax `is_libc_row` to accept a test-only alternate path via cfg flag and verify the child's call routes through its own `.dynsym`; (b) load a shim cdylib (like P03's `elf_fixture`) and have the child call through the cdylib; (c) delete the sacrificial-child design for Tier B and make aarch64 device-run against real init the acceptance criterion.

---

**[CRITICAL 3]**
**[DECISION CHALLENGED: `install_trampoline` issues `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` without `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` (0x40) pre-registration]**

WHY IT'S WEAK: Overlaps code-reviewer CRITICAL-1 verbatim. `arm64-a64-encoding.md:422` requires REGISTER first; kernel returns -EPERM without it. Fallback `execute_remote_isb` is documented unsafe on SMP (line 423).

WHEN IT MATTERS: First hook invocation on any multi-core Android device.

BETTER ALTERNATIVE: (a) issue REGISTER (0x40) before SYNC_CORE; (b) switch to `__clear_cache` via libc.so symbol resolution (full DC CVAU + IC IVAU + DSB + ISB); (c) rely on `ptrace_poketext` maintaining IC on the trampoline page and delete the membarrier/ISB path entirely, documenting the ABI assumption.

---

**[CRITICAL 4]**
**[DECISION CHALLENGED: `Error::SealHookError` named in spec Task 3; code uses `Error::HookInstallFailed`; Gate 2 PASS would sign off a contradictory record]**

WHY IT'S WEAK: Overlaps code-reviewer MAJOR-5 — critic upgrades because Gate 2 is the scrutiny boundary where drift gets cemented.

WHEN IT MATTERS: Future sessions reading only the spec generate agents that match a nonexistent variant.

BETTER ALTERNATIVE: Amend P04 spec Task 3 + checklist to `Error::HookInstallFailed` (single find-replace).

---

### Major Findings

**[MAJOR 1]** Workspace-wide `--export-dynamic` rustflag. Overlaps reviewer MAJOR-2. Upgraded justification: three compounding harms beyond size — (a) +40KB breach of REGISTRY §2 400KB target, (b) security surface (dlsym leak of internal symbols — the entire point of `resetprop-rs` is resistance to property manipulation), (c) platform drift (`-Wl,--export-dynamic` is GNU-ld specific, silently breaks cross-compile to non-GNU-ld targets). FIX: `build.rs` emitting `cargo:rustc-link-arg-tests=-Wl,--export-dynamic` scoped to test-binaries within one crate.

**[MAJOR 2]** Lock-list + hook body co-located in same 4KB page (`LOCK_LIST_CAPACITY=1024` + `HOOK_BODY_OFFSET=1024`). Code comment admits: "exceeding it would clobber the body's first instruction (word 0 of the 92-byte hook body at hook_page + 1024), crashing init on its next trampoline entry". At ~40 seals with avg name length 25B, capacity hits hard-fail. FIX: two-page layout (one RW for list, one RX for body, optional unmapped guard page) — +8KB negligible for init, eliminates clobber failure mode.

**[MAJOR 3]** `seal_prop` advances `handle.lock_list_len = new_len` AFTER `attach.detach()`. If tracer is interrupted between detach and counter update, tracer-side counter stays at old length; next `seal_prop` computes wrong `write_start` and overwrites the previous entry's last byte + trailing sentinel. FIX: bump counter BEFORE detach — keeps all transitions inside the attach window.

**[MAJOR 4]** `hook_handle: OnceLock<Mutex<Option<HookHandle>>>` — three-layer wrapper where Mutex is vestigial (kernel ptrace-SEIZE already serializes) and poisoning permanently breaks the API (any panic mid-install → all future `seal` calls fail with "mutex poisoned"). FIX: apply `lock().unwrap_or_else(|p| p.into_inner())` poison recovery pattern already used at `lib.rs:814-818` for the seals registry.

**[MAJOR 5]** Hook body x1 register handling: (a) STRCMP_BODY (once spliced per CRITICAL 1) reads `[x0]` and `[x1]`, but x1 at hook entry is `value` from bionic ABI — must rebind x1 before splice; (b) fallthrough path re-executes 4 stolen prologue instructions which may clobber x9/x10/x11 under PAC (`paciasp`) or HWASAN variants on Android 14+. Documentation gap: hook body's register invariants not stated.

**[MAJOR 6]** `lock_list_remove_bytes` uses `buffer[new_cur_len + 1..=tail]` slice arithmetic that is brittle under tracer-side counter skew (MAJOR 3). No current path panics, but the idiom is fragile. FIX: `buffer[new_cur_len as usize..=tail].fill(0)` after `copy_within` — simpler, no `+1` arithmetic.

**[MAJOR 7]** Stage-A runs entirely inside the `RemoteAttach` window, with init ptrace-stopped for 15-40ms (libc.so ELF parse + GNU_HASH walk + maps parse). Zygote and daemons block for that window. Acceptable for operator-initiated one-shot seal; must be documented in REGISTRY §2 or P04 spec as a known stall.

---

### Minor Findings

**[MINOR 1]** `finish_stage_b_locked` returns `saved_prologue` as `[u8; 16]`; `[u32; 4]` would be more type-safe downstream.

**[MINOR 2]** `fits_signed` at hook.rs:456-459 diverges from reference form over clippy `int_plus_one`. Semantically equivalent; record in REGISTRY §1 so future auditors don't re-flag.

**[MINOR 3]** `LOCK_LIST_CAPACITY` and `HOOK_BODY_OFFSET` both 1024 but constrained independently — a single `const PAGE_SPLIT: u64 = 1024;` + derivations would prevent drift.

**[MINOR 4]** `execute_remote_isb` duplicates the PEEK+POKE+getregset+setregset+CONT+wait_stop skeleton from `remote_syscall_via_poke`. Extract shared `execute_one_shot(pid, scratch_pc, payload_u64)` helper.

**[MINOR 5]** `ChildGuard::drop` waitpid pattern is copy-pasted from `tier_a_child_smoke.rs`. Document in test-harness-patterns reference.

**[MINOR 6]** `tier_b_child_smoke.rs:60` `#[no_mangle] pub extern "C" fn __system_property_update` has unsafe body but function not marked `unsafe fn`. Valid Rust but violates REGISTRY §2 row 12 convention at declaration level.

**[MINOR 7]** `FakePropInfoHeader.value` is `[u8; 92]`; fake's `copy_nonoverlapping` uses `min(91)` — inconsistent with bionic `PROP_VALUE_MAX=92`.

---

### What's Missing

- No test proves the hook body actually executes on a real call path.
- No test for membarrier registration step (even if CRITICAL 3 is fixed).
- No test that stolen-prologue re-execution correctly handles PAC/BTI libc prologue.
- No rollback test for `install_trampoline` mid-flight failure (membarrier fails AND ISB staging fails).
- No multi-seal-then-unseal stress test.
- No device test against a libc with PAC/BTI prologue.
- No size-regression gate in CI (flagged in session report but not automated).
- No pre-mortem for init-crash with trampoline installed.

---

### Multi-Perspective Notes

**Executor**: Can an executor follow P04 and land correct code? NO. Spec Task 2 text ("produces the strcmp-loop hook body") is compatible with either "emits template stub" or "splices STRCMP_BODY". Reference §Hook body sketch's `HOOK_BODY` const is written in stub form with comments saying "installer splices strcmp here" — but at the wrong layer (on the template, not in the installer's instruction list). An executor reading only Task 2 + template produces exactly what this session produced. Spec lacks an explicit splice step.

**Stakeholder**: Does this plan solve the stated problem? Per REGISTRY §1 "seal mechanisms shipped: Tier A AND Tier B", the problem is "block init's write to sealed properties". With STRCMP_BODY splice missing, Tier B blocks nothing. Not solved.

**Skeptic**: Strongest production failure modes:
1. SMP i-cache coherence: membarrier lacks REGISTER, ISB runs on one core, other cores prefetch stale bytes → first hook call races.
2. 40-60ms init stall blocks zygote, delays app launches.
3. Lock-list capacity hard-fail at ~40 entries with no graceful retry.

Counter-defense: P05 is on-device-only; device-run catches SMP + timing. Counter-counter: REJECT until an integration test proves the hook actually blocks a mutation.

---

### Verdict

**VERDICT: NEEDS_FIX** — 4 CRITICAL + 7 MAJOR findings block Gate 2 PASS.

Four critical defects are systemic: Task 2's template was copied verbatim without completing the splice; Task 3's i-cache sync has no registration step; Task 5's integration test yields false positive regardless of hook install success; Task 3's spec-declared error variant does not exist. P04 `SEGMENT_COMPLETE` status in REGISTRY §4 is premature.

Path to ACCEPT:
1. Fix CRITICAL 1 (STRCMP_BODY splice + scan-past-NUL at word 8 + x1 rebind) with round-trip test decoding spliced body.
2. Fix CRITICAL 2 (redesign integration test to actually install-and-fire, OR replace with aarch64 device-run gate).
3. Fix CRITICAL 3 (REGISTER pre-call, OR switch to `__clear_cache`, OR remove membarrier path + document POKETEXT IC maintenance as primary).
4. Fix CRITICAL 4 (amend P04 spec to `HookInstallFailed`).
5. Fix MAJOR 1 (narrow rustflag to test-binaries via build.rs).
6. Fix MAJOR 3 (counter advance before detach).
7. At minimum document MAJOR 2 (single-page layout) in REGISTRY §1 as "acceptable for operator-initiated ≤40 seals".
8. Fix MAJOR 5 (document hook body register invariants; implement scan-past-NUL as part of CRITICAL 1 fix).

After all blocking findings resolved, re-dispatch both Gate 2 agents.

