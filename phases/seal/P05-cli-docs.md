# P05: CLI, Docs, and On-Device Acceptance

## Objective

Expose the seal feature through the CLI surface by wiring five new parser arms, a dispatch block, and updated `print_usage()` to the already-verified library API; document the new commands in README.md with a new "Seal" subsection and CLI-reference rows; extend `tests/device-stress-test.sh` with Tests 21 and 22 that validate Tier B per-prop precision and Tier A arena-level enforcement on a rooted device.

## Preconditions

- [ ] P02 (Tier A: arena-level seal) shows COMPLETE in REGISTRY §4 — provides `PropSystem::seal_arena` and `PropSystem::unseal_arena`
- [ ] P04 (Tier B pt2: trampoline + lock-list) shows COMPLETE in REGISTRY §4 — provides `PropSystem::seal`, `PropSystem::unseal`, `PropSystem::seals`, and the `SealRecord` / `SealTier` types
- [ ] Files that must exist: `crates/resetprop-cli/src/main.rs`, `README.md`, `tests/device-stress-test.sh`
- [ ] Library public API names stable: `seal`, `unseal`, `seals`, `seal_arena`, `unseal_arena` on `PropSystem` (per plan §New public API in `crates/resetprop/src/lib.rs`)
- [ ] `Error` variants `HookInstallFailed`, `ElfParse`, `SymbolNotFound` available (per plan §Error variants in `crates/resetprop/src/error.rs`)

## Scope

### Files to CREATE

(none — all modifications; this phase adds only dispatch glue and docs)

### Files to MODIFY

| File | Changes |
|------|---------|
| `crates/resetprop-cli/src/main.rs` | Five new parser arms inside the existing `while i < args.len()` loop (after the `-st` arm at line 54), five new locals near the top of `run()`, one new dispatch block BEFORE the positional handler at line 138, and new rows in `print_usage()` (lines 254-288) for `-sl`/`--seal`, `-sla`/`--seal-arena`, `--unseal NAME`, `--unseal-arena NAME`, `--seals` |
| `README.md` | New "Seal" subsection after the "Stealth" subsection (around line 82) and five new rows in the CLI-reference Options table (lines 232-248) |
| `tests/device-stress-test.sh` | Append Test 21 (Tier B: sealed prop holds, neighbor updatable) and Test 22 (Tier A: sealed prop holds) following the Test 18 stress block at lines 253-276; adjust PASS/FAIL tallies |

## Reference Material

Read ONLY these at session start:

| File | Sections | Est. Tokens | Why |
|------|----------|-------------|-----|
| `phases/seal/references/resetprop-rs-integration.md` | §11 CLI Parser and Dispatch (main loop lines 34-85, dispatch lines 138-177, `arg_val` at 182-186, `bool_op` at 188-204, `print_usage` at 254-288); §12 Device Stress Test pattern (Test 18 at lines 253-276) | ~1400 | The authoritative map of where each new line goes and what pattern to mirror (`--nuke\|-nk` at 50-53, `--stealth\|-st` at 54). Required to hit exact insertion points without guessing. |

## External API Verification

- **Required**: YES
- **Source**: `phases/seal/references/resetprop-rs-integration.md` §11 (the CLI parser pattern documentation, including the `--nuke|-nk` template at `crates/resetprop-cli/src/main.rs:50-53` and `--stealth|-st` template at `crates/resetprop-cli/src/main.rs:54`).
- **Justification**: Gate 2 agents must verify that the CLI parser additions (new flags `-sl`, `-sla`, `--seal`, `--seal-arena`, `--unseal`, `--unseal-arena`, `--seals`) match the existing `--nuke|-nk` / `--stealth|-st` template exactly — same short/long pattern, same `arg_val`/`bool_op` helper usage, same insertion point inside the `while i < args.len()` loop. The underlying `libc` / AOSP / bionic signatures are owned by the core seal modules (P01-P04) and are consumed here unchanged; no new AOSP/bionic verification is required beyond the CLI parser template conformance.

## Tasks (Max 5 Per Session)

### Single-Segment Format (5 tasks)

1. **Task 1 — Parser arms**: Add five new match cases inside the existing `while i < args.len()` loop in `crates/resetprop-cli/src/main.rs` (mirror the `--nuke|-nk` pattern at lines 50-53 and the `--stealth|-st` pattern at line 54). Declare five new locals near the top of `run()` — `let mut seal: Option<String> = None;`, `let mut seal_arena: Option<String> = None;`, `let mut unseal: Option<String> = None;`, `let mut unseal_arena: Option<String> = None;`, `let mut list_seals = false;`. Add parser arms: `"--seal" | "-sl"` → `i += 1; seal = Some(arg_val(&args, i, "--seal")?);`, `"--seal-arena" | "-sla"` → `i += 1; seal_arena = Some(arg_val(&args, i, "--seal-arena")?);`, `"--unseal"` → `i += 1; unseal = Some(arg_val(&args, i, "--unseal")?);`, `"--unseal-arena"` → `i += 1; unseal_arena = Some(arg_val(&args, i, "--unseal-arena")?);`, `"--seals"` → `list_seals = true;`. — Files: `crates/resetprop-cli/src/main.rs` — Verifies: `cargo build -p resetprop-cli` exits 0 and `grep -E '"-sl"|"-sla"|"--seals"' crates/resetprop-cli/src/main.rs` returns non-empty.
2. **Task 2 — Dispatch block**: Insert a new dispatch block in `crates/resetprop-cli/src/main.rs` BEFORE the positional handler at line 138. The block handles — in order: (a) if `list_seals` is true, iterate `sys.seals()?` and `println!("[{name}]: [{tier:?}] {arena}", name=r.name, tier=r.tier, arena=r.arena_path.display())` for each record, then `return Ok(());`; (b) if `unseal.is_some()`, call `sys.unseal(&name)` and use `bool_op(...)` with label `"unseal"`; (c) if `unseal_arena.is_some()`, call `sys.unseal_arena(&name)` and use `bool_op` with label `"unseal-arena"`; (d) if `seal.is_some()`, take `positional[0]` as the VALUE (one positional arg expected after the flag-supplied NAME), call `sys.seal(&name, &value)`; on `Err(Error::HookInstallFailed(_) | Error::ElfParse(_) | Error::SymbolNotFound(_))` emit `eprintln!("Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback.");` and `return Ok(ExitCode::FAILURE);` — but since `run()` returns `Result<(), String>`, surface the Tier-B message via `Err(format!("Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback."))`; (e) if `seal_arena.is_some()`, symmetric behaviour calling `sys.seal_arena(&name, &value)`. All five branches `return` or `return Ok(())` so the subsequent positional match is not entered. — Files: `crates/resetprop-cli/src/main.rs` — Verifies: `./target/release/resetprop -sl ro.test.prop 1 2>&1 | head -5` does not panic and `./target/release/resetprop --seals 2>&1 | head -5` returns without error when no seals exist.
3. **Task 3 — `print_usage()` update**: Update `print_usage()` in `crates/resetprop-cli/src/main.rs` (lines 254-288). In the "Usage" block (lines 258-277), insert — directly after the `--stealth|-st -p` row at line 269 — five new rows preserving column alignment: `resetprop --seal\|-sl NAME VALUE     Stealth write + Tier B per-prop init hook (default seal)`, `resetprop --seal-arena\|-sla NAME VALUE  Stealth write + Tier A arena privatize (fallback)`, `resetprop --unseal NAME            Remove NAME from the Tier B lock list`, `resetprop --unseal-arena NAME      Revert Tier A arena privatization for NAME`, `resetprop --seals                  List active seals (name, tier, arena)`. In the "Options" block (lines 279-287), insert directly after the `--stealth, -st` row at line 283 five new rows: `--seal, -sl     Tier B seal: stealth write + per-prop hook on __system_property_update in init`, `--seal-arena, -sla  Tier A seal: stealth write + remap init's arena as MAP_PRIVATE|MAP_FIXED`, `--unseal NAME   Remove NAME from the in-init Tier B lock list`, `--unseal-arena NAME  Revert Tier A privatization for the arena holding NAME`, `--seals         List currently active seals for this session`. Keep total block width consistent with existing rows. — Files: `crates/resetprop-cli/src/main.rs` — Verifies: `./target/release/resetprop -h 2>&1 | grep -c -E '\-\-seal|\-\-unseal|\-\-seals'` returns at least 10 (five usage rows + five option rows).
4. **Task 4 — README.md updates**: Insert a new "**Seal**" subsection in `README.md` AFTER the "Stealth" subsection ending at line 94 (after the `- [x] **Arena compaction** ...` bullet). The new subsection must explain five points: (a) seal = stealth + ptrace-driven lock that nothing on the device can revert; (b) `-sl` / `--seal` is the default (per-prop Tier B hook on `__system_property_update`); (c) `-sla` / `--seal-arena` is the Tier A arena-level fallback that privatizes init's entire arena mapping; (d) `-st` / `--stealth` remains unchanged — pure stealth write, no ptrace, no hook, 100% back-compat for existing scripts; (e) seals do not persist across reboots — user must re-run after every boot (persistence is deferred per plan). Then, in the CLI-reference Options table at lines 232-248, insert five new rows AFTER the existing `--stealth, -st` row (line 236), preserving the two-column `| Flag | Description |` format: `| \`--seal NAME VALUE\`, \`-sl NAME VALUE\` | Tier B seal (default): stealth write + per-prop init hook. Does not persist across reboots. |`, `| \`--seal-arena NAME VALUE\`, \`-sla NAME VALUE\` | Tier A seal (fallback): stealth write + arena-level MAP_PRIVATE in init. Broader blast radius, use when Tier B cannot install. |`, `| \`--unseal NAME\` | Remove NAME from the Tier B in-init lock list. |`, `| \`--unseal-arena NAME\` | Revert Tier A privatization for the arena holding NAME. |`, `| \`--seals\` | List active seals (name, tier, arena). |`. — Files: `README.md` — Verifies: `grep -c '^\*\*Seal\*\*' README.md` returns ≥1 and `grep -c -E '\-\-seal\|\-sl|\-\-seal-arena\|\-sla|\-\-seals|\-\-unseal' README.md` returns ≥5.
5. **Task 5 — device-stress-test.sh append**: Append Test 21 (Tier B with neighbor verification) and Test 22 (Tier A arena stress) to `tests/device-stress-test.sh` directly after the Test 20 (or current final-test) block, following the Test 18 stress pattern at lines 253-276. **Test 21**: declare `TEL_PROP="ro.telephony.default_network"` and `NEIGHBOR_PROP="ro.telephony.call_ring.delay"`; save `ORIG=$(getprop "$TEL_PROP")` and `NEIGHBOR_ORIG=$(getprop "$NEIGHBOR_PROP")`; run `$RP -sl "$TEL_PROP" "0"`; loop `for i in $(seq 1 50); do setprop "$TEL_PROP" "99"; sleep 0.05; done`; set `SEALED_FINAL=$(getprop "$TEL_PROP")`; run `setprop "$NEIGHBOR_PROP" "7"; sleep 0.1`; set `NEIGHBOR_FINAL=$(getprop "$NEIGHBOR_PROP")`; PASS iff `"$SEALED_FINAL" = "0"` AND `"$NEIGHBOR_FINAL" = "7"`; then `$RP --unseal "$TEL_PROP"; setprop "$TEL_PROP" "$ORIG"; setprop "$NEIGHBOR_PROP" "$NEIGHBOR_ORIG"` to restore. **Test 22**: save `ORIG=$(getprop "$TEL_PROP")`; run `$RP -sla "$TEL_PROP" "0"`; loop `for i in $(seq 1 50); do setprop "$TEL_PROP" "99"; sleep 0.05; done`; set `ARENA_FINAL=$(getprop "$TEL_PROP")`; PASS iff `"$ARENA_FINAL" = "0"` (no neighbor check because the whole arena is privatized, so neighbors also freeze — that's the documented Tier A trade-off); then `$RP --unseal-arena "$TEL_PROP"; setprop "$TEL_PROP" "$ORIG"` to restore. Use the existing `pass`/`fail` helper functions for reporting; the existing PASS/FAIL counters are incremented automatically by those helpers — no manual tally changes needed. — Files: `tests/device-stress-test.sh` — Verifies: `grep -c 'Test 21:' tests/device-stress-test.sh` returns ≥1 AND `grep -c 'Test 22:' tests/device-stress-test.sh` returns ≥1 AND `bash -n tests/device-stress-test.sh` exits 0 (syntax check); on-device acceptance (manual, rooted device): `sh tests/device-stress-test.sh` reports Tests 21 and 22 PASS.

## Approach

1. **Why `-sl` instead of re-binding `-st`.** REGISTRY §1 locks `-st` / `--stealth` as unchanged — pure stealth set with no ptrace and no init hook. The user has existing telephony scripts that rely on that exact semantic (100% back-compat). Rebinding `-st` to mean "stealth + seal" would silently change behaviour for every existing invocation and break scripts. Therefore `-sl` is introduced as a new flag: muscle-memory adjacent (`-st` → `-sl` is a one-character change for scripts that want to upgrade), but the semantic change is explicit and opt-in.
2. **Why Tier B is the default.** Per plan §Recommended Approach and REGISTRY §1: Tier B (per-prop hook on `__system_property_update`) is the default for `-sl` because it preserves per-prop precision — legitimate init writes to non-sealed props in the same arena continue to flow. Tier A (arena-level privatize) is available via `-sla` / `--seal-arena` as the guaranteed fallback when Tier B's ELF/symbol resolution refuses on a particular libc build.
3. **Tier B failure surface.** When `sys.seal(...)` returns an `Error::HookInstallFailed`, `Error::ElfParse`, or `Error::SymbolNotFound`, the CLI emits a clear, actionable message: `"Tier B hook install failed: {e}. Try --seal-arena for Tier A fallback."` — and exits non-zero. We do NOT silently downgrade to Tier A because that would mask the broader blast radius of the arena-level seal from the caller. The plan §New CLI surface explicitly rejects silent downgrade.
4. **Parser-to-value binding.** `-sl NAME VALUE` uses the same two-arg shape as `-st NAME VALUE`: the flag stores NAME via `arg_val`, and VALUE is taken from `positional[0]` in the dispatch block. This preserves the existing parser contract (positional args are collected into `positional: Vec<String>` at line 82) and mirrors how `-st` is dispatched in the `2 => { ... }` arm at lines 148-175.
5. **Seal listing format.** `--seals` prints each active `SealRecord` as `[{name}]: [{tier:?}] {arena}` — mirrors the existing `[{name}]: [{value}]` list format at line 141 for visual consistency and avoids introducing a new output style. `{tier:?}` uses the `Debug` impl of `SealTier` (cheap — enum has only two variants, `Prop` and `Arena`).
6. **No changes to existing behaviour.** The new parser arms, dispatch block, and `print_usage()` rows are purely additive. `-st`, `-p`, `-d`, `--nuke`, `--hexpatch-delete`, `--compact`, `--init`, `-f`, `--wait`, `--timeout`, `--dir`, `-P`, `-v`, `-h` all keep their current semantics. The `match positional.len()` block at line 138 is unchanged — the new dispatch sits BEFORE it and `return`s for seal operations, so the positional match only runs for non-seal invocations.
7. **README structure.** The "Seal" subsection is positioned after "Stealth" because seal is conceptually "stealth+": it performs a stealth write first, then adds the lock. Placing it adjacent makes the progression natural (`-st` → `-sl` as a supers et). The CLI-reference table rows are grouped with the other write modifiers (persist, stealth, init) for discoverability.
8. **Device-stress-test.sh design.** Test 21 and Test 22 reuse the existing `pass`/`fail` helper contract (no changes to tallying needed) and mirror the Test 18 stress pattern of a 50-iteration loop with `sleep 0.05` between iterations. Test 21 uniquely adds a neighbor-prop assertion because the whole point of Tier B is per-prop precision — that's the behavioural difference from Tier A. Test 22 deliberately omits the neighbor check because Tier A privatizes the entire arena, so neighbors also freeze (documented behaviour, not a regression).
9. **On-device acceptance is manual.** Running `tests/device-stress-test.sh` requires a rooted device with `setprop`/`getprop`/`resetprop-rs` available. Gate 2 treats this as a documented manual acceptance test (`#[manual]` in spirit), not an auto-runnable CI step. The Validation section below documents the invocation.
10. **Branch**: `feat/P05-cli-docs` (per REGISTRY §2 — one branch per phase, `feat/P##-short-name` convention; single segment so only one branch lifetime).

## Accepted Trade-offs (user-facing documentation)

These trade-offs are from the approved plan's "Known Trade-offs" section and MUST be surfaced in the README.md "Seal" subsection so end-users understand seal lifetime and observable behaviour. Each bullet cites the plan's authoritative location.

- **`SystemProperties::Reload` drops the seal** (plan §Known Trade-offs bullet 3; `system_properties.cpp:140-146`). If init re-initializes its contexts on signal, the private mapping (Tier A) is replaced with fresh `MAP_SHARED` mappings and the hook page (Tier B) is unaffected in init's code region but the seal's effect on the arena is lost. The user must re-run the `-sl` / `-sla` command. README.md Seal subsection MUST document this re-run requirement.
- **init restart drops the seal** (plan §Known Trade-offs bullet 4). In the rare case init is restarted, init's address space is replaced wholesale, so both the Tier A private mapping and the Tier B hook page disappear. The user must re-run the seal command. README.md Seal subsection MUST document this re-run requirement.
- **Per-prop futex waiters on sealed props stall silently** (plan §Known Trade-offs bullet 8). `__system_property_wait(pi, ...)` waits on `&pi->serial` in the caller's mapping; init's serial bump happens in init's private copy, so waiters on sealed prop_info serials are never woken. This is acceptable and aligned with seal intent (a sealed prop should not notify waiters of spurious updates). README.md Seal subsection MUST document this behaviour with the rationale, so downstream test authors do not build waiter-based regression probes that silently hang.

## Validation

```bash
# Syntax / build checks (off-device)
cargo build -p resetprop-cli                                # exits 0
cargo build --release -p resetprop-cli                      # exits 0 (checks release profile too)
bash -n tests/device-stress-test.sh                         # exits 0

# CLI-surface checks (off-device)
./target/release/resetprop --help | grep -E -- '--seal(\s|\|)'     # matches
./target/release/resetprop --help | grep -E -- '-sl|-sla'          # matches
./target/release/resetprop --help | grep -- '--seals'              # matches
./target/release/resetprop --help | grep -- '--unseal'             # matches

# Doc checks
grep -c '^\*\*Seal\*\*' README.md                           # >= 1
grep -c -E -- '--seal\|-sl|--seal-arena\|-sla|--seals' README.md   # >= 3
grep -c 'Test 21:' tests/device-stress-test.sh              # >= 1
grep -c 'Test 22:' tests/device-stress-test.sh              # >= 1

# On-device acceptance (MANUAL — requires rooted device)
# Push the built binary to /data/local/tmp/resetprop-rs (see README §Setup)
adb shell "sh /data/local/tmp/device-stress-test.sh"
# Expect: "Test 21: seal (Tier B) ... PASS" and "Test 22: seal (Tier A) ... PASS"
# Expect: no init SIGSEGV in dmesg; device remains responsive.
```

### On-device acceptance (manual, rooted device)

The six live-regression steps below are from plan §Verification → "Live regression" and MUST be executed on a real rooted device before declaring the release done. Each step cites the plan bullet it implements.

1. **Apply spoofs with `--seal` (Tier B default)** (plan §Live regression step 1). Covered by Test 21 in `tests/device-stress-test.sh`. Run the stress test block to apply the target telephony spoofs.

2. **Confirm `resetprop-rs --seals` lists the expected names** (plan §Live regression step 2).

```bash
adb shell "/data/local/tmp/resetprop-rs --seals"
# Expect: one line per sealed prop in the format "[{name}]: [{tier:?}] {arena}"
# Expect: every prop sealed by Test 21 / Test 22 setup appears in the output.
```

3. **Run `propdetect` — verify stealth signals still read clean** (plan §Live regression step 3). With the sealed telephony spoofs active, run the existing `propdetect` binary and confirm the stealth-signal scan reports zero anomalies for the telephony context (zero-serial preserved, no futex-wake drift). This confirms the seal does not introduce new observable side-effects on top of the stealth-write guarantees.

4. **30-minute soak with cell radio active** (plan §Live regression step 4). Leave the device running with the cell radio active for 30 minutes. Confirm: (a) the sealed props do not drift (re-read via `getprop` at the 30-minute mark matches the spoofed value); (b) no init SIGSEGV in `dmesg`; (c) no other telephony behaviour (SystemUI, CellBroadcast, emergency dial) is visibly broken.

5. **`adb shell dumpsys telephony.registry` sanity-check** (plan §Live regression step 5).

```bash
adb shell "dumpsys telephony.registry"
# Expect: telephony reports sane state (valid service state, valid cell info) despite frozen props.
# Expect: no stacktrace or "null" fields where valid data is expected.
```

6. **Manual fallback retry: re-run with `--seal-arena` if Tier B fails** (plan §Live regression step 6).

```bash
# Only if step 4 or step 5 shows breakage that traces to a neighbor prop also being frozen
# (which would not occur under Tier B — per-prop precision is the whole point),
# OR if Tier B refused to install on this device's libc build.
adb shell "/data/local/tmp/resetprop-rs --unseal $TEL_PROP"
adb shell "/data/local/tmp/resetprop-rs --seal-arena $TEL_PROP $SPOOFED_VALUE"
# Then repeat steps 4 and 5 to re-verify with Tier A.
```

## Anti-Scope

- AS-01: No new core seal logic — `PropSystem::seal`, `seal_arena`, `unseal`, `unseal_arena`, `seals` are owned by P01-P04 and are consumed unchanged here (per P05 spec, Scope).
- AS-02: No persistence of seals to disk — `SealRecord` stays in-memory only; `--replay-seals` is deferred post-v1 per plan §Persistence across reboots (REGISTRY §1 Persistence row).
- AS-03: No changes to `propdetect` heuristics for Tier A / Tier B signatures — noted in REGISTRY §1 as future work outside v1 scope (per plan §Touchpoints for propdetect).
- AS-04: No changes to `-st` / `--stealth` semantics — REGISTRY §1 back-compat lock. `-st` remains pure stealth write: no ptrace, no hook, no arena remap.
- AS-05: No new library modules (seal/ tree is owned by P01-P04 per REGISTRY §3).
- AS-06: No new error variants — the seven seal-related variants are introduced by P02/P04 per REGISTRY §1.
- AS-07: No changes to `Cargo.toml` dependencies — single-dep policy (`libc` only for prod) holds; `resetprop-cli` depends only on the workspace `resetprop` crate (per REGISTRY §1).
