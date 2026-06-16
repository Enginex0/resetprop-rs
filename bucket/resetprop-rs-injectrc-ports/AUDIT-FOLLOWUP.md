# Audit follow-up — bucket amendment (2026-06-16)

Adversarial audit performed against `main @ d25be85` (seal subsystem:
`hook.rs`, `arena.rs`, `ptrace.rs`, `elf.rs`, `xz_decoder.rs`, plus the
`PropSystem` seal entry points in `lib.rs` and the CLI). This file carries the
reasoning behind the bucket amendment to the implementation account. The task
specs (`tasks/T15-T19.yaml`) carry the what; this carries the why.

## Problem

The W1 "GREEN" certification is not commensurate with the subsystem's risk.
The engine patches PID 1 (init), and its single highest-severity hazard was
documented but never bucketed: `RemoteAttach` SEIZE+INTERRUPTs only init's
leader thread, while init is multi-threaded, so sibling threads run live
through the Tier A remap and the Tier B trampoline patch. `--seal` (the
default user command) can therefore bootloop a real device. Separately, the
gate passed a real ARM encoding bug because the test asserted the same wrong
golden constant, and a second runtime dependency (`lzma-rs`) shipped with no
consumer.

## Decision

Amend the bucket: add **T15** (thread-group stop — the actual fix for
Defect B / audit C1) as the new foundational task ahead of T03; add **T16**
(independent encoding oracle), **T17** (collapse the four syscall-injector
copies + single attach window + i-cache revert symmetry), **T18** (shared
libc-row helper + capacity-comment fix + doc-rot). Drop Port 3: cut **T11**
and revert `lzma-rs`/`xz_decoder` via **T19**.

## Why

- C1 (Defect B): T03 (identity guard), T04 (verify-after-write), T06 (on-device
  gate) and T08 (throttle) only mitigate around the hazard; none freezes the
  sibling threads, so none removes the bootloop window between the two
  non-atomic trampoline POKEs (`hook.rs:1129`/`:1132`). If X = "init is
  multi-threaded at patch time" (true on real Android), then a sibling calling
  `__system_property_update` mid-patch crashes PID 1, therefore the only
  root fix is a thread-group stop. With the group fully stopped, the
  lock-list write-ordering race (audit L2) is also moot.
- M1 (lzma-rs): the live resolver uses `.dynsym` only (`elf.rs:554,622`); the
  sole resolved symbol `__system_property_update` is exported under
  `LIBC_PLATFORM` (`libc.map.txt:1819-1825`), so it is in the shipped
  `libc.so`'s `.dynsym` (never stripped). `.gnu_debugdata` resolves
  non-exported symbols only. PLAN.md:180,182-184 confirm there is no consumer
  and the port was a speculative capability door. The project's own doctrine
  forbids designing for hypotheticals and caps runtime deps at one. Therefore
  drop it now; reintroduce with its consumer if ever scoped.

## Rejected

- Mitigate-and-gate C1 (ship Tier B behind T06, defer the fix): rejected by
  the user in favor of the root fix; leaves a documented bootloop default.
- Disable Tier B entirely: rejected; loses the headline feature when a real
  fix is tractable.
- Keep lzma-rs as a capability door / fast-track T11: rejected after source
  evidence showed the target symbol is already in `.dynsym`, so the fallback
  resolves nothing the engine currently needs.

## Constraints

Hard:
- Single runtime dependency by law (`libc`); T19 restores it. A new crate
  needs a written justification in the task that adds it.
- Correctness and safety on PID 1 outrank features.
- Conventional Commits; the repo commit hook rejects AI-attribution trailers.
Soft:
- Prefer reusing the hardened predicates/helpers already in `hook.rs` over the
  older `arena.rs` forms when consolidating.

## Open questions

- T15(e): policy for threads cloned after enumeration —
  `PTRACE_O_TRACECLONE` on the leader vs a bounded re-scan with a documented
  residual race. Tolerance: unknown; recommend TRACECLONE for completeness.
- OEM matrix: source proves `__system_property_update` is exported on AOSP 15;
  a device with a heavily modified bionic could differ. Tolerance: low-value
  confirmation, not a blocker — a single `readelf --dyn-syms` on the target
  `libc.so` settles it if Tier B ever fails symbol resolution on a device.

## Risks

- T15 is the hardest task (foundational, touches both tiers' attach). It can
  only be proven on an aarch64 device under concurrent property-set load.
  Monitor via T06's extended acceptance.
- T17 reworks the injector that T15 just changed; sequence T17 after T15 to
  avoid double-churn. Accepted.
- Reverting a merged dependency (T19) is a clean revert of d25be85's
  Cargo/​source changes; low risk, no dependents (xz_decoder has no callers).

## Next

Implementation account, on aarch64: land T19 (independent, immediate), then
T15 (foundational), then the T03 -> T04 -> T07 -> T17 spine, with T16/T18 in
parallel (host-only). The only honest proof of Tier B safety is T06 + T15's
live half on a device; that is where "pristine and flawless" is established.

## Finding -> task map

| Audit finding | Task | Status |
|---|---|---|
| C1 thread-group stop (Defect B) | T15 (new) | ready |
| H1 self-confirming encoder gate | T16 (new) | ready |
| M1 dead lzma-rs dep | T19 (new), T11 cut | ready / cut |
| M2 four injector copies + dead remote_syscall | T17 (new) | backlog (dep T15) |
| M3 stale capacity comment + missing assert | T18 (new) | backlog (dep T03) |
| M4 divergent libc-row predicates | T18 (new) | backlog (dep T03) |
| M5 three attaches per seal() | T17 (new) | backlog (dep T15) |
| L1 i-cache revert asymmetry | T17 (new) | backlog (dep T15) |
| L2 lock-free ordering vs stop-the-world | closed by T15 | n/a |
| L4 doc-rot | T18 (new) | backlog (dep T03) |
| L5 SELinux /data/adb assumption | T09 (existing) | backlog |
| init identity / verify / gate / throttle | T03/T04/T06/T08 | existing |
