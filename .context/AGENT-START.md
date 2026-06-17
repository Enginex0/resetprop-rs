# Session Start

```
branch:  main
last:    28b5b63  (mark T04, T13 done; chore(bucket))
active:  W3 landed: T04 verify-after-write (85d8ac3) + T13 per-arch ptrace facade (00d1af7). Combined gate green: host 151 tests + clippy, 4 android cross-builds, aarch64 clippy. T13 added a neutral set_pc for the hook.rs:1002 consumer (a DAG file-scope gap). Not pushed.
next:    T07 (m3 dry-run/--check; critical path, dep[T04] met) ∥ T14 (per-arch tests, dep[T13]) ∥ T18 (dep[T03]); hook.rs serializes T07/T08/T09/T10/T17/T18.
```

## Pointers (open only when the task needs them)

- Status snapshot: `.context/ledger.yaml`
- The work:        `bucket/resetprop-rs-injectrc-ports/` (progress.yml + tasks/)
- Provenance:      `planning/SOURCES.md`
- Audit follow-up: `bucket/resetprop-rs-injectrc-ports/AUDIT-FOLLOWUP.md`
- Project README:  `README.md`

## The bucket at a glance

17 active tasks; W2 merged 2026-06-16 (T15, T19); W3 merged 2026-06-17 (T04, T13). Status + parallelism:

```
done T01 T02 T03 T04 T05 T13 T15 T16 T19    (T12 done → reverted by T19)
now  T07 🟢                     ← critical path; writes seal/hook.rs + cli
free T14  T18  T17          T14 tests-only (dep T13); T18 (dep T03); T17 (dep T15) wave-parked, collides broadly
gate T06(device)            deps met; Tier B on-device acceptance, needs real hardware
then T08 → T09 → T10
critical path = T07 → T17 → T06(device)
hook.rs = chokepoint (writers: T07 T08 T09 T10 T17 T18)
```

## Slash commands

- `/pv-resume`     brief from AGENT-START + ledger + recent commits
- `/pv-status`     print the ledger
- `/pv-checkpoint` wrap-up: update dashboard + flip flags + commit
