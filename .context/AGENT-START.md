# Session Start

```
branch:  main
last:    9170052  (W2 merged + pushed to origin/main)
active:  T03 init-identity guard landed in working tree (Error::NotInit + verify_init_identity before both poke entry points + 4 unit tests; cargo test 146✓, clippy -D warnings clean) — NOT yet committed
next:    commit T03, then T16 (ready) or T04 (now unblocked, critical path). first 2-wide window opens (T13 ∥ T04|T16); hook.rs serializes the rest.
```

## Pointers (open only when the task needs them)

- Status snapshot: `.context/ledger.yaml`
- The work:        `bucket/resetprop-rs-injectrc-ports/` (progress.yml + tasks/)
- Provenance:      `planning/SOURCES.md`
- Audit follow-up: `bucket/resetprop-rs-injectrc-ports/AUDIT-FOLLOWUP.md`
- Project README:  `README.md`

## The bucket at a glance

17 active tasks; W2 merged 2026-06-16 (T15, T19). Status + parallelism:

```
done T01 T02 T03 T05 T15 T19    (T12 done → reverted by T19; T03 in working tree, pending commit)
now  T16 🟢                     ← ready; writes seal/hook.rs
W4   T04  T18  T13          T13 is the only non-hook.rs task → first parallel partner
W5   T07  T17               T17 dep[T15] met but wave-parked (4-file refactor, collides broadly)
W6   T08  T09  T14
W7   T06(device)  T10
critical path = T03 → T04 → T07 → T17 → T06(device)
hook.rs = serialization chokepoint (writers: T03 T04 T07 T08 T09 T10 T16 T17 T18)
```

## Slash commands

- `/pv-resume`     brief from AGENT-START + ledger + recent commits
- `/pv-status`     print the ledger
- `/pv-checkpoint` wrap-up: update dashboard + flip flags + commit
