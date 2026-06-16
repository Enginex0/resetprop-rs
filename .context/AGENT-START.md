# Session Start

```
branch:  main
last:    d25be85
active:  W1 done + adversarial audit complete; bucket amended with audit follow-ups (T15-T19; Port 3 / T11-T12 dropped)
next:    impl account on aarch64 — land T19 (lzma revert), then T15 (thread-group stop, foundational), then the T03 chain
```

## Pointers (open only when the task needs them)

- Status snapshot: `.context/ledger.yaml`
- The work:        `bucket/resetprop-rs-injectrc-ports/` (progress.yml + tasks/)
- Provenance:      `planning/SOURCES.md`
- Audit follow-up: `bucket/resetprop-rs-injectrc-ports/AUDIT-FOLLOWUP.md`
- Project README:  `README.md`

## The bucket at a glance

17 active tasks (T15-T19 added 2026-06-16; Port 3 / T11-T12 dropped). Waves:

```
done T01 T02 T05            (T12 done → reverted by T19)
W2   T15  T19  T16          ← claimable now: T15 foundational, T19 indep, T16 host-only
W3   T03                    (rebases on T15's group-stop RemoteAttach)
W4   T04  T18  T13
W5   T07  T17
W6   T08  T09  T14
W7   T06(device)  T10
critical path = T01 → T15 → T03 → T04 → T07 → T17 → T06(device)
```

## Slash commands

- `/pv-resume`     brief from AGENT-START + ledger + recent commits
- `/pv-status`     print the ledger
- `/pv-checkpoint` wrap-up: update dashboard + flip flags + commit
