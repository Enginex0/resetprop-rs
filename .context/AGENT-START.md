# Session Start

```
branch:  feat/bucket-injectrc-ports
last:    d07d49f
active:  none
next:    claim a Wave-1 task — T01, T02, T05, or T12 (write-disjoint, parallel-safe)
```

## Pointers (open only when the task needs them)

- Status snapshot: `.context/ledger.yaml`
- The work:        `bucket/resetprop-rs-injectrc-ports/` (progress.yml + tasks/)
- Provenance:      `planning/SOURCES.md`
- Project README:  `README.md`

## The bucket at a glance

14 tasks, gate-green. Waves (write-set-disjoint, computed from the DAG):

```
W1  T01 T02 T05 T12     ← claimable now, 4 parallel worktrees
W2  T03 T11             W3  T04 T13      W4  T06 T07 T14
W5  T08   W6  T09   W7  T10
critical path = hook.rs spine  T01→T03→T04→T07→T08→T09→T10
```

## Slash commands

- `/pv-resume`     brief from AGENT-START + ledger + recent commits
- `/pv-status`     print the ledger
- `/pv-checkpoint` wrap-up: update dashboard + flip flags + commit
