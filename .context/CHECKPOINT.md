# Session Checkpoint

Triggered by the keywords `checkpoint`, `wrap up`, or `end session`.

Execute the `/pv-checkpoint` slash command. The protocol lives at `~/.claude/commands/pv-checkpoint.md`.

In short: update `.context/AGENT-START.md` (branch, last, active, next), flip flipped flags in `.context/ledger.yaml`, append ONE LINE to `.context/history.md`, commit with subject `chore(context): checkpoint YYYY-MM-DD <one-line>`.

This file is the trigger; the slash command is the body. Do not run two wrap-up protocols.
