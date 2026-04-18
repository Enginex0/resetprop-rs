# Session 01 Handoff — P01 Foundation (T1-T3 shipped, T4-T5 + Gate 2 pending)

> Read this FIRST on next session start. Then follow the Session Start Protocol in `.claude/system-prompt.md`.

## State at handoff (2026-04-18)

### Branch

`feat/P01-foundation` — 9 commits ahead of `main`. Do NOT rebase, do NOT merge to main yet. Next session appends T4 + T5 + audit commits, then runs Gate 2.

### Commits on branch (oldest first)

```text
65b5a25 feat(seal): scaffold seal module skeleton
b0917f2 feat(seal): add 7 error variants for seal path
07d9238 feat(seal): wire seal module into lib.rs
6982944 docs(seal): fill P01 T1 self-audit gate notes
fa02dc3 feat(seal): implement /proc/pid/maps parser
2ad4557 refactor(seal): re-export MapEntry and parse_maps
67b9848 docs(seal): fill P01 T2 self-audit gate notes
3477933 feat(seal): add ptrace constants and register IO
0d30d9f refactor(seal): re-export ptrace primitives
```

Plus the closing session commit that appends this handoff and fills Self-Audit Gate 3.

### Task progress (REGISTRY §4 row P01)

| Task | Status | Self-Audit Gate |
|------|--------|-----------------|
| T1 module skeleton + 7 error variants + SealRecord/SealTier | COMPLETE | Gate 1 filled |
| T2 `/proc/pid/maps` parser + 3 tests | COMPLETE | Gate 2 filled |
| T3 ptrace constants + UserPtRegs + 6 primitives | COMPLETE | Gate 3 filled |
| T4 `remote_syscall` injector | PENDING | Gate 4 empty |
| T5 `ptrace_core_smoke.rs` integration test | PENDING | Gate 5 empty |
| Gate 2 adversarial audit (code-reviewer + critic in parallel) | PENDING | — |

### Test baseline

`cargo test -p resetprop --lib` reports `63 passed; 0 failed` on both x86_64 and aarch64-linux-android. Gate against regression: T4 and T5 must preserve 63 lib tests; T5 adds 1 ignored integration test.

### Environment facts verified this session

- `/proc/sys/kernel/yama/ptrace_scope` = `0` on this host (ptrace-gated integration tests CAN run).
- AOSP headers at `/home/president/aosp-android15/bionic/libc/kernel/uapi/{linux/ptrace.h, linux/elf.h, asm-arm64/asm/ptrace.h}` exist; values quoted verbatim in T3 report — Gate 2's External API Verification has the citations pre-built.
- `aarch64-linux-android` rustc target is installed — size assert for `UserPtRegs` has been exercised.

## Next session — start sequence

1. Read `.claude/system-prompt.md` (governance), `phases/seal/REGISTRY-P.md` §1-§3, `phases/seal/P01-foundation.md` (spec), `phases/seal/checklists/P01-checklist.md` (gates).
2. Read this handoff file in full.
3. Verify branch: `git branch --show-current` should report `feat/P01-foundation`.
4. Verify baseline: `cargo test -p resetprop --lib` → 63 passed.
5. Dispatch T4 using the prompt shell below.
6. Audit T4, fill Self-Audit Gate 4, commit, dispatch T5.
7. Audit T5, fill Self-Audit Gate 5, commit, then run Gate 2 adversarial audit (two agents in parallel per `.claude/system-prompt.md §Gate 2`).
8. On both Gate 2 verdicts `PASS`, promote REGISTRY §4 row P01 to `COMPLETE` and append §7 session log for S02. Phase done.

## Cross-session directive — agents may push back

User directive (2026-04-18, end of S01):

> "agents can push back if they have a more better elegant logic compared to what we have in the plan, this makes the door open for free improvements, not just blind implementation without intelligent semantic understanding"

Add this stanza VERBATIM to every dispatch prompt from T4 onward, placed just before the "Verification" section:

```text
# Pushback permitted (senior-engineer license)

If while reading the references you identify a more elegant approach than the dispatch prescribes — better Rust idioms, a cleaner invariant, a simpler factoring — you are permitted and encouraged to deviate. The rules: (a) cite the specific reference or evidence that motivates the change, (b) keep the deviation inside the task's declared scope (anti-scope still holds), (c) document the deviation in §6 of your final report with rationale. Do NOT silently override dispatch text. Do propose the improvement with evidence. The T3 agent correctly flagged two such improvements (`as _` cast portability; `WIFSTOPPED` is `pub const fn`, not unsafe); that kind of pushback is explicitly welcome.
```

## Cross-task facts T4 must know (from T3 agent's handoff §7)

Available inside `seal::ptrace` (module-private, reusable by T4):

- `fn last_ptrace_err() -> Error` wraps `io::Error::last_os_error()` as `Error::PtraceAttach`. Reuse for `process_vm_readv`/`writev` failures and the `PTRACE_CONT` step of the injector.
- `PTRACE_CONT` const (line 27 of `ptrace.rs`) already declared.
- `NR_GETPID = 172` already declared. T4 should NOT add `NR_OPENAT`/`NR_CLOSE`/`NR_MMAP` speculatively — `remote_syscall` takes `syscall_no: u64` as a parameter, so adding those constants is P02 scope, not T4's.

T4 must ADD to `use libc::{…}`:

- `libc::process_vm_readv`
- `libc::process_vm_writev`

T4 must NOT re-export `remote_syscall` until the implementation lands; append it to the `pub use ptrace::{…}` block in `seal/mod.rs` at line 39-43 in the final T4 commit.

T4 safety contract: `grep -c "// SAFETY:" crates/resetprop/src/seal/ptrace.rs` must remain ≥ `grep -c "unsafe {"`. T3 left it at 6/6 — T4 adds roughly 4 more unsafe blocks (readv + writev + the injector's ptrace(CONT) + the scratch-byte save/restore vm-ops), so expected post-T4 count is ~10/10.

## T4 dispatch prompt (draft — copy into next session)

Target: `oh-my-claudecode:rust-engineer` with `model="opus"`. Include this prompt VERBATIM, adjusting only "Task N of 5 — Task 4" to stay current.

See `phases/seal/P01-foundation.md` §Tasks item 4 for the canonical algorithm (linux-arm64-abi.md §7 is the primary reference). Key implementation points the next orchestrator should stress in the prompt:

- Save 8 bytes at `scratch_pc` via `process_vm_readv` BEFORE writing the svc+brk payload; restore on exit.
- Payload bytes: `[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]` (svc #0 followed by brk #0, little-endian).
- `read_remote(pid, addr, &mut buf)` and `write_remote(pid, addr, &buf)` must loop on partial transfers per linux-arm64-abi.md §10 — `UIO_MAXIOV` is 1024 but one iovec per call is fine at our byte counts.
- `wait_stop` after `PTRACE_CONT` must verify `event_byte == 0` (brk-trap), not `PTRACE_EVENT_STOP == 128`.
- Restore saved regs via `setregset` THEN restore scratch bytes via `write_remote` — order matters so the instruction bytes at `scratch_pc` are fresh if caller re-invokes.
- Function is declared `pub unsafe fn remote_syscall(...)` — `unsafe` at the function boundary because the caller owes scratch_pc validity, not inside the body.
- Add re-export for `remote_syscall` to `seal/mod.rs:39-43` block in the final commit of T4.

## T5 dispatch prompt (draft — copy into next session)

Target: `oh-my-claudecode:rust-engineer` with `model="opus"`. Canonical algorithm at `phases/seal/P01-foundation.md` §Tasks item 5 (test-harness-patterns.md §2-§3 is the primary reference).

Key points:

- File path: `crates/resetprop/tests/ptrace_core_smoke.rs` (integration test, not `#[cfg(test)]` inline).
- `fork_child` + `ChildGuard` (SIGKILL + waitpid in Drop) per test-harness-patterns.md §3 — copy the skeleton verbatim, adjust names only.
- Pre-fork parent mmaps an anonymous RWX page at a known address; child inherits via COW; stage `svc #0 ; brk #0` into it before fork OR have child write it in its own address space before pause-loop (either works; pre-fork is simpler).
- `#[test] #[ignore = "requires ptrace_scope<=1; run with cargo test --test ptrace_core_smoke -- --ignored --test-threads=1"]`.
- Assertion: `remote_syscall(child_pid, scratch_pc, seal::ptrace::NR_GETPID, [0; 6])` returns `child_pid as i64`.
- Default `cargo test --test ptrace_core_smoke` reports `0 passed; 1 ignored`.
- Gated invocation `-- --ignored --test-threads=1` reports `1 passed` (yama=0 on this host — confirmed viable).
- Top-of-file doc comment documents the runner invocation AND the CAP_SYS_PTRACE / yama precondition.

## Gate 2 dispatch sequence (after T5)

Per `.claude/system-prompt.md §Gate 2`. Build the context-pointer block with:

- Phase: `P01 — Foundation: ptrace + maps`
- Phase spec: `phases/seal/P01-foundation.md`
- Phase checklist: `phases/seal/checklists/P01-checklist.md`
- REGISTRY: `phases/seal/REGISTRY-P.md`
- Code paths: `crates/resetprop/src/seal/mod.rs`, `crates/resetprop/src/seal/maps.rs`, `crates/resetprop/src/seal/ptrace.rs`, `crates/resetprop/src/error.rs`, `crates/resetprop/src/lib.rs`, `crates/resetprop/tests/ptrace_core_smoke.rs`
- Branch: `feat/P01-foundation`
- External API Verification: `YES`
- Sources: `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h`, `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/elf.h`, `/home/president/aosp-android15/bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.h`, `/usr/include/asm-generic/unistd.h`

Dispatch BOTH agents in a single message with two `Agent` tool calls so they run in parallel:

1. `Agent(subagent_type="oh-my-claudecode:code-reviewer", model="sonnet", prompt=<Persona A VERBATIM from system-prompt.md §Gate 2 + context block>)`
2. `Agent(subagent_type="oh-my-claudecode:critic", model="opus", prompt=<Persona B VERBATIM from system-prompt.md §Gate 2 + context block>)`

Reports append to `phases/seal/audits/P01-audit.md` under `## code-reviewer report` and `## critic report` headings. Phase is NOT `COMPLETE` until both emit `VERDICT: PASS`.

## Known cosmetic debt (non-blocking, address at Gate 2 minor findings if raised)

- `maps.rs:28-29` doc comment cites `error.rs:61-68` for `From<io::Error>` impl; actual location post-T1 is `error.rs:66-73`. Off by 5 lines. Cosmetic.
- `SealRecord` / `SealTier` / `Pid` / `NR_GETPID` / several ptrace primitives still emit `dead_code` warnings on `cargo check` because they are declared-but-not-consumed within P01. P02 (Tier A) and P04 (Tier B) consume them per REGISTRY §3 Domain Ownership. The warnings will naturally clear when downstream phases land. Not suppressed with `#[allow]` per anti-paper-over policy.

## Checklist state of P01-checklist.md

Gates 1–3: filled (non-empty Notes on Optimality / Completeness / Correctness). Gates 4–5: empty — next session fills after T4 and T5 respectively. Functional Requirements FR-01..FR-24 + FR-26 checked. FR-25, FR-27..FR-29 unchecked (T4/T5 scope). TC-01, TC-03, TC-04, TC-05, TC-08, TC-09 checked. TC-02, TC-06, TC-07 unchecked (T4/T5 + final build).

## Orchestrator reminder — do not rebase this branch

The 9-commit history on `feat/P01-foundation` is the audit trail. Do not squash, amend, or force-push. Let it stand exactly as-is so Gate 2 can walk the history.
