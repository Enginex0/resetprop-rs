
## critic report

**VERDICT: ACCEPT-WITH-RESERVATIONS** (promoted from REVISE after Realist Check — see Verdict Justification)

**Overall Assessment**: P01 is a rigorously-executed foundation phase. Constants, `UserPtRegs` layout, ptrace primitives, partial-transfer loops, and the `remote_syscall` stager all match the bionic UAPI headers and the phase's own linux-arm64-abi.md reference. The implementation exceeds spec in two places (documents the `fn()->!` vs `FnOnce()->!` harness deviation, and gates the entire integration test file on `#[cfg(target_arch = "aarch64")]`). The flaws are real but narrow: one mild contract drift with the reference (SEIZE options), one ergonomic mis-typing (`PtraceAttach` used as a catch-all error variant), and one public-API hygiene issue (ARM64 instruction constants and `NR_GETPID` leak out of a module meant to own ptrace). None block P02/P03/P04 if acknowledged and tracked.

**Pre-commitment Predictions**:
1. `PTRACE_SEIZE` options dropped — **CONFIRMED** (impl passes 0 for `data` where the reference passes `PTRACE_O_TRACESYSGOOD`).
2. `wait_stop` failure-mode clarity — **PARTIALLY CONFIRMED** (helper is correct for both call sites; but error mapping conflates unexpected stops with attach failures).
3. Non-arm64 compile handling of ARM64 constants — **NOT AN ISSUE** (constants are pure integers; test file is fully cfg-gated; size-assert is cfg-gated).
4. Integration test race (child reaching `pause()` before SEIZE) — **CONFIRMED** (50 ms sleep is the only sync; flaky under load).
5. Error variant overloading — **CONFIRMED** (`Error::PtraceAttach` is reused for stall, unexpected-status, and post-CONT failures — misleading for both logs and matches).

Escalation: thorough mode throughout. No CRITICAL findings after Realist Check → no ADVERSARIAL expansion triggered.

---

### Critical Findings
None.

### Major Findings

**M1. `ptrace_seize` drops the `PTRACE_O_TRACESYSGOOD` option that the phase reference mandates.**
- Evidence: `crates/resetprop/src/seal/ptrace.rs:149-159` calls `libc::ptrace(PTRACE_SEIZE, pid, 0, 0)`. `phases/seal/references/linux-arm64-abi.md:153` says `ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD)` — "attaches without stopping the tracee; sets options atomically." Line 95 of the reference locks `PTRACE_O_TRACESYSGOOD = 1`.
- Confidence: HIGH
- Why this matters: `PTRACE_O_TRACESYSGOOD` sets bit 7 of the syscall-stop signal number (`SIGTRAP|0x80` → 0x85) so syscall-stops are distinguishable from regular SIGTRAPs. Without it, a concurrent syscall-stop on the tracee delivers plain `SIGTRAP` (5) and slides past `wait_stop`'s `WSTOPSIG == SIGTRAP` check with `event == 0` — which `remote_syscall` will treat as its expected brk trap. For P01's single-threaded `pause()` child the probability is ~zero, but P04 will attach to multi-threaded init where this becomes a real misread-your-return-value bug. Fixing it in P01 also prevents Gate 2 consistency drift: the phase reference was presumably vetted by auditors, and the code does not match.
- Fix: Change `ptrace.rs:154` to pass `PTRACE_O_TRACESYSGOOD as *mut c_void` as the 4th argument to the SEIZE call, and expose the constant at module scope (`pub const PTRACE_O_TRACESYSGOOD: c_int = 1; // source linux/ptrace.h:100`). Update the T3 self-audit entry in the checklist to cite `linux/ptrace.h:100`.

**M2. `Error::PtraceAttach` is overloaded as a catch-all for "any failure inside the ptrace module," which defeats the typed-error design.**
- Evidence: `ptrace.rs:115-116` (`last_ptrace_err` returns `PtraceAttach`), used by `ptrace_interrupt` (:175), `wait_stop` (:193 for waitpid failure, :198-201 for unexpected-status), `getregset` (:229), `setregset` (:254), `ptrace_detach` (:271), `read_remote`/`write_remote` stall paths (:315-322, :360-368), and the `PTRACE_CONT` failure in `remote_syscall` (:445). Six of those seven sites never attach anything.
- Confidence: HIGH
- Why this matters: REGISTRY §3 gives `error.rs` ownership of the typed error surface and P01 adds `PtraceAttach(io::Error)` specifically so CLI can present an attach-phase remediation. A user now sees `"ptrace attach failed: process_vm_readv stalled: 3/8 bytes transferred"` when the failure happened deep inside `remote_syscall` post-attach — or worse, `"ptrace attach failed: unexpected wait status: 0xb7f"` when the child hit a `PTRACE_EVENT_EXEC`. The variant name contradicts the `Display` text and the CLI cannot match on this to give useful diagnostics. P02/P03/P04 will each hit `wait_stop`, `getregset`, and partial-transfer loops; without a fix here they inherit the same misnomer and the error surface rots into "it's all a ptrace attach failure."
- Fix: Split into two or three variants now (cheap — no external users yet): add `Error::PtraceOp(io::Error)` for generic ptrace/waitpid syscall failures post-attach, and `Error::PtraceUnexpectedStatus(i32)` for unexpected wait statuses (the raw status word is the useful payload, not an `io::Error`). Restrict `PtraceAttach` to `ptrace_seize` and `ptrace_detach` only. Update `Display` text accordingly and update REGISTRY §1 row "Error surface" count from 7 to 8 (or 9) variants.

**M3. Public re-exports from `seal/mod.rs` pull ARM64 instruction-encoding constants into the wrong module tier.**
- Evidence: `seal/mod.rs:38-44` publicly re-exports `ptrace_seize`, `ptrace_interrupt`, `wait_stop`, `getregset`, `setregset`, `ptrace_detach`, `remote_syscall`, `UserPtRegs`. But `ptrace.rs:54, 59, 67` also declare `pub const ARM64_SVC_0`, `pub const ARM64_BRK_0`, `pub const NR_GETPID` — reachable via `resetprop::seal::ptrace::ARM64_SVC_0`. REGISTRY §3 Domain Ownership explicitly puts ARM64 encoders under `seal/hook.rs` ("Hand-rolled `const fn` encoders in `seal/hook.rs`") and says `ptrace.rs` owns "ptrace attach/detach, register snapshot, remote syscall injector."
- Confidence: HIGH
- Why this matters: Two concrete downstream costs. (a) When P04 implements its `seal/hook.rs` encoder module it will legitimately need a *different* `ARM64_BRK_0` usage (trampoline codegen, not syscall stager) and will either re-declare the constant (duplicate source of truth) or import from `seal::ptrace` (wrong domain — couples hook installation to ptrace). The REGISTRY §1 row already locks `LDR_X16_PC8 = 0x58000050` in `seal/hook.rs` — same class of constant, but the phase split put it in the right place. (b) `pub const NR_GETPID` is a *test-only* syscall number used solely by `ptrace_core_smoke.rs`; it's on the public API of the library (`resetprop::seal::ptrace::NR_GETPID`). Every external consumer now sees it; every future syscall number (NR_openat/NR_close/NR_mmap) needed by P02/P03/P04 will accrete here unless the pattern is corrected.
- Fix: Downgrade `ARM64_SVC_0` and `ARM64_BRK_0` to `pub(super)` or `pub(crate)` — the `remote_syscall` implementation is their only legitimate consumer; external callers never need them. Downgrade `NR_GETPID` to `pub(crate)` and move it (or at minimum document it as test-support) since the integration test is the only consumer. When P02/P03/P04 land, their own syscall-number tables go in the arena/hook modules, not in `ptrace.rs`.

### Minor Findings

**m1. Integration test uses a fixed 50 ms sleep to wait for the child to reach `pause()` before `PTRACE_SEIZE`.**
- Evidence: `tests/ptrace_core_smoke.rs:147`. Under kernel scheduler pressure (CI box, low-priority runner, KVM) 50 ms is not a hard guarantee. `PTRACE_SEIZE`/`PTRACE_INTERRUPT` will still succeed if the child is in the `fork()` return path rather than `pause()`, because the subsequent `wait_stop` accepts any SIGTRAP-stop — but the *semantics* the test intends (child blocked in `pause`, scratch page pre-populated) aren't guaranteed.
- Fix (optional, harden before P05): replace the sleep with a pipe-based sync — child writes a byte to a pipe before `pause()`; parent `read`s it.

**m2. `write_remote`'s safety comment says the kernel "bypasses VMA write bits for ptrace-attached writers" (`ptrace.rs:337-340`).**
- Evidence: Line 338-340. The kernel's `process_vm_writev` path (`mm/process_vm_access.c`) actually does require write permission on the target VMA *unless* the caller is ptrace-attached *and* has `PTRACE_MODE_ATTACH_FSCREDS`. The comment is approximately right but handwaves a real precondition. In P01's smoke test the scratch page is mmap'd RWX so it's moot; in P02/P03/P04 the target pages will be RWX (arena post-remap) or a freshly mmap'd RWX page, so the comment will stay accidentally true. Still worth tightening.
- Fix (optional): narrow the SAFETY comment to "caller's scratch_pc names an RWX mapping" rather than making a general claim about kernel behavior.

**m3. `wait_stop` wraps an unexpected status into `io::Error::new(Other, …)` inside `PtraceAttach`.**
- Evidence: `ptrace.rs:198-201`. If M2 is fixed this goes away (caller gets `PtraceUnexpectedStatus(i32)` with the raw status bits preserved).

**m4. `const _: () = assert!(size_of::<UserPtRegs>() == 272)` is only gated on `target_arch = "aarch64"`.**
- Evidence: `ptrace.rs:103-104`. On x86_64 the assert would still hold (31\*8 + 3\*8 = 272 is arch-invariant), so the cfg gate is defensive cosmetics. Not wrong, just over-conservative. The runtime `size_assert` test (`ptrace.rs:489-491`) already compensates.

### What's Missing

- No `unsafe` contract on `remote_syscall` for *single-threaded tracee*. The function doc says "no other thread in the tracee is racing on those 8 bytes" but does not state what happens if the tracee has multiple threads and `PTRACE_INTERRUPT` stops only one of them. P04 attaches to init (PID 1), which *is* multi-threaded. The function signature gives no way to express "thread ID that owns this scratch_pc." If P04 plans to inject into a specific thread, P01's safety contract is incomplete. Flag for P02/P04 spec: how is the thread pinned?
- No test that exercises `process_vm_readv/writev` partial-transfer loops. Current T5 smoke test uses 8-byte transfers which are always atomic in kernel fastpath. A page-boundary-crossing write (e.g. 4088..4104 across a PROT_* boundary) would be the only way to exercise the `transferred < buf.len()` retry. P02/P03 will move larger payloads (trampolines, lock-lists) — consider a fault-injection unit test now, since the loop logic is the kind of thing that breaks silently.
- No assertion that `scratch_pc` in `remote_syscall` is 4-byte aligned. The doc-comment says "Caller must have already ensured `scratch_pc` is 4-byte aligned"; the function does not `debug_assert!(scratch_pc & 3 == 0)`. A misaligned `scratch_pc` will decode garbage under the AArch64 IFU, the `svc` will likely SIGILL before reaching `svc`, and the test failure message will say "unexpected wait status" — debugging from that is painful.
- No CI entry. The checklist verification steps `cargo test ... -- --ignored --test-threads=1` is a *manual* gate. Without a CI pipeline that runs it (on a privileged container with `ptrace_scope <= 1`) the test can rot silently through P02/P03/P04. Flag for P05 readiness.
- No `PTRACE_O_EXITKILL`. Android init will not be killed by test runs, but P04's attachment to PID 1 on a developer phone is dangerous: if the resetprop CLI panics between SEIZE and DETACH, init is left ptrace-stopped forever (reboot). `PTRACE_O_EXITKILL` makes the tracee receive SIGKILL if the tracer dies — which for `init` means a reboot, but at least it's *a reboot*, not a frozen system. Not needed in P01's fork-a-dummy smoke test, but the absence of a TODO for P04 is a gap.
- No handling of `PTRACE_EVENT_EXEC` during `remote_syscall`. `exec` clears the tracee's mapping, which invalidates `scratch_pc`. `remote_syscall` currently surfaces `event != 0` as `PtraceAttach` (see M2) but the diagnosis will say "attach failed" for an event-byte=4 (exec) which is misleading.
- `SealRecord`/`SealTier` are defined in `seal/mod.rs` but there is no test that constructs them. A trivial `#[test]` verifying the struct-literal compiles prevents a rename in P02 from breaking the type surface silently.

### Multi-Perspective Notes

- **Skeptic**: The strongest argument against shipping P01 as-is is that the error surface decision (M2) compounds. P02 will add two error paths (arena-already-sealed, arena-not-mapped) and P04 adds three (elf-parse, symbol-not-found, hook-install-failed). If `PtraceAttach` is already miscategorizing `getregset`/`setregset`/stall failures, every future phase will have to decide whether their ptrace call site uses `PtraceAttach` or something else, and the answer will diverge across authors. Fix the typology *now* while `ptrace.rs` is the only consumer.
- **Executor (P02 author)**: "Can I consume P01's surface?" Yes for `parse_maps`, `MapEntry`, `UserPtRegs`, all the ptrace primitives, `remote_syscall`. But I notice `find_by_path` is reachable only via `seal::maps::find_by_path` (not re-exported). The T2 self-audit calls this "intentional" — but P02 and P03 are explicitly named as consumers. Either re-export it or document the reason in a code comment, not buried in a checklist entry.
- **Stakeholder**: Does P01 ship what the phase spec promised? Yes — mod tree, 7 error variants, `UserPtRegs` at 272 B (aarch64-asserted), all six ptrace primitives, `remote_syscall` stager, integration smoke test. Scope respected (no arena remap, no ELF parsing, no hook page, no CLI). This is a well-executed phase.
- **Ops**: What fails under load? (a) Test flakiness from the 50 ms sleep (m1). (b) If `/proc/sys/kernel/yama/ptrace_scope` transiently returns EIO (CI runners sometimes do), `classify_seize_err` at `ptrace.rs:127` silently falls through to `PtraceAttach` instead of `PtraceScope` — that's correct behavior, but the chain is undocumented and looks like a bug during triage. (c) No timeout on `wait_stop` — a lost INTERRUPT (yama rejected it, kernel event dropped) hangs the parent forever under `waitpid`. Consider a `waitpid` with `WNOHANG` in a loop with a deadline for post-P01 robustness.

### Ambiguity Risks

- `SealRecord` field `sealed_at: SystemTime` — P02/P04 will each set this, but the spec does not say whether they use `SystemTime::now()` at seal-start or seal-commit (i.e., before or after the `MAP_PRIVATE|MAP_FIXED` remap). For in-memory v1 this is semantic only, but the moment persistence lands (post-v1) this becomes replay-ordering. Not a P01 blocker; flag for P02/P04.
- The `Pid` type alias (`seal/mod.rs:15`) is `libc::pid_t` which is `i32`. The `remote_syscall` return type is `i64` for x0, and values `-4095..=-1` are `-errno`. A caller who sees `ret == child_pid as i64` and `child_pid` is a `pid_t i32 = -1` (fork failure already caught, but imagine a stress scenario) would silently match `-errno=1 EPERM`. The smoke test asserts `assert!(pid >= 0)` before use, so safe in P01, but the signature conflation is worth a comment.

### Verdict Justification

Initial draft was REVISE (M1+M2+M3 all blocking). Realist Check downgraded to ACCEPT-WITH-RESERVATIONS:
- **M1 (TRACESYSGOOD)**: Mitigated by the fact that P01's test fixture is a single-threaded child in `pause()` — zero probability of a concurrent syscall-stop. The real-world failure mode manifests only against multi-threaded init in P04. Mitigating factor: detection will be fast (remote_syscall returns an unexpected value, the P04 smoke test or on-device P05 run catches it immediately). Kept as MAJOR, not CRITICAL.
- **M2 (error variant overload)**: Mitigated by the fact that no CLI consumer exists yet and no plan asset depends on the current variant name. Fix cost rises exponentially once P02/P04 authors match on `PtraceAttach`. Flag as MAJOR and strongly recommend fix before P02 starts; do not block P01's merge.
- **M3 (public const leakage)**: Mitigated by the fact that nothing outside the crate imports these yet. Pure hygiene issue. MAJOR because the fix is cheap now and expensive later.

Upgrade to ACCEPT: address M1 and M2 in the next session's first task (before T5 integration smoke is re-run on aarch64); M3 can fold into the P02 opening task (same file touched). The ptrace.rs size-assert, UserPtRegs layout, waitpid/status handling, partial-transfer loops, SAFETY comments, and yama classification are all correct and verifiable against bionic headers.

### Open Questions (unscored)

- Is `pause()` in the child actually reached before the parent's SEIZE under heavy scheduler load? Empirical — couldn't verify without running the test.
- Does `PTRACE_O_TRACESYSGOOD` need to be set *before* `PTRACE_INTERRUPT` for the initial stop's status bits to be correctly classified? The reference implies yes (SEIZE sets options atomically); the kernel sources would confirm.
- Will P04's init attachment use `PTRACE_SEIZE` on PID 1 directly, or on a specific thread? If the latter, P01's `Pid` type alias may need to distinguish TGID vs TID.

## code-reviewer report

**Reviewer:** code-reviewer (oh-my-claudecode, claude-sonnet-4-6)
**Date:** 2026-04-18
**Branch:** feat/P01-foundation
**Diff base:** main...feat/P01-foundation
**Files reviewed:** 6
  - crates/resetprop/src/seal/mod.rs
  - crates/resetprop/src/seal/maps.rs
  - crates/resetprop/src/seal/ptrace.rs
  - crates/resetprop/src/error.rs
  - crates/resetprop/src/lib.rs
  - crates/resetprop/tests/ptrace_core_smoke.rs

---

### Stage 1 — Spec Compliance

#### External API Verification (mandatory per context pointer block)

All constants verified verbatim against authoritative sources:

**linux/ptrace.h** (AOSP android15, lines 17–31):
```
#define PTRACE_CONT       7      // line 17 ✓ matches PTRACE_CONT=7
#define PTRACE_DETACH    17      // line 21 ✓ matches PTRACE_DETACH=17
#define PTRACE_GETREGSET 0x4204  // line 27 ✓ matches
#define PTRACE_SETREGSET 0x4205  // line 28 ✓ matches
#define PTRACE_SEIZE     0x4206  // line 29 ✓ matches
#define PTRACE_INTERRUPT 0x4207  // line 30 ✓ matches
#define PTRACE_EVENT_STOP 128    // line 99 (not defined in code; see finding F1)
```

**linux/elf.h** (AOSP android15, line 301):
```
#define NT_PRSTATUS 1  // ✓ matches NT_PRSTATUS=1
```

**asm-arm64/asm/ptrace.h** (AOSP android15, lines 49–54):
```c
struct user_pt_regs {
  __u64 regs[31];  // 31×8 = 248 bytes
  __u64 sp;        // +8 = 256
  __u64 pc;        // +8 = 264
  __u64 pstate;    // +8 = 272
};  // ✓ total 272 bytes; layout matches UserPtRegs exactly
```

**asm-generic/unistd.h** (syscall numbers):
```
#define __NR_openat  56   // line 158 ✓
#define __NR_close   57   // line 160 ✓
#define __NR_getpid 172   // line 461 ✓ matches NR_GETPID=172
#define __NR_mmap   222   // line 570 (via __NR3264_mmap) ✓
#define __NR_process_vm_readv  270  // line 657 ✓
#define __NR_process_vm_writev 271  // line 659 ✓
```

All external API values are correct. No drift found.

---

### Stage 2 — Code Quality + Defect Analysis

---

### Issues

---

[MAJOR]
[LOCATION: crates/resetprop/src/seal/ptrace.rs:149-158 (ptrace_seize)]
[DEFECT: `PTRACE_SEIZE` is called without `PTRACE_O_TRACESYSGOOD` in the `data` argument, contradicting the reference spec §6 which requires options to be set atomically at SEIZE time; the `data` argument is passed as literal `0`.]
[EVIDENCE:
Code (ptrace.rs:153-154):
```rust
let rc =
    unsafe { libc::ptrace(PTRACE_SEIZE as _, pid, 0 as *mut c_void, 0 as *mut c_void) };
```
Reference spec linux-arm64-abi.md §6, line 153:
```
1. `ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD)` — attaches
   without stopping the tracee; sets options atomically.
```
The `data` parameter of `PTRACE_SEIZE` is the options bitmask. Passing `0` omits `PTRACE_O_TRACESYSGOOD`. This does not block P01's smoke test (the test uses only `brk` traps, not syscall-stops), but it diverges from the reference that every downstream phase (P02–P04) was written against. Any P03/P04 code that subsequently relies on `SIGTRAP|0x80` syscall-stop disambiguation will silently behave differently than expected when `PTRACE_O_TRACESYSGOOD` is absent.

Additionally, `PTRACE_O_TRACESYSGOOD` is defined in linux/ptrace.h line 100 (`#define PTRACE_O_TRACESYSGOOD 1`) and is referenced in the codebase's own reference docs but never defined as a constant in ptrace.rs, leaving future phases without a canonical source. The spec §6 lifecycle is the single reference for all ptrace attach/detach operations; the implementation deviates from it at step 1.]
[FIX: Define `pub const PTRACE_O_TRACESYSGOOD: c_int = 1;` in ptrace.rs (matching linux/ptrace.h:100) and pass it in the `data` argument of `PTRACE_SEIZE`:
```rust
pub const PTRACE_O_TRACESYSGOOD: c_int = 1;  // linux/ptrace.h:100

pub fn ptrace_seize(pid: Pid) -> Result<()> {
    let rc = unsafe {
        libc::ptrace(
            PTRACE_SEIZE as _,
            pid,
            0 as *mut c_void,
            PTRACE_O_TRACESYSGOOD as *mut c_void,  // sets option atomically
        )
    };
    ...
}
```]

---

[MAJOR]
[LOCATION: crates/resetprop/src/seal/ptrace.rs:186-204 (wait_stop)]
[DEFECT: `wait_stop` rejects any `event` byte other than 0 via `WSTOPSIG != SIGTRAP`, but the initial SEIZE+INTERRUPT stop always arrives with `event == PTRACE_EVENT_STOP (128)`. This means `wait_stop` will fail on the very first call in the seize/interrupt/wait_stop sequence used throughout ptrace.rs, the spec, and the smoke test.]
[EVIDENCE:
Code (ptrace.rs:195-203):
```rust
let is_stopped = libc::WIFSTOPPED(status);
let sig = libc::WSTOPSIG(status);
if !is_stopped || sig != libc::SIGTRAP {
    return Err(Error::PtraceAttach(io::Error::new(
        io::ErrorKind::Other,
        format!("unexpected wait status: 0x{status:x}"),
    )));
}
```
Reference spec linux-arm64-abi.md §6, lines 158–159:
```
4. Expect `WIFSTOPPED(status)` true, `(status >> 16) == PTRACE_EVENT_STOP`
   (128), `WSTOPSIG(status) == SIGTRAP`.
```
Reference spec linux-arm64-abi.md §9, lines 232–234:
```
- Group-stop (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU): `event ==
  PTRACE_EVENT_STOP` (128). Initial SEIZE+INTERRUPT stop also reports
  `event == 128` with `stopsig == SIGTRAP` — that one is expected.
```
The smoke test (ptrace_core_smoke.rs:155) calls `wait_stop(guard.pid())` to consume the initial SEIZE stop. The initial stop has `WSTOPSIG == SIGTRAP` (5) AND `(status >> 16) == 128`. `wait_stop` only checks `WSTOPSIG == SIGTRAP`, which is satisfied by the initial stop — so this call actually PASSES.

However the check is still wrong by omission: the `event` byte is never examined in `wait_stop`. The function accepts both `event==0` (brk-trap) and `event==128` (SEIZE group-stop) and `event==1..=7` (fork/exec/clone) identically, masking logic errors in callers. The spec explicitly designates two distinct wait-stop roles: one for the initial SEIZE stop (`event==128`) and one for the brk-trap (`event==0`). The function should either:
  (a) Verify `event==128` for the initial stop and `event==0` for the brk-trap (requires splitting into two functions), OR
  (b) Document that `wait_stop` is intentionally event-agnostic and the caller is responsible for checking the event byte.
`remote_syscall` does check `event != 0` for the brk-trap but `wait_stop` on line 155 of the smoke test (initial stop) will silently accept `event==128`, which is correct. The ambiguity does not cause a bug today but creates a latent maintenance hazard as P02–P04 add new call sites.

Assessment: This is MAJOR because the function's contract (`WIFSTOPPED && WSTOPSIG==SIGTRAP`) is incomplete relative to the reference spec, and new callers in P02–P04 will not know whether to call `wait_stop` or check the event byte themselves. The split contract is a likely source of defects in the next phases.]
[FIX: Rename `wait_stop` to `wait_seize_stop` for the initial SEIZE stop (checking `event==128`) and keep `wait_stop` with the tighter `event==0` contract for use after `PTRACE_CONT`. Alternatively add a documented `event` parameter:
```rust
/// Wait for a ptrace stop; `expected_event` is 128 for the initial SEIZE
/// stop and 0 for a brk/signal-trap.
pub fn wait_stop(pid: Pid, expected_event: u32) -> Result<i32> {
    ...
    let event = ((status >> 16) & 0xffff) as u32;
    if !is_stopped || sig != libc::SIGTRAP || event != expected_event {
        return Err(...);
    }
    Ok(status)
}
```]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/ptrace.rs:338-339 (write_remote SAFETY comment)]
[DEFECT: The SAFETY comment for `write_remote` states "kernel's `process_vm_writev` path bypasses VMA write bits for ptrace-attached writers", but this claim is not accurate: `process_vm_writev` does NOT bypass VMA write protections. It can write to read-only mappings only if the kernel's copy-on-write machinery allows it, but it will fail with EFAULT on genuinely read-only pages (e.g., shared file-backed mappings with no write permission). Only `PTRACE_POKEDATA` or `/proc/<pid>/mem` writes bypass VMA protections through the kernel's `ptrace_access_vm` path. The comment therefore creates a false expectation in downstream engineers that `write_remote` can target any rx mapping.]
[EVIDENCE:
Code (ptrace.rs:334-341):
```rust
/// # Safety
///
/// Caller guarantees `remote_addr..remote_addr + buf.len()` is writable in
/// the tracee (kernel's `process_vm_writev` path bypasses VMA write bits for
/// ptrace-attached writers, so an rx page backing executable code is
/// acceptable as long as the caller owns its content for the duration of
/// the call) and that the tracee is ptrace-stopped.
```
linux-arm64-abi.md §8, lines 205–214 (correct formulation):
```
`process_vm_writev` bypasses VMA write bits via the kernel mm path
```
However the actual Linux kernel source (mm/process_vm_access.c) does NOT skip VMA permission checks for `process_vm_writev`. The smoke test is safe only because the scratch page is `PROT_READ|PROT_WRITE|PROT_EXEC` (i.e., writable). The reference doc itself contains this same inaccuracy. This is a documentation bug that will cause confusion in P03/P04 when targeting libc.so padding (read-only mapped pages).]
[FIX: Correct the SAFETY doc:
```rust
/// # Safety
///
/// Caller guarantees `remote_addr..remote_addr + buf.len()` is writable
/// in the tracee (i.e., the VMA has write permission — `process_vm_writev`
/// does NOT bypass VMA write bits; use an RWX anonymous page as scratch).
```]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/ptrace.rs:103-104 (size assert gate)]
[DEFECT: The compile-time `size_of` assert is gated behind `#[cfg(target_arch = "aarch64")]`, but the comment says "the assertion is still sound (size is layout-invariant under `#[repr(C)]`)". If the assertion is truly sound on all architectures, there is no reason to gate it — removing the gate would give stronger protection on x86_64 dev boxes where `u64` is also 8 bytes. The gate was added per spec §Approach.4 as a policy decision, but the inline comment contradicts the policy's rationale (which was to let `cargo check` pass "even if future porting changes the primitive sizes", implying the assert might fail on hypothetical future arches, not on current x86_64).]
[EVIDENCE:
Code (ptrace.rs:103-104):
```rust
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);
```
The spec says: "Non-arm64 hosts skip the assert so `cargo check` on x86_64 dev boxes still passes". On x86_64 with `u64` = 8 bytes, `UserPtRegs` has identical layout to arm64, so the assert would pass on x86_64 too. The `#[cfg]` gate therefore buys nothing for current host architectures and silently weakens the guard.]
[FIX: Either remove the `#[cfg]` gate (the assert is sound everywhere u64=8) or update the comment to honestly state the reason is policy/cross-compilation hygiene rather than correctness concern:
```rust
// Gated to aarch64 per REGISTRY §2 row 11: avoids surprising failures on
// hypothetical 32-bit host ports where u64 layout could differ.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);
```]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/ptrace.rs:397-474 (remote_syscall)]
[DEFECT: `remote_syscall` is declared `pub unsafe fn` but is not re-exported with a `pub use` from `seal/mod.rs`. The mod.rs re-export at line 43 includes `remote_syscall`, so it IS accessible as `resetprop::seal::remote_syscall`. However, the function signature carries `unsafe` which means callers cannot call it in safe code regardless of pub visibility. This is correct design — but the function's doc-comment does not document the precondition that the tracee must already be ptrace-stopped AND that `scratch_pc` must be 4-byte aligned, in a `# Preconditions` section. The preconditions are in a prose paragraph but not in the canonical Rust `# Safety` heading position where downstream consumers (P02, P04) will look first.]
[EVIDENCE:
Code (ptrace.rs:390-396):
```rust
/// Caller must have already:
/// - invoked [`ptrace_seize`] + [`ptrace_interrupt`] on `pid`;
/// - consumed the initial SEIZE stop via [`wait_stop`];
/// - ensured `scratch_pc` is 4-byte aligned...
///
/// # Safety
///
/// Caller guarantees (a) the tracee is ptrace-stopped at entry, (b)
```
The full precondition list appears before the `# Safety` section and partially in it, making the contract split across two locations.]
[FIX: Consolidate all preconditions under `# Safety` and remove the duplicating prose block above it.]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/maps.rs:88-103 (path parsing)]
[DEFECT: The `split_whitespace` + `join(" ")` strategy for reconstructing the path column is documented as correct because "real maps paths never contain spaces". This is true for Android property arena paths but is not a kernel guarantee. The comment acknowledges this but the code provides no error path for paths containing spaces — it silently re-joins them. This is low risk for P01 scope but will become a correctness hazard if `find_by_path` is ever asked to match a path that was reconstructed with space-collapsing (e.g., multiple spaces in the original become one).]
[EVIDENCE:
Code (maps.rs:88-103):
```rust
// split_whitespace collapses runs of spaces, so the path cannot contain
// leading spaces once we rejoin; real maps paths never contain spaces.
let path = {
    let remainder: Vec<&str> = it.collect();
    ...
    let joined = remainder.join(" ");
```
The Linux kernel's `/proc/<pid>/maps` format uses a fixed number of space-separated columns (5) and then the rest of the line as the path. A more precise parser would use `splitn(6, ' ')` to take the path column verbatim without collecting and re-joining.]
[FIX: Use `splitn` to avoid the collect + join allocation and preserve exact path content:
```rust
// Use splitn(6, ...) so column 6+ is captured verbatim as the path.
let mut it = trimmed.splitn(6, ' ');
// ... consume first 5 columns ...
let path = it.next()  // remainder is the raw path string
    .filter(|s| !s.trim().is_empty())
    .map(|s| s.trim_start())
    .map(|s| PathBuf::from(s.strip_suffix(" (deleted)").unwrap_or(s)));
```]

---

[MINOR]
[LOCATION: crates/resetprop/tests/ptrace_core_smoke.rs:147]
[DEFECT: A 50ms `thread::sleep` is used to give the child time to reach `pause()` before the parent sends `PTRACE_INTERRUPT`. This is a TOCTOU race: on a heavily loaded system, 50ms may not be sufficient. The reference spec (test-harness-patterns.md §3) recommends this pattern for single-shot smoke tests under `yama=0 localhost`, which is acceptable for a smoke test. The actual race window is small (child just needs to be past `execve` and `fork` cleanup). However there is a more robust alternative that eliminates the sleep entirely.]
[EVIDENCE:
Code (ptrace_core_smoke.rs:147):
```rust
std::thread::sleep(std::time::Duration::from_millis(50));
```
If `PTRACE_INTERRUPT` fires before the child calls `pause()`, the child is still alive and running; `ptrace_interrupt` + `wait_stop` still succeeds because `PTRACE_SEIZE` + `PTRACE_INTERRUPT` works on any running process, not just processes blocked in `pause`. The race is theoretical here, but the sleep gives a false sense of synchronization.]
[FIX: Either keep the sleep (acceptable per test-harness-patterns.md) with a comment explaining it is a best-effort yield, or use a pipe/eventfd to signal readiness from child before entering `pause`. The current approach is acceptable for P01 scope.]

---

### Positive Observations

1. **External API constants are all correct.** Every `PTRACE_*`, `NT_PRSTATUS`, and `NR_GETPID` constant was verified against the authoritative AOSP and kernel headers and all match exactly. No constant drift.

2. **`UserPtRegs` layout is perfect.** The struct exactly mirrors `struct user_pt_regs` from `asm-arm64/asm/ptrace.h:49-54` — field order, types, and count are all correct. The 272-byte size assertion will catch any future accidental reordering.

3. **SAFETY comments are thorough and consistent.** Every `unsafe` block across all three source files carries a well-formed `// SAFETY:` comment that identifies the invariant. This is fully compliant with REGISTRY §2 row 12.

4. **`classify_seize_err()` EPERM/Yama classification is well-designed.** The two-level classification (read ptrace_scope, classify `0` as PtraceAttach and `>0` as PtraceScope) is exactly right for the CLI remediation path and handles the missing/unreadable scope file gracefully.

5. **`remote_syscall` restore ordering is correct.** The function restores registers first (`setregset(pid, &saved_regs)`) then memory (`write_remote(scratch_pc, &saved_bytes)`). This is the correct order: registers hold the saved `pc` which must be restored before memory, so if `write_remote` fails, the tracee can still be detached with a valid `pc`.

6. **Partial-transfer loops in `read_remote` / `write_remote` are correct.** Both loops advance the offset, reduce the remaining count, and handle the `n==0` stall case. This correctly implements the `process_vm_readv/writev` partial-transfer contract from linux-arm64-abi.md §10.

7. **`ChildGuard::drop` is correctly ordered.** `SIGKILL` is sent, `WNOHANG` waitpid drains an already-zombie child, then a blocking `waitpid` handles the still-running case. The double-waitpid pattern cleanly handles both states and the `ESRCH` case (already reaped) is harmless.

8. **Module insertion point is correct.** `pub mod seal;` lands at lib.rs:33 (after line 32 `mod wait;`), exactly as specified by the P01 spec and integration reference.

9. **Error variant `Display` + `Error::source` are complete.** All 7 new variants have `Display` arms; `PtraceAttach(e)` surfaces `Some(e)` from `source()` while the remaining six return `None` via the `_ => None` arm. This exactly matches the spec.

10. **`find_by_path` returns the first match.** The spec says "exact path" matching, and `Iterator::find` returns the first entry whose `path` equals the query. For P02/P03 usage (looking up a specific arena file or `libc.so`), first-match is correct because a given file is typically mapped at multiple contiguous addresses (text, data, bss segments) and P02 wants the first (lowest-address) segment.

---

### LSP Diagnostics

All 5 modified/created files returned zero diagnostics from the language server (rust-analyzer). No type errors, no unused import warnings.

---

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0     |
| MAJOR    | 2     |
| MINOR    | 5     |

**MAJOR findings:**
- F1 (ptrace.rs:154): `PTRACE_SEIZE` passes `data=0` instead of `PTRACE_O_TRACESYSGOOD`, diverging from the reference spec §6 that all downstream phases are written against.
- F2 (ptrace.rs:197): `wait_stop` does not validate the event byte, making the initial SEIZE stop and brk-trap stops indistinguishable at the function boundary; the split contract will cause defects in P02–P04 callers.

Both MAJOR findings are protocol-level gaps: they do not break the P01 smoke test as written, but they create incorrect foundations for P02–P04 which rely on the ptrace lifecycle primitives being spec-complete.

---

VERDICT: NEEDS_FIX

2 MAJOR findings must be resolved before merging. No CRITICAL issues. 5 MINOR issues are logged for implementer awareness and may be addressed in a follow-up commit within P01 or deferred to a cleanup pass before P02 begins.

## critic report — round 2

**VERDICT: ACCEPT** (upgraded from round-1 ACCEPT-WITH-RESERVATIONS after fix-cycle verification)

**Overall Assessment**: All three round-1 MAJOR findings are cleanly resolved with mechanically verifiable evidence. The fix cycle is not just cosmetic — each change was made at the right semantic layer (not a band-aid), and the REGISTRY amendment is sound. The new `wait_stop(pid, expected_event: u32)` contract is well-designed for downstream consumers; it does not leak complexity. Two new MINOR findings surfaced during re-audit (checklist drift + reference-doc inconsistency), neither blocking. No CRITICAL findings.

**Pre-commitment Predictions (round 2)**:
1. M1 fix will set TRACESYSGOOD but forget to expose the constant publicly — **REFUTED** (`pub const PTRACE_O_TRACESYSGOOD: c_int = 1;` at ptrace.rs:49 with citation comment).
2. M2 fix will partially split error variants but leave `wait_stop` unexpected-status as `PtraceAttach` — **REFUTED** (ptrace.rs:224 correctly emits `PtraceUnexpectedStatus(status)`; helper is properly renamed to `last_ptrace_op_err`).
3. M3 fix will downgrade ARM64 consts but leave `NR_GETPID` public — **REFUTED** (grep confirms `NR_GETPID` no longer exists in `ptrace.rs`; lives only at `tests/ptrace_core_smoke.rs:40`).
4. REGISTRY row 35 amendment will be silently inconsistent with code — **REFUTED** (REGISTRY row 35 enumerates 9 variants; `error.rs:5-24` enumerates exactly those 9; display + source arms complete).
5. `wait_stop(pid, expected_event)` contract will feel like a band-aid — **REFUTED after investigation** (the parameter is semantically meaningful per the kernel's own `(status >> 16)` event byte, captures the exact distinction the spec §9 requires, and the test-site usage reads naturally).

Escalation: thorough mode throughout. Zero MAJOR or CRITICAL after re-audit → no ADVERSARIAL expansion triggered.

---

### Round-1 Finding Resolution Verification

**M1 (PTRACE_O_TRACESYSGOOD) — RESOLVED.**
- Evidence: `crates/resetprop/src/seal/ptrace.rs:49` declares `pub const PTRACE_O_TRACESYSGOOD: c_int = 1;` citing `linux/ptrace.h:100`. Verified against `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h:100` (`#define PTRACE_O_TRACESYSGOOD 1`) — exact match.
- The SEIZE call at `ptrace.rs:168-175` passes `PTRACE_O_TRACESYSGOOD as *mut c_void` as the fourth argument, matching linux-arm64-abi.md:153 `ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD)` verbatim.
- Commit `6fc6b48 fix(seal): harden ptrace primitives per Gate 2 audit` body explicitly cites round-1 M1.
- Confidence: HIGH.

**M2 (Error::PtraceAttach overload) — RESOLVED.**
- Evidence: `error.rs:15-17` declares three distinct variants: `PtraceAttach(std::io::Error)`, `PtraceOp(std::io::Error)`, `PtraceUnexpectedStatus(i32)`. Call-site audit:
  - `ptrace_seize` → uses `classify_seize_err` → `PtraceAttach` or `PtraceScope` only (`ptrace.rs:130-147, 176-178`). Attach-phase only. Correct.
  - `ptrace_interrupt`, `getregset`, `setregset`, `ptrace_detach`, `PTRACE_CONT` in `remote_syscall` → all use `last_ptrace_op_err` → `PtraceOp` (`ptrace.rs:196, 252, 277, 294, 471`). Correct.
  - `wait_stop` waitpid failure → `PtraceOp` via `last_ptrace_op_err` (`ptrace.rs:218`). Unexpected wait status → `PtraceUnexpectedStatus(status)` carrying raw status bits (`ptrace.rs:224`). Correct — the raw `i32` payload is exactly what callers need for triage, not an `io::Error`.
  - `read_remote`/`write_remote` partial-transfer stall → `PtraceOp` (`ptrace.rs:335, 338, 384, 387`). Correct.
- `Display` impl (`error.rs:39-44`) emits distinct messages per variant. `Error::source` (`error.rs:62`) returns `Some(e)` for both `PtraceAttach(e)` and `PtraceOp(e)`, correctly returning `None` for `PtraceUnexpectedStatus` since there's no wrapped error there.
- Commit `6fc6b48` + REGISTRY amendment `684f551` (see below) close the round-1 finding cleanly.
- Confidence: HIGH.

**M3 (public constant leakage) — RESOLVED.**
- Evidence: `crates/resetprop/src/seal/ptrace.rs:68,74` — both `ARM64_SVC_0` and `ARM64_BRK_0` are `pub(crate) const`. The doc comments explicitly justify the scoping: "`pub(crate)` scope because only [`remote_syscall`] consumes this; the ARM64 encoder in P04 (`seal/hook.rs`) re-derives its own encodings." This is semantically correct — the P04 encoder will need its own trampoline constants, not these ones.
- `NR_GETPID` no longer appears in `ptrace.rs`. Grep confirms it is declared exclusively at `tests/ptrace_core_smoke.rs:40` as a `const NR_GETPID: u64 = 172` local to the test crate with citation `asm-generic/unistd.h:461`. Verified against `/usr/include/asm-generic/unistd.h` — citation matches.
- The public surface of `seal::ptrace` now exposes only: `PTRACE_*` request numbers, `PTRACE_O_TRACESYSGOOD`, `PTRACE_EVENT_STOP`, `NT_PRSTATUS`, `UserPtRegs`, and the six primitives + `remote_syscall`. That is correct: external callers need the PTRACE constants for status bit decoding and event classification; they do not need ARM64 instruction bytes.
- Confidence: HIGH.

**REGISTRY §1 Row 35 Amendment (684f551) — SOUND.**
- The amended row enumerates 9 variants with an in-line rationale: "[Amended S02 2026-04-18 per Gate 2 critic M2: split the original `PtraceAttach` catch-all into three semantically-distinct variants so the CLI and P02/P04 can match-on-variant for hint logic.]"
- The amendment trail is audit-friendly (explicit date, source, reason). The 9 variants listed in REGISTRY row 35 exactly match the 9 new variants in `error.rs:7-23` (modulo the 2 pre-existing variants `PermissionDenied(io::Error)` and `Io(io::Error)`, which were not added by P01). Spot-check: `PtraceAttach(io::Error)`, `PtraceOp(io::Error)`, `PtraceUnexpectedStatus(i32)`, `PtraceScope`, `ArenaAlreadySealed(PathBuf)`, `ArenaNotMapped(PathBuf)`, `ElfParse(String)`, `SymbolNotFound(String)`, `HookInstallFailed(String)` — 9 new, all present.
- The amendment preserves the "match `error.rs:5-22`" citation convention used throughout REGISTRY.
- Confidence: HIGH.

### New `wait_stop(pid, expected_event: u32)` Contract Review

Round-2 mandate: "does the new contract feel right for P02/P04 consumers, or does it feel like a band-aid?"

Verdict: **the contract is correct and does not leak complexity.**

Rationale:
1. The `event` byte at `(status >> 16) & 0xffff` is the kernel's own distinguishing signal between the initial SEIZE group-stop (`PTRACE_EVENT_STOP == 128`) and a post-CONT brk-trap (`event == 0`). Making the caller declare which one they expect is not arbitrary — it is the minimum information needed to decide whether the status is correct. See linux-arm64-abi.md:158-159 and §9 lines 232-234 where the spec itself requires callers to distinguish these two.
2. P02/P04 consumers have only two legitimate call sites for `wait_stop`:
   - After `ptrace_seize` + `ptrace_interrupt` → expect `PTRACE_EVENT_STOP` (128). One line.
   - After `PTRACE_CONT` through a staged `svc ; brk` (via `remote_syscall`) → expect `0`. Already handled inside `remote_syscall` itself at `ptrace.rs:478`, so P02/P04 never write this call directly.
3. The alternative "split into `wait_seize_stop` and `wait_brk_stop`" (proposed by code-reviewer round 1) would have produced two functions with ~95% duplicated body, only differing in the expected event constant. The parameterized form is strictly simpler.
4. The constant `PTRACE_EVENT_STOP: u32 = 128` is `pub` and exported from `seal::ptrace` (used by `ptrace_core_smoke.rs:32` via `use resetprop::seal::ptrace::PTRACE_EVENT_STOP;`). This is the named-constant discipline; callers do not pass magic `128`.
5. Complexity leakage check: if P04 ever needs to handle `PTRACE_EVENT_EXEC` or group-stops after delivered signals, the parameter generalizes to `0 | 128 | 4 (EVENT_EXEC) | ...` without API churn. A split-function design would force adding a third function. The parameterized design is the one that scales.

Not a band-aid. Approve.

### Critical Findings
None.

### Major Findings
None.

### Minor Findings

**m5 (NEW). Checklist is stale — file:line references and self-audit notes predate the fix cycle.**
- Evidence: `phases/seal/checklists/P01-checklist.md` contains no mention of M1/M2/M3, TRACESYSGOOD, `PtraceOp`, `PtraceUnexpectedStatus`, or the round-1 audit (grep for "TRACESYSGOOD|expected_event|PtraceOp|PtraceUnexpectedStatus|M1|M2|M3|round 1|round 2" returns zero matches). Specific stale references:
  - Line 58: "Also `NR_GETPID=172` added (used by T5's smoke test) per dispatch directive." — NR_GETPID no longer exists in ptrace.rs; moved to test file.
  - Line 62: cites yama classification at "ptrace.rs:118-133, 149-159" — actual lines are 130-147, 163-180 after T3-fix cycle.
  - Line 63: cites SAFETY pairing "lines 150/153, 166/167, 187/190, 217/222, 245/247, 263/264" — invalid after 6fc6b48 hardening.
  - Line 138: FR-22 reads `wait_stop(pid)` but actual signature is `wait_stop(pid, expected_event)`. Self-audit gate for T3 (line 71 Correctness note 3) still documents `PtraceAttach(io::Error::new(io::ErrorKind::Other, format!("unexpected wait status...")))` as the unexpected-stop behavior — that was the round-1 behavior; round-2 behavior is `PtraceUnexpectedStatus(i32)`.
  - Canonical Values table line 178: cites `NR_GETPID` at "`crates/resetprop/src/seal/ptrace.rs:67`" — NR_GETPID is no longer in that file.
  - AS-05 line 201: states `lib.rs` has only "1-char `mod seal;` → `pub mod seal;` flip" — this was correct at round 1 but is still fine post-fix (no AS change).
- Confidence: HIGH.
- Why this matters: A future auditor reading this checklist will believe the code matches the line numbers shown. It does not. The checklist was written to document round-1 state and was not updated when round-1 findings were fixed. This does not break code but breaks the checklist's function as a traceable audit artifact.
- Fix: Before checking the "Phase-End Adversarial Audit (Gate 2)" boxes at lines 211-221, regenerate the file:line citations in Task 3 checkboxes, FR-22, the Canonical Values table, and the SAFETY-pairing claim on line 63 (the current code has 12 SAFETY/unsafe pairings after T4, not 6 after T3). Also update FR-22 to reflect the `wait_stop(pid, expected_event: u32)` signature and update T3 Gate 3 §Correctness note 3 to describe the new `PtraceUnexpectedStatus` behavior.

**m6 (NEW). Reference doc `linux-arm64-abi.md:213` still contains the inaccurate claim that `process_vm_writev` "bypasses VMA write bits via the kernel mm path" — code no longer agrees with the reference.**
- Evidence: `grep -n "bypasses VMA" phases/seal/references/linux-arm64-abi.md` → line 213. The round-1 code-reviewer flagged this as inaccurate; the round-1 fix cycle corrected the SAFETY comment in `ptrace.rs:357-366` (now reads "`process_vm_writev` does NOT bypass VMA write bits") but did not update the reference doc. The reference doc is REGISTRY §3's "shared references" artifact consumed by every session's agents.
- Confidence: HIGH.
- Why this matters: P03 targets `libc.so` RX padding for trampoline installation. If a future P03/P04 author reads linux-arm64-abi.md §8 first (which is the documented hot-load pattern per REGISTRY §6 row "Hot-load references") they will believe `process_vm_writev` can write to the RX mapping. It cannot. The P03/P04 plan will need an `mprotect` step — if the author trusts the reference over the code, they will omit it and the hook install will silently fail with EFAULT.
- Fix: Correct `linux-arm64-abi.md:213` to match the new SAFETY comment: `process_vm_writev` respects VMA write bits and returns EFAULT on non-writable pages; trampoline installation requires a prior remote `mprotect(…, PROT_READ|PROT_WRITE|PROT_EXEC)` round-trip. This should be a docs-only commit; it does not affect P01 code.

### What's Missing (gaps still open after fix cycle)

- **Still no `debug_assert!(scratch_pc & 3 == 0)` in `remote_syscall`.** Round-1 "What's Missing" item still unfixed. Low-priority for P01 (the test's mmap'd page is page-aligned) but worth a cheap assertion before P04.
- **Still no `PTRACE_O_EXITKILL` flag discussion.** Round-1 flagged this as a gap for P04 (init attachment). Not a P01 defect but worth noting in P04 spec.
- **Still no `debug_assert!` or runtime check that the tracee is ptrace-stopped** on entry to `remote_syscall` / `getregset` / `setregset`. These are `unsafe` contracts, so compiler-enforced is impossible, but a `debug_assert!` querying `/proc/<pid>/status` field `State:` could catch misuse in P02/P04 development cycles cheaply.
- **Still no CI entry for the `--ignored` integration test.** The on-device runs cited in the checklist (TC-07) are manual. Without CI the test can rot silently across P02/P03/P04. Flag for P05.
- **`lib.rs:33` visibility flip `pub mod seal;` exposes `seal::maps::parse_line` (pub(super))** — wait, let me verify. `parse_line` is `pub(super)` at `maps.rs:51`, so it's reachable only from `seal/mod.rs`, not crate-external. Confirmed: crate-external callers see only what `pub use maps::{MapEntry, parse_maps};` at `mod.rs:38` re-exports, plus anything `pub` on the `maps` module surface (`MapEntry`, `parse_maps`, `find_by_path`). Correct — not a leak.

### Multi-Perspective Notes

- **Skeptic**: The strongest argument against accepting the fix cycle is m5 (stale checklist). An auditor walking the checklist in P02's Gate 2 will hit cited line numbers that don't match the code and may distrust the whole artifact. Counter: the CODE is correct; the checklist drift is documentation debt, fixable in a follow-up commit without code changes. Not grounds to block the fix cycle.
- **Executor (P02 author)**: "Can I consume the new surface cleanly?" Yes. `use resetprop::seal::ptrace::{PTRACE_EVENT_STOP, ...};` works; `wait_stop(pid, PTRACE_EVENT_STOP)` reads naturally; `PtraceOp` vs `PtraceAttach` vs `PtraceUnexpectedStatus` allow the CLI to match on variant for targeted remediation hints. The split was the right call.
- **Stakeholder**: Did the fix cycle land the fixes without regression? Yes — 63 unit tests pass (unchanged), `constants_match_canonical_values` test validates all 11 constants (`ptrace.rs:512-523`), `size_assert` test preserves the compile-time tripwire. Commit quality is good (three atomic commits, conventional-commits prefix, signed work).
- **Ops**: What fails under load in the new surface? Still no `waitpid` timeout — a lost `PTRACE_INTERRUPT` or a dropped kernel event will hang the parent forever. Still round-1 "What's Missing" territory. P02/P04 robustness concern, not a P01 blocker. Also: `PtraceUnexpectedStatus(i32)` carrying the raw status bits is excellent for post-hoc triage — an operator reading the log sees exactly what the kernel reported.

### Ambiguity Risks

- The new `wait_stop(pid, expected_event: u32)` has `expected_event` typed as `u32`. `PTRACE_EVENT_STOP` is declared as `u32` (`ptrace.rs:54`). However `PTRACE_O_TRACESYSGOOD` is `c_int`, and `PTRACE_CONT`/`PTRACE_DETACH`/etc. are `c_int`. Type inconsistency between "option" constants (`c_int`) and "event" constants (`u32`) is defensible (events are positive status-byte payloads, options are kernel API arguments) but future authors may mis-cast. Not a defect; minor style concern.

### Verdict Justification

All three round-1 MAJOR findings (M1, M2, M3) are resolved with mechanically verifiable evidence. The REGISTRY amendment at commit `684f551` is sound. The new `wait_stop(pid, expected_event: u32)` contract is the right design — not a band-aid; it captures a real kernel-level distinction that P04's multi-threaded tracee work will need. Round-2 surfaces two new MINOR findings: checklist drift (m5) and reference-doc inconsistency (m6). Neither blocks merge; both should be addressed in docs-only commits before the Gate 2 acceptance boxes at checklist lines 211-221 are checked.

No Realist Check recalibration needed — no CRITICAL or MAJOR findings to pressure-test.

Upgrade verdict from round-1 ACCEPT-WITH-RESERVATIONS to **ACCEPT**. Recommend: land a docs-only follow-up commit `docs(seal): refresh P01 checklist + linux-arm64-abi reference post-fix-cycle` addressing m5 and m6, then check the Gate 2 acceptance boxes and mark REGISTRY §4 P01 row `Status = COMPLETE`.

### Open Questions (unscored)

- The `wait_stop` function ignores the upper 8 bits of the event byte (`(status >> 16) & 0xffff` extracts 16 bits but kernel only uses the low byte for `PTRACE_EVENT_*`). Harmless — but if P04 ever sees a status with non-zero upper event bits (unlikely; reserved by kernel) the function will silently reject it as "unexpected." Not a defect today.
- Does the aarch64-only compile-time size assert `size_of::<UserPtRegs>() == 272` still trigger if a future rustc changes `u64` alignment on aarch64? Stable Rust guarantees `size_of::<u64>() == 8` so this is unreachable; purely academic.
- On Android 15, does `/proc/sys/kernel/yama/ptrace_scope` exist? Most AOSP builds have yama enabled; but some carrier customizations disable it entirely. `classify_seize_err` handles the "file missing" case correctly (falls through to `PtraceAttach`), so behavior is sound either way. Documentation nit: the round-1 finding stays, "ops triage chain undocumented" — still not annotated in code comments.

VERDICT: PASS
