# P02 Gate 2 Adversarial Audit

## Round 1

## code-reviewer report

**Phase:** P02 — Tier A arena-level seal via remote MAP_PRIVATE|MAP_FIXED  
**Branch:** feat/P02-tier-a  
**Files reviewed:**
- `crates/resetprop/src/seal/arena.rs` (587 lines, new)
- `crates/resetprop/src/seal/mod.rs` (modified — arena exports, SEALS static, tests)
- `crates/resetprop/src/seal/ptrace.rs` (modified — PEEK/POKE primitives, read_remote/write_remote)
- `crates/resetprop/src/lib.rs` (modified — PropSystem::seal_arena / unseal_arena + helpers)
- `crates/resetprop/tests/tier_a_child_smoke.rs` (284 lines, new)

**External APIs verified:** YES — all claimed values confirmed against named AOSP sources.

---

## Stage 1 — Spec Compliance

### Scope verification

All five P02 tasks are present and accounted for:

- T1 `find_arena_mapping` / `find_arena_mapping_in`: shipped in `arena.rs:56-75`. Three unit tests present.
- T2 `PTRACE_PEEKDATA/POKEDATA` primitives + NOP-slide scanner: shipped in `ptrace.rs:326-375` and `arena.rs:79-111`. Four unit tests present.
- T3 `RemoteAttach` RAII guard + `remote_remap_private`: shipped in `arena.rs:143-405`. Guard `Drop` impl present.
- T4 `seal_arena` / `unseal_arena` orchestrators + `OnceLock` registry + `PropSystem` API: shipped in `arena.rs:412-458` and `lib.rs:544-579`. Three unit tests present.
- T5 `tier_a_child_smoke.rs`: shipped, `#[ignore]`-gated, `fn() -> !` child bound, `ChildGuard` present.

Anti-scope verification: no `chmod`/`fchmod`/`fchown`/`ftruncate` calls found. No ELF parsing. No trampoline. No `persist/mod.rs` coupling. No CLI changes.

REGISTRY §1 `properties_serial` guard: present at `lib.rs:547` and `lib.rs:571` using the shared `SERIAL_FILE` constant.

REGISTRY §1 file-permissions invariant: confirmed no inode-permission mutations anywhere in the new code.

### Stage 1 result: PASS — all spec requirements met, anti-scope clean.

---

## Stage 2 — Code Quality and Correctness

### External API Verification (quoted against AOSP source)

**prop_area.cpp lines 99 (map_prop_area_rw mmap call):**
```cpp
void* const memory_area = mmap(nullptr, pa_size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```
The code replaces `MAP_SHARED` with `MAP_PRIVATE` — exactly one flag bit difference. All other arguments (`PROT_READ|PROT_WRITE`, `fd`, offset `0`) match. Verified.

**prop_area.cpp lines 63-68 (EACCES abort):**
```cpp
if (errno == EACCES) { abort(); }
```
Confirms that any file-permission change would cause init to abort on next reload. The code correctly avoids all permission modifications.

**prop_area.cpp lines 117-121 (map_fd_ro rejection criteria):**
```cpp
if ((fd_stat.st_uid != 0) || (fd_stat.st_gid != 0) ||
    ((fd_stat.st_mode & (S_IWGRP | S_IWOTH)) != 0) ||
    (fd_stat.st_size < static_cast<off_t>(sizeof(prop_area)))) {
```
No `fchown`/`fchmod` calls in new code. Verified safe.

**system_properties.cpp lines 325-333 (properties_serial global wake channel):**
```cpp
atomic_store_explicit(serial_pa->serial(), ..., memory_order_release);
__futex_wake(serial_pa->serial(), INT32_MAX);
```
`SERIAL_FILE = "properties_serial"` guard at `lib.rs:547` and `lib.rs:571` correctly blocks this file. Verified.

**system_properties.cpp lines 305-315 (appcompat mirror writes):**
Both `override_pi->value` and `override_pi->serial` are written alongside the primary. The `derive_mirror_path` helper correctly targets the appcompat mirror. Verified.

**uapi/linux/ptrace.h (all PTRACE constants):**  
`PTRACE_PEEKDATA=2`, `PTRACE_POKEDATA=5`, `PTRACE_CONT=7`, `PTRACE_DETACH=17`, `PTRACE_GETREGSET=0x4204`, `PTRACE_SETREGSET=0x4205`, `PTRACE_SEIZE=0x4206`, `PTRACE_INTERRUPT=0x4207`, `PTRACE_EVENT_STOP=128`, `PTRACE_O_TRACESYSGOOD=1` — all match verbatim.

**O_NOFOLLOW = octal 00400000 = 0x20000** (AOSP `asm-generic/fcntl.h`). `O_RDONLY_NOFOLLOW = 0x20000` matches. `O_RDWR_NOFOLLOW = 0x20002` matches `O_RDWR(2) | O_NOFOLLOW`.

**mmap flags:** `MAP_PRIVATE|MAP_FIXED = 0x12`, `MAP_SHARED|MAP_FIXED = 0x11`, `MAP_PRIVATE|MAP_ANON = 0x22` — all verified against kernel mman-common.h values.

**linux-arm64-abi.md §2 instruction encodings:**
- Reference doc: `ARM64_SVC_0 = 0xD4000001`, `ARM64_BRK_0 = 0xD4200000`
- `ptrace.rs:83`: `ARM64_SVC_0 = 0xd400_0001` — matches
- `ptrace.rs:89`: `ARM64_BRK_0 = 0xd420_0000` — matches

Both the `arena.rs` bootstrap construction (`svc_brk: u64 = (ARM64_SVC_0 as u64) | ((ARM64_BRK_0 as u64) << 32)`) and the `remote_syscall` byte-array construction produce identical 8-byte little-endian blobs `[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]`. Both are correct.

---

## Issues

---

[MAJOR]
[LOCATION: crates/resetprop/src/seal/arena.rs:390-392]
[DEFECT: Remote `close` failure after a successful `mmap` propagates `Err` to the caller even though the seal has already been applied — the VMA is already remapped MAP_PRIVATE|MAP_FIXED.]
[EVIDENCE:
```rust
let _ = unsafe {
    super::ptrace::remote_syscall(pid, bootstrap_page, NR_CLOSE, [fd, 0, 0, 0, 0, 0])?
};
```
`remote_syscall` returns `Err(PtraceOp(...))` if any ptrace operation inside it fails (e.g., `wait_stop` gets `PtraceUnexpectedStatus` if the tracee dies between the mmap and the close). The `?` propagates that error. `let _ =` only discards the `Ok(i64)` value; it does not suppress `Err`. The mmap at `arena.rs:361-386` was already applied before reaching line 390. The caller (`seal_arena`) sees `Err` and treats the seal as failed — but init's VMA is already remapped. The next `seal_arena` call would succeed and push a duplicate registry entry.]
[FIX: Wrap the close call so ptrace-level failures are swallowed (they indicate the tracee died, not that the seal failed). Use a non-propagating form with a diagnostic log:
```rust
// close: best-effort — the important invariant (mmap) is already satisfied.
// A ptrace failure here means init died, which is a system-level event.
let _ = unsafe {
    super::ptrace::remote_syscall(pid, bootstrap_page, NR_CLOSE, [fd, 0, 0, 0, 0, 0])
};
// Do NOT use '?' here: the seal is already applied regardless of close outcome.
```
Or alternatively, add a `// SAFETY:` comment making it explicit that this `?` is intentional and documenting that callers must treat `Err` after a successful `mmap` as a partial-success requiring registry reconciliation.]

---

[MAJOR]
[LOCATION: crates/resetprop/src/seal/arena.rs:238-249]
[DEFECT: The libc.so scan uses `file_name().to_str().is_some_and(|n| n.contains("libc"))` — this matches any file whose name contains "libc" (e.g., `libc++.so`, `libcurl.so`, `libcryptographic.so`). On some Android builds, `libc++.so` has a large r-xp mapping and precedes `libc.so` in /proc/maps order. Scanning a C++ standard library for a NOP slide is harmless but wasteful; worse, it would use that mapping's start address as the scratch_pc base, potentially placing scratch_pc inside a non-NOP region of `libc++.so` and then staging `svc+brk` at live code rather than a NOP padding run.]
[EVIDENCE:
```rust
.is_some_and(|n| n.contains("libc"))
```
On a typical Android 15 device `/proc/1/maps` includes:
```
7f1a000000-7f1a800000 r-xp ... /apex/com.android.runtime/lib64/bionic/libc.so
7f1b000000-7f1b400000 r-xp ... /system/lib64/libc++.so
```
The `.contains("libc")` predicate matches both. The first entry in iteration order wins, which may or may not be `libc.so`.]
[FIX: Tighten the predicate to require an exact basename or the `.so` suffix without `++`:
```rust
.is_some_and(|n| n == "libc.so" || n.starts_with("libc.so."))
```
This matches `libc.so` and `libc.so.6` (MUSL convention) but not `libc++.so` or `libcurl.so`.]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/arena.rs:393-401]
[DEFECT: The bootstrap RWX page is intentionally leaked in init's address space. The inline comment documents the rationale clearly, but the leak accumulates: each `seal_arena` call (primary + mirror = 2 attach cycles, each leaving a 4 KiB RWX page) adds 8 KiB of anonymous RWX memory to PID 1. On devices that call `seal_arena` + `unseal_arena` repeatedly (e.g., telephony reset flows), this could accumulate to a detectable footprint in `/proc/1/maps` — an operator-visible anomaly and a minor forensic indicator for the threat model ("rooted self-inspection can detect seal" per REGISTRY §1).]
[EVIDENCE: Inline comment at `arena.rs:395`: "The bootstrap RWX page is intentionally left mapped in the tracee". Each `seal_arena` call for a single property with a mirror produces 2 `remote_remap_private` invocations = 2 leaked pages = 8 KiB per seal operation.]
[FIX: Document the expected per-call accumulation explicitly (e.g., "up to 2 × 4 KiB per `seal_arena` call") or, for the future cleanup pass, consider the POKEDATA-staged munmap approach referenced in the comment. No code change required for v1; the current comment is sufficient to track this.]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/arena.rs:435-445]
[DEFECT: `seal_arena_with_mirror` seals the primary and mirror in two separate `remote_remap_private` calls, each with their own ptrace attach/detach cycle. Between the first detach and the second attach, init is running. A process that reads the primary arena during this window sees a COW-isolated value (the sealed value), while a process that reads the appcompat mirror sees the live/unsealed value. This creates a brief observable inconsistency for any reader that consults both arenas.]
[EVIDENCE:
```rust
pub fn seal_arena_with_mirror(...) -> Result<()> {
    seal_arena(pid, primary)?;   // detach after this
    if let Some(m) = mirror {    // window: init is unseized here
        seal_arena(pid, m)?;
    }
```
`system_properties.cpp:278-296` shows `Update` writes both `pa` and `override_pa` in a single function call, so readers observing the intermediate state see an inconsistency for the window between the two seals.]
[FIX: For v1 the window is acceptable (seals are rare events and the inconsistency window is sub-millisecond). Document this limitation in a `// NOTE:` comment on `seal_arena_with_mirror`. A future improvement would batch both seals under a single ptrace session, but that requires refactoring `remote_remap_private` to accept multiple VMAs.]

---

[MINOR]
[LOCATION: crates/resetprop/tests/tier_a_child_smoke.rs:130]
[DEFECT: `static CHILD_PATH: OnceLock<PathBuf>` can only be set once per process lifetime. If the test binary runs the `seal_arena_blocks_child_writes_from_reaching_file` function more than once in the same process (e.g., via a test harness that repeats individual tests), the second invocation hits `expect("CHILD_PATH must be empty on test entry")` and panics with a misleading message rather than a clean test failure.]
[EVIDENCE:
```rust
static CHILD_PATH: OnceLock<PathBuf> = OnceLock::new();
// ...
CHILD_PATH
    .set(path.clone())
    .expect("CHILD_PATH must be empty on test entry");
```
OnceLock provides no reset mechanism. With standard `cargo test --ignored --test-threads=1` this is safe (one run per process), but the panic message is confusing for anyone who re-runs tests interactively.]
[FIX: The comment on the static already explains the rationale. Add a note: "Test can only run once per process; re-invocation will panic at CHILD_PATH::set. Use a fresh cargo test invocation." This is documentation-only; no code change needed for v1.]

---

[MINOR]
[LOCATION: crates/resetprop/src/seal/arena.rs:55]
[DEFECT: `#[allow(dead_code)]` on `find_arena_mapping_in` is a temporary suppression whose stated rationale ("first direct caller lives in the integration smoke test") is only partially correct. The function is also transitively called by `find_arena_mapping`, which is `pub(crate)` and called by the public `seal_arena` / `unseal_arena`. The `#[allow(dead_code)]` is technically unnecessary once `seal_arena` is in scope, and it masks future dead-code warnings if the call site changes.]
[EVIDENCE:
```rust
#[allow(dead_code)] // first direct caller lives in the integration smoke test (T5)
fn find_arena_mapping_in(entries: &[MapEntry], arena_path: &Path) -> Result<MapEntry> {
```
`find_arena_mapping` at `arena.rs:72` calls `find_arena_mapping_in` unconditionally, so the function is live.]
[FIX: Remove `#[allow(dead_code)]`. The function is called by `find_arena_mapping` and will not generate a dead_code warning once the compiler traces the full call graph.]

---

## Positive Observations

- **REGISTRY §1 compliance is thorough.** The `SERIAL_FILE` constant is checked at both `seal_arena` and `unseal_arena` entry points, before any ptrace work begins. The guard uses the canonical `arena_filename()` helper shared by both methods, eliminating the risk of one path missing the check.

- **Flag encoding correctness.** All 8 constants (`NR_OPENAT`, `NR_MMAP`, `NR_CLOSE`, `O_RDONLY_NOFOLLOW`, `O_RDWR_NOFOLLOW`, `MAP_PRIVATE_FIXED`, `MAP_SHARED_FIXED`, `MAP_PRIVATE_ANON`) verified against AOSP kernel headers and match exactly. The accompanying unit test `constants_match_registry_canonical_values` (arena.rs:567-586) provides a compile-time trip-wire for any future constant drift.

- **`RemoteAttach` RAII guard design is correct.** The `detached` flag prevents double-detach, `Drop` logs and swallows the ptrace error on unwind (correct — panicking in Drop on a panicking thread causes abort), and the guard is dropped via `guard.detach()?` at the success path, ensuring the tracee is never left seized on any code path.

- **Bootstrap svc+brk construction is consistent.** The arena.rs bootstrap uses bit-shift packing; the ptrace.rs `remote_syscall` uses byte-array copying. Both produce the identical 8-byte little-endian blob `[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]`, verified numerically. The two independent encodings cross-validate each other.

- **I-cache coherence for bootstrap POKEDATA.** The initial `svc+brk` staging uses `PTRACE_POKEDATA` into a libc.text NOP slide. The kernel's `ptrace_access_vm` path calls `flush_icache_range` on arm64, so the I-side cache is coherent without any explicit `membarrier`. Subsequent `remote_syscall` calls run from the RWX bootstrap_page; the write-execute pattern on that page is also coherent because each call writes `svc+brk` (what the I-cache also contained from the prior call), so stale I-cache entries are never harmful.

- **`find_arena_mapping_in` separation of concerns.** The pure-function inner variant (`find_arena_mapping_in`) taking `&[MapEntry]` enables complete unit test coverage without any process-fork setup, correctly separating the parsing concern from the test oracle.

- **`derive_mirror_path` follows the REGISTRY-locked convention precisely.** `parent.join("appcompat_override").join(filename)` maps to the AOSP path `/dev/__properties__/appcompat_override/<ctx-filename>`, matching `system_properties.cpp:278-296`.

- **`tempfile` is correctly placed in `[dev-dependencies]`** (`Cargo.toml` lists `tempfile = "3"` in dev-deps). The production binary does not gain the tempfile dependency.

- **`seal_record_roundtrip` test is a genuine contract test**, not just a smoke test: it verifies insert, count, retain-by-name removal, and cleanup, proving the `OnceLock<Mutex<Vec<SealRecord>>>` pattern works correctly for the registry use case.

---

## Summary by Severity

| Severity | Count | Blocking? |
|----------|-------|-----------|
| CRITICAL | 0     | —         |
| MAJOR    | 2     | Yes       |
| MINOR    | 4     | No        |

**MAJOR-1** (`arena.rs:390`): `remote close ?` — false `Err` return after successful seal. The seal IS applied but the caller's registry and error handling treat it as failed.

**MAJOR-2** (`arena.rs:238`): Overly broad libc.so detection predicate — `contains("libc")` matches `libc++.so`, risking use of the wrong r-xp mapping as the NOP-slide base.

---

VERDICT: NEEDS_FIX (2 MAJOR findings)

---

## critic report

**MODE: ADVERSARIAL** — escalated after the first CRITICAL finding. Two CRITICALs were surfaced during a close re-read of `remote_remap_private`; once a load-bearing decision fails, the entire scratch-page architecture needs reconsideration, so I widened the hunt across every downstream use of `scratch_pc=bootstrap_page`.

**VERDICT: NEEDS_FIX**

---

### Pre-commitment predictions

Before reading the diff, I predicted the top-5 failure classes for a first-shot ptrace-based remote remap on Android init:

1. Scratch-memory / pathname collision (svc-stager clobbers the arena-path buffer because both live at the same address).
2. SELinux `execmem` denial on `mmap(... PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, ...)` under init's domain.
3. Concurrent-thread race in init (ptrace SEIZE only stops one TID; other threads keep executing while scratch bytes are installed in shared libc.text).
4. `wait_stop(pid, 0)` cross-triggered by an unrelated syscall-stop / signal on init (pid 1 is multi-threaded, receives signals constantly).
5. Integration test permanently masked: `#[cfg(target_arch = "aarch64")]` + `#[ignore]` + CI on x86_64 means the only test that can catch the above never runs pre-merge.

Actuals found: #1 **confirmed CRITICAL** (two variants), #2 **confirmed MAJOR**, #3 **confirmed MAJOR**, #4 **confirmed MAJOR**, #5 **confirmed MAJOR** — this is exactly the pattern that motivates the pre-commitment step. Every predicted class reached a finding.

---

### [SEVERITY: CRITICAL]
**DECISION CHALLENGED**: Using `bootstrap_page` as both the pathname buffer AND the `scratch_pc` argument to `remote_syscall` — `arena.rs:336` writes the NUL-terminated arena path to `bootstrap_page`, then `arena.rs:343-350, 361-375, 390-392` call `remote_syscall(pid, scratch_pc=bootstrap_page, ...)` three times.

**WHY IT'S WEAK**: `ptrace::remote_syscall` at `ptrace.rs:509-516` reads 8 bytes at `scratch_pc`, then writes `svc #0 ; brk #0` (`[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]`) into those same 8 bytes before resuming the tracee. This means the first 8 bytes of the pathname buffer are **clobbered with the svc+brk blob at the moment openat/mmap/close execute**. When openat reads `x1 = bootstrap_page`, the kernel sees a pathname starting `\x01\x00…` — NUL-terminated after 1 byte — so it always returns `-ENOENT` on a path named `"\x01"`. Every remote openat in this flow will fail. The bytes are only restored at `ptrace.rs:561` AFTER the syscall is complete, too late to matter. The failure will surface on the smoke test as `Error::HookInstallFailed("openat failed: errno=2")` (ENOENT), 100% reproducible on every real run — but **nothing in CI catches this** because the whole test file is `#![cfg(target_arch = "aarch64")]` and `#[ignore]`d, and the unit tests in `arena.rs::tests` only exercise `find_arena_mapping_in` / `find_nop_slide` / `RemapFlags` — none of them exercise `remote_remap_private`. The REGISTRY row "`75 lib tests pass`" is noise here; not one of them drives the bug.

This also silently poisons the mmap and close calls: `mmap_ret != mapping.start` will never be true because `mmap` never gets a valid fd (fd is the ENOENT return value, `-2`, then `(-2) as u64 = 0xffff...fffe`, and `mmap(..., fd=0xff...fe, 0)` returns `-EBADF`). The error-path "best-effort close" at `arena.rs:380` would then `close(0xff...fe)` — a write into the tracee's syscall no-op territory. Every layer on top of this one is built on sand.

**BETTER ALTERNATIVE**: Split the bootstrap page into a code region and a data region. Concretely, use two separate addresses:
  - `scratch_pc = bootstrap_page` (first 16 bytes, aligned, reserved for svc+brk clobbering).
  - `path_addr = bootstrap_page + 0x40` (64-byte offset, well clear of the clobber window) — write the NUL-terminated path there and pass `path_addr` as `x1` to openat.

Exact patch shape:
```rust
const PATH_OFFSET: u64 = 64;           // any aligned value >= 8
unsafe { write_remote(pid, bootstrap_page + PATH_OFFSET, &path_nul)? };
let fd_ret = unsafe {
    remote_syscall(pid, bootstrap_page, NR_OPENAT,
        [AT_FDCWD, bootstrap_page + PATH_OFFSET, flags.open_flags(), 0, 0, 0])?
};
```
Add a unit test that drives `remote_remap_private` in a forked child (not gated to aarch64 — use a host-resident libc, syscalls are cross-arch via `qemu-user` on CI if needed, OR add a host-architecture conditional for the syscall numbers). At minimum, add an aarch64-gated integration test that asserts `openat` returned a valid fd before the mmap step (intermediate-stage assertion), which would have caught this in a single run.

**WHEN IT MATTERS**: On every real-world invocation. The first time an operator runs `resetprop -sla telephony.something value` on a device, the seal fails with a generic `"hook install failed: openat failed: errno=2"` — no root cause, no indication that the code architecture itself is wrong. There is no scenario under which the current code path returns `Ok(())` from `remote_remap_private`.

---

### [SEVERITY: CRITICAL]
**DECISION CHALLENGED**: The integration smoke test is gated `#![cfg(target_arch = "aarch64")]` AND `#[ignore]` AND requires `ptrace_scope <= 1`. Combined with a host CI running x86_64 (confirmed: `uname -m` == `x86_64` in the working tree), there is no automated gate that would catch the CRITICAL above.

**WHY IT'S WEAK**: The P02 checklist claims T5 "Verifies" via the smoke test. In practice the smoke test compiles to an empty binary on every developer's host and on every CI pass (comment at `tier_a_child_smoke.rs:30-33` explicitly acknowledges this: "the file compiles to an empty test binary that reports `0 passed; 0 failed; 0 ignored`"). So the **only** test that actually drives `remote_remap_private` end-to-end never runs during the normal development loop. The decision to gate the entire test file on `target_arch = "aarch64"` is load-bearing and silently disables the only correctness probe for the Tier A primitive. The P01 pattern (`ptrace_core_smoke.rs`) made the same choice, but P01 had an on-device run logged in the session notes (3 consecutive passes on aarch64 Android 15). P02's session log says nothing about an on-device run of `tier_a_child_smoke` — the Gate 2 checklist is about to be stamped based on unit-test signal only.

**BETTER ALTERNATIVE**: Either (a) run the smoke test on an aarch64 runner before Gate 2 closes and paste the result into the session log (same rigor as P01), OR (b) restructure the test so its non-ptrace portions (fork, tempfile setup, sentinel verification) can run on any arch with a mock `seal_arena` helper, and only the ptrace injection path is aarch64-gated. Option (b) lets CI catch the offset-collision CRITICAL above without needing aarch64 hardware in the loop. Minimum-effort mitigation: add a `host-only` sibling test at `crates/resetprop/tests/tier_a_offsets.rs` that exercises `remote_remap_private` against a local child using a stubbed scratch_pc — the bug above manifests even without a real target arena, since openat fails at `-ENOENT` long before mmap runs.

**WHEN IT MATTERS**: Every time this phase closes without an on-device run. The REGISTRY's "Gate 2 PASS from BOTH agents" is not sufficient evidence that the Tier A primitive works; it only proves the code compiles and the unit-test subset passes. An operator-blocking defect can sit in `main` for months with green CI.

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: Bootstrap page is allocated as `MAP_PRIVATE|MAP_ANON` with `PROT_READ|PROT_WRITE|PROT_EXEC` (`arena.rs:278-279` — `PROT_RWX = 0x7`, `MAP_PRIVATE_ANON = 0x22`).

**WHY IT'S WEAK**: On Android devices with SELinux in enforcing mode (default on all production Android 10+ devices — the `REGISTRY §1 target platforms: Android 10-15`), init's SELinux domain (`u:r:init:s0`) typically denies `execmem` on anonymous PROT_EXEC mappings. The kernel's SELinux hook `selinux_file_mprotect` and `selinux_mmap_file` check `EXECMEM` permission when the mapping is anonymous and PROT_EXEC is requested. There is no `execmem` grant on init in AOSP's stock policy (see `system/sepolicy/private/init.te` — the `execmem` permission is explicitly not granted to init). The `mmap` syscall will return `-EACCES` or `-EPERM`. The P02 code would surface this as `bootstrap mmap failed: errno=13` — cryptic, not actionable, and happens BEFORE the path-collision CRITICAL above gets a chance to trigger.

The REGISTRY §1 says the hook page (P04, Tier B) is "4 KB RWX anonymous mmap injected into init" — that decision has the same latent flaw but at least is scoped to P04. P02 inherited the same recipe without re-auditing for SELinux. The P02 spec §Approach does not mention SELinux at all.

**BETTER ALTERNATIVE**: Do not use PROT_EXEC on the bootstrap page — P02 never executes from it, only stores a pathname. Change `PROT_RWX = 0x7` at the call site (`arena.rs:278`) to `PROT_RW = 0x3`. The bootstrap page is only used as (a) a writable buffer for the arena pathname, and (b) incidentally as `scratch_pc` for the openat/mmap/close syscalls — but fixing the first CRITICAL above means `scratch_pc` moves back into libc.text (where R+X already exists) and the bootstrap page becomes pure data. Once `scratch_pc = libc_text NOP slide` (as it was during the initial `mmap` bootstrap at `arena.rs:269`), the bootstrap page only needs PROT_RW, which is permitted under every Android SELinux policy.

**WHEN IT MATTERS**: On any Android device with SELinux enforcing — that is, effectively every production device matching the REGISTRY's target platforms. The one-line fix turns an entire class of devices from "never works" to "works".

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: Continuing to stage `svc+brk` in init's live libc.text NOP slide for **every** Tier A syscall after the bootstrap page is acquired — `arena.rs:343, 361, 390` all call `remote_syscall(pid, bootstrap_page, ...)`, which ends up writing svc+brk into `bootstrap_page` (the CRITICAL above), but the PRIOR bootstrap mmap at `arena.rs:269` correctly used the libc.text slide. This architectural split is confusing and fragile — it also means the libc.text NOP slide hunt and scan are done purely for the one-shot bootstrap call and never re-used.

**WHY IT'S WEAK**: The intent appears to be "use libc.text only once, then switch to bootstrap_page"; but the switch is what introduces the CRITICAL scratch/path collision. After fixing the CRITICAL, a simpler design is:
  - Allocate `bootstrap_page` as PROT_RW (pure data, see MAJOR above).
  - Keep `scratch_pc = libc.text NOP slide` for all three post-bootstrap syscalls (openat, mmap, close).
  - Pass `bootstrap_page + PATH_OFFSET` as the pathname arg.

This collapses the design from "two scratch regions, each with its own quirks" to "one code-scratch (libc.text, R+X, never written except via POKE/process_vm_writev which we've already proven works) + one data-scratch (bootstrap page, R+W)". The NOP slide scan done during bootstrap is now amortized across all Tier A syscalls — zero additional cost.

Additional fragility: `find_nop_slide` requires 4 consecutive `0xd503201f` nops 8-byte aligned. Android bionic's libc is stripped and LTO'd aggressively; 16-byte nop runs are not guaranteed to exist. The code treats this as `Error::HookInstallFailed("no NOP slide found in libc.text")` — which is the right error type, but the P02 spec / Approach section never justifies the assumption that a NOP slide always exists in Android's bionic. On stripped bionic builds (Android 14+) with `--icf=all` and `-fomit-frame-pointer`, inter-function padding is frequently `brk`/`udf` trap instructions, not nops. If the 64 KiB scan prefix doesn't find a slide, the seal fails with no fallback.

**BETTER ALTERNATIVE**: Two concrete improvements:
  1. Simplify the scratch topology per above (libc.text for code, bootstrap_page for data).
  2. Add a fallback: if NOP slide is not found in the first 64 KiB, expand the scan to the full libc text mapping (`libc_text.end - libc_text.start` up to, say, 2 MiB — a typical bionic libc is ~1 MiB). If still no slide, fall back to allocating the scratch page via PTRACE_POKEDATA (word by word) into a temporarily-writable region — or more simply, use the padding region in the vdso (`[vdso]` often has zero-pages at the end) per `linux-arm64-abi.md §8`.

**WHEN IT MATTERS**: Under stripped-libc builds and aggressive LTO, which are common on production Android images. The fallback is cheap insurance; right now a single broken assumption in `find_nop_slide` bricks the entire Tier A path.

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: `wait_stop(pid, 0)` at `arena.rs:304` after the bootstrap `PTRACE_CONT` (and implicitly inside every `remote_syscall` at `ptrace.rs:550`) assumes the next ptrace-stop on init is the `brk #0` we just staged. But init (PID 1) is a multi-threaded process that receives signals constantly (SIGCHLD from zygote, SIGTERM from shutdown, plus kernel-internal activity).

**WHY IT'S WEAK**: Ptrace SEIZE/INTERRUPT is per-TID. The P02 code seizes `pid=1` (the init main thread). If the main thread happens to be in a syscall when we INTERRUPT, the next wait_stop will consume the syscall-stop (with `PTRACE_O_TRACESYSGOOD` enabled, that's `stopsig == SIGTRAP | 0x80`, event == 0). The `wait_stop(pid, 0)` at `ptrace.rs:226-242` checks `sig != libc::SIGTRAP` — but `SIGTRAP | 0x80` is `0x85`, which passes the `sig == SIGTRAP` check (`libc::WSTOPSIG(status)` returns the low 7 bits, so 0x85 → SIGTRAP=5). Wait — let me re-check. `WSTOPSIG` unpacks `(status >> 8) & 0xff`. For TRACESYSGOOD, the stopsig is `SIGTRAP | 0x80 = 0x85`. `0x85 != SIGTRAP(5)` — so the check at `ptrace.rs:238` `sig != libc::SIGTRAP` would fire, returning `PtraceUnexpectedStatus`. OK, so the failure mode is "wait_stop rejects the syscall-stop" — the code is actually defensive here, good. BUT: this means that on any init where another syscall-stop arrives during injection (likely on a busy device), the seal fails with `PtraceUnexpectedStatus(0x85...)` and no retry logic. Error message is cryptic; no pathway to recover.

The second failure mode is worse: the INTERRUPT arrives while init's thread is already stopped at a group-stop (e.g., init's SIGCHLD handler). Then the seize stop AND the group-stop are both pending. Consuming them in the wrong order leads to `wait_stop` consuming a group-stop with `event == 128` when the caller wanted `event == 0`. Same error class, same no-retry.

**BETTER ALTERNATIVE**: Add a retry loop in `wait_stop` that re-resumes spurious stops (syscall-stops, group-stops with `event == 128` that arrive AFTER the initial SEIZE group-stop was already consumed) by calling PTRACE_CONT with the pending signal and looping until the expected event arrives. Bound the loop (e.g., 64 retries) and surface `PtraceUnexpectedStatus` only if we exhaust the budget. This matches how Frida and other production ptrace injectors handle busy targets. Alternatively, PTRACE_SYSEMU the brk trap to force deterministic trap delivery.

**WHEN IT MATTERS**: On busy multi-threaded tracees — i.e., init on every boot. The failure is probabilistic, which is worse than deterministic: some runs work, some fail with the same invocation, and the operator can't reproduce.

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: "Bootstrap page intentionally leaked" — `arena.rs:394-401` documents the 4 KiB leak per seal call as acceptable. The REGISTRY does not flag this.

**WHY IT'S WEAK**: The session-log comment says "seals are rare events" but provides no bound. An operator invoking `resetprop -sla` N times leaks 4N KiB in init. On a device that gets `resetprop` invoked via a script on every boot (the REGISTRY §1 says "user re-runs on every boot"), over 1000 boots you leak 4 MiB. That's small absolute, but:
  1. Each leaked page is RWX anonymous. An attacker with a partial memory read primitive in init now has a pool of executable scratch regions to work from. This undermines the security posture of the seal itself (the REGISTRY says "rooted self-inspection CAN detect seal" is acceptable, but RWX anonymous pages are a signal far stronger than a VMA flag flip).
  2. The "fix in future release" pointer is vague. There is no task, no branch, no spec reference — it's a note buried in arena.rs. This is exactly the "future-pain" pattern the devil's advocate role is here to block.

**BETTER ALTERNATIVE**: After the final `close(fd)` remote syscall, add a fourth remote syscall: `munmap(bootstrap_page, 4096)`. The munmap can run from the same libc.text scratch_pc (after MAJOR #4's fix), so no circular-dependency issue. Cost: one extra `remote_syscall` invocation per seal call (~microseconds). Benefit: zero leak, zero RWX pages, zero future-debt promise. If the design genuinely needs the scratch page to survive for some reason not stated, document the reason in the REGISTRY under "locked decisions" so it survives code review; don't hide it in a module comment.

**WHEN IT MATTERS**: Always — this is a footprint regression that has no justification. Fix it before release.

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: `PropSystem::seal_arena` at `lib.rs:544-563` hard-codes PID 1 at the `seal::arena::seal_arena_with_mirror(1, ...)` call site (line 554). Similarly for `unseal_arena` at `lib.rs:576`. No path to parameterize, override, or test against a non-init tracee.

**WHY IT'S WEAK**: Two concrete problems:
  1. **Testability**: The `tier_a_child_smoke` integration test cannot drive `PropSystem::seal_arena` because it needs to target a sacrificial child, not PID 1. The test instead calls the low-level `seal::arena::seal_arena(guard.pid(), &path)` directly, bypassing all of `PropSystem`. That means the entire path-resolution, appcompat-mirror-detection, `properties_serial`-guard, and registry-insert logic in `PropSystem::seal_arena` is **untested end-to-end**. The unit tests at `seal/mod.rs::tests` cover the registry roundtrip and the `properties_serial` path-derivation, but none cover the full `PropSystem::seal_arena` flow. This is a gap.
  2. **Future-pain**: Tier B (P04) will also target init (PID 1). Hard-coding `1` in two places now means a future refactor to share "target pid" resolution across tiers will touch every call site. If Android ever ships a multi-init arrangement (or if we ever want to seal a non-init property service — e.g., a vendor-specific prop daemon), this assumption breaks.

**BETTER ALTERNATIVE**: Factor out an `init_pid() -> Pid` constant/function in `seal::mod.rs` (returning `1` for now) and route both `PropSystem::seal_arena` and `PropSystem::unseal_arena` through it. In tests, allow injection via a newtype wrapper or a trait so the smoke test can cover the full `PropSystem::seal_arena` codepath with a sacrificial child. Minimum viable change: extract `pub(crate) const INIT_PID: Pid = 1;` and a thin helper `pub fn seal_arena_on(&self, pid: Pid, name: &str, value: &str) -> Result<SealRecord>` that the public `seal_arena` delegates to.

**WHEN IT MATTERS**: Every time we want to test `PropSystem::seal_arena` without privileging the test harness as a production tracer of PID 1 (which is almost never — PID 1 ptrace requires CAP_SYS_PTRACE OR yama scope 0, both root-level prerequisites). Right now, the end-to-end PropSystem path is effectively dark.

---

### [SEVERITY: MAJOR]
**DECISION CHALLENGED**: `seal_arena_with_mirror` at `arena.rs:435-445` calls `seal_arena(pid, primary)?` and `seal_arena(pid, mirror)?` sequentially, **each of which runs a full attach → bootstrap mmap → openat → mmap → close → detach cycle**. That is two independent ptrace attach/detach rounds per `PropSystem::seal_arena` call when an appcompat mirror is present.

**WHY IT'S WEAK**: Each attach/detach is expensive (PTRACE_SEIZE, PTRACE_INTERRUPT, waitpid, SETREGSET, CONT, waitpid, SETREGSET, DETACH — ~8 syscalls just for attach/detach). More importantly, each cycle leaks a fresh 4 KiB RWX bootstrap page per MAJOR #6 above. Sealing a single property name with a mirror thus leaks 8 KiB per `PropSystem::seal_arena` invocation, doubling the footprint regression.

Worse: between the two attach/detach rounds, init resumes execution. During that resume window, init can (and does) process property updates. If a set from another process arrives between the primary-sealed state and the mirror-sealed state, the mirror captures the pre-seal value while the primary has already been sealed. The atomicity guarantee the seal is trying to provide is violated.

**BETTER ALTERNATIVE**: Add an internal `remote_remap_private_multi(pid, mappings: &[(&MapEntry, &Path)], flags: RemapFlags)` that does ONE attach, ONE bootstrap mmap, loops through N syscall triples (openat/mmap/close per path), and ONE detach. Keep `seal_arena`/`unseal_arena` as thin shims over the multi-path variant. This:
  - Cuts the leak from 4 KiB × N paths to 4 KiB × 1 per call (and to 0 after MAJOR #6 is fixed).
  - Amortizes attach/detach cost.
  - Closes the atomicity gap — init is stopped for the full duration of all mmap flips.

**WHEN IT MATTERS**: Every time an appcompat mirror is present (Android 14+, which is in scope per REGISTRY §1). The atomicity issue is theoretical but real under load (telephony prop churn during boot or during SIM swaps).

---

### [SEVERITY: MINOR]
**DECISION CHALLENGED**: `arena.rs:56` — `find_arena_mapping_in` is marked `#[allow(dead_code)]` with a comment that "the first direct caller lives in the integration smoke test (T5)". The smoke test does not actually call `find_arena_mapping_in` — it calls `seal::arena::seal_arena(...)`, which calls `find_arena_mapping` (the `_in`-less variant), which calls `find_arena_mapping_in`. So the dead-code allow is only needed because the unit tests in the same file call it directly. The comment is misleading.

**BETTER ALTERNATIVE**: Replace the stale comment with "exposed to the in-file test module only; production callers go through `find_arena_mapping`". Or: make `find_arena_mapping_in` `pub(super)` and drop the `allow(dead_code)` — the compiler will stop warning because the tests count as a live caller under `cfg(test)`. Minor, but the comment-reality mismatch is a smell.

---

### [SEVERITY: MINOR]
**DECISION CHALLENGED**: `arena.rs:68` — `Err(Error::ArenaNotMapped(arena_path.to_path_buf()))` is returned both when no matching entry exists at all AND when only a read-only (`r-x`) entry exists. The comment at `arena.rs:44-48` acknowledges the conflation and justifies it. But the two failure modes are operationally distinct: "target PID is wrong" (no entry) vs "the file is mapped read-only in the target" (R/W view not present — usually means someone else already did the remap, or the target has `/dev/__properties__` mounted noexec in a way that only leaves RO mappings).

**BETTER ALTERNATIVE**: Add a distinct `Error::ArenaReadOnly(PathBuf)` variant (bumps the 9-variant error surface to 10, matches the P01 precedent for splitting). Or at minimum surface the distinction via a `Display` suffix: `"arena not mapped in target process (only read-only view found): ..."`. The CLI will want this when producing actionable error messages.

---

### [SEVERITY: MINOR]
**DECISION CHALLENGED**: `lib.rs:699-714` — `insert_or_refresh_seal` silently upserts on duplicate `(name, tier)` rather than returning an `ArenaAlreadySealed` error. The REGISTRY §1 lists `ArenaAlreadySealed(PathBuf)` in the error surface but the code never produces it.

**BETTER ALTERNATIVE**: Either wire the error variant to the duplicate-seal detection path, or remove the unused variant from the error enum. An unused error variant is a dead-code smell; retaining it implies a contract that isn't enforced. My recommendation is to make `seal_arena` return `Err(Error::ArenaAlreadySealed(primary_path))` when a record with the same `(name, SealTier::Arena)` already exists — this is the behavior the CLI will want (so the operator sees that they're double-sealing). Refresh semantics should be reserved for an explicit `--force` or `reseal` API.

---

### What's Missing

- **On-device verification evidence** for P02. P01 logged three consecutive aarch64 passes in the session log; P02's session log claims "75 lib tests pass" but nothing about an on-device run of `tier_a_child_smoke`. The REGISTRY P02 row is about to move to COMPLETE based on off-device signal only — the CRITICAL above is exactly what an on-device run would have caught in 60 seconds.
- **SELinux audit log capture path**. Even if a production device denies the PROT_EXEC bootstrap (MAJOR #3), the code surfaces the failure as `HookInstallFailed(...)` with no cross-reference to `dmesg` or `logcat -b all | grep audit`. The operator-visible error should name `execmem` as a candidate cause.
- **Documentation of the failure envelope**. Under what yama scope, SELinux state, and threading conditions does this work? The REGISTRY mentions root + CAP_SYS_PTRACE but never the SELinux prerequisites. An operator running on a debuggable build (permissive SELinux) will see success; the same operator on a production build sees cryptic failures.
- **No fuzz / property-test over the maps parser interaction**. `find_arena_mapping` walks `parse_maps` output; if a malicious tracee (pid != 1) includes a path containing embedded newlines or spaces, the maps parser may attribute the wrong VMA to the target path. Not exploitable in the REGISTRY-locked scope (we only target init-owned files under `/dev/__properties__/`) but the design never explicitly asserts this.
- **No metric / counter for "bootstrap mmap leaked"**. See MAJOR #6. Silent leaks don't show up in any observability surface.
- **No rollback plan if step 3 (openat) succeeds but step 4 (mmap) fails**. The code attempts a best-effort close at `arena.rs:379-381`, but doesn't document what happens if that close itself fails (the `let _ = unsafe { ... }` discards the result). A failed close on a successfully-opened fd leaks a file descriptor in init forever. `/proc/1/fd` inspection would reveal it, but nothing flags it.

---

### Multi-perspective Notes

- **Executor** (the developer following the P02 spec): The spec says "mirror the local `privatize` flag recipe" (§Approach.1) and points to `area.rs:230-260`. The executor shipped a much more complex bootstrap-page-based recipe than `area.rs::privatize` uses (because `privatize` is local-process, no ptrace needed). That's fine — the complexity is inherent to remote remap. But the spec never documents the bootstrap-page flow at all; the session-log mentions "T3 shipped `RemoteAttach`... bootstrap flow" but no architectural justification for the two-scratch-region approach. An executor re-reading this in P05 (who has to CLI-ify the seal) has no spec to anchor to; they'll reverse-engineer from the code.
- **Stakeholder** (the user who locked "Tier A arena-level seal" as a deliverable): The deliverable is advertised as "proven correct by a forked-child integration smoke test." In reality the smoke test has never run on this host (it's aarch64-gated and CI is x86_64). The stakeholder is getting "unit tests pass and the happy path looks structured" — not "the seal works." The gap between advertised and actual correctness coverage is the single biggest risk in this phase.
- **Skeptic** (me): What is the strongest argument AGAINST the scratch-page-is-also-pathname-buffer design? The strongest argument is exactly CRITICAL #1 — it's broken. The alternative was likely considered and rejected because it "just seemed simpler to keep everything in one page"; the rejection rationale was never documented, and in fact was wrong. This is a textbook case of the devil's-advocate role: if you can construct a strong counter-argument that the plan doesn't address, the plan is fragile.

---

### Verdict Justification

Review was escalated to ADVERSARIAL mode after the first CRITICAL finding (the scratch/path collision). Once a load-bearing architectural decision fails, the remainder of the codebase built on top of it inherits the failure — which is why I widened scope from "verify the spec is implemented" to "verify the implementation is correct against the actual external contracts." The second CRITICAL (test gating that masks the first) was surfaced during the widened scan.

Realist Check applied to every CRITICAL and MAJOR:
- CRITICAL #1 (scratch/path collision) — realistic worst case is 100% reproducible seal failure on every real invocation. No mitigating factor: unit tests don't exercise the path, smoke test is arch-gated, and the error surfaces as a generic `HookInstallFailed(errno=2)` with no trace of the root cause. Severity stands.
- CRITICAL #2 (test gating masks CRITICAL #1) — realistic worst case: CRITICAL #1 reaches `main` and ships, blocked only by someone running the aarch64 on-device test manually before release. Mitigated by the REGISTRY's Gate 2 process IF it requires an on-device run, but the P01 gate closed based on on-device evidence and the P02 gate is about to close without. Severity stands.
- MAJOR #3 (PROT_EXEC SELinux) — realistic worst case: every Android 10-15 production device fails before CRITICAL #1 even gets a chance. One-line fix. Mitigated by the fact that CRITICAL #1 makes it moot (the whole flow fails either way today), but after CRITICAL #1 is fixed MAJOR #3 becomes the next blocker. Severity stands.
- MAJOR #4 (scratch topology) — not a downgrade candidate; it's the clean fix for CRITICAL #1. Severity stands.
- MAJOR #5 (wait_stop on busy init) — realistic worst case: flaky seals on production devices. Mitigated by "manual retry" (operator re-runs the command), downgrade-eligible? No — flakiness on a security primitive is a correctness defect. Severity stands.
- MAJOR #6 (RWX page leak) — realistic worst case: bounded but real footprint creep AND a discovery channel for attackers. Not downgradable. Severity stands.
- MAJOR #7 (hard-coded PID 1) — primarily a testability / future-pain issue, not a correctness issue today. **Realist-check downgrade candidate to MINOR** — the impact is "we can't drive PropSystem::seal_arena end-to-end in tests" and "future refactors will touch more call sites"; neither is catastrophic. But the cost of the fix is two lines of code. Keeping at MAJOR because of compounding with CRITICAL #2: if PID 1 were parameterizable, the smoke test could drive the full PropSystem path and catch CRITICAL #1 even without aarch64 hardware. Severity stands due to compounding.
- MAJOR #8 (non-atomic mirror seal) — realistic worst case: race window where mirror observes different state than primary. Mitigated by "seal is rare" per REGISTRY but the race window is bounded only by scheduler + ptrace detach cost (milliseconds). Severity stands.

Minimum bar to upgrade verdict to PASS:
1. Fix CRITICAL #1 (split scratch/path regions). Add a unit or property test that would catch a regression.
2. Fix CRITICAL #2 (either run the smoke test on aarch64 hardware with logged output, OR add a host-executable test that drives `remote_remap_private` against a sacrificial child).
3. Fix MAJOR #3 (drop PROT_EXEC from the bootstrap page — one line).
4. Address or explicitly-defer-with-REGISTRY-entry the rest.

Counts: 2 CRITICAL + 6 MAJOR + 3 MINOR. Fix count == 2 CRITICAL + 6 MAJOR = 8 blockers.

**VERDICT: NEEDS_FIX** (8 blockers)

---

### Open Questions (unscored)

- Does Android 15 bionic's libc actually ship with 4-NOP-word aligned runs in `.text`? The assumption in `find_nop_slide` is load-bearing for MAJOR #4 fallback planning. An empirical scan on a few AOSP images would answer this definitively; I did not have time to perform it during this audit.
- Is there a known production device where `u:r:init:s0` is granted `execmem` by vendor policy (making MAJOR #3 less universal)? I know stock AOSP denies it; vendor patches vary.
- Does `PTRACE_SEIZE(pid=1)` under CAP_SYS_PTRACE + yama scope 0 succeed consistently, or is there a signal-race between init-triggered `sigsuspend` and our INTERRUPT that the P01 tests didn't exercise? P01's smoke test ran against a sacrificial child, not PID 1 — the behavior against a real init is unverified in this repo. This intersects with MAJOR #5.
