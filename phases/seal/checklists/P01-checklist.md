# P01 — Foundation: ptrace core + maps parser — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [ ] None — P01 is the root phase (per P01 spec, Preconditions; REGISTRY §5).
- [ ] `crates/resetprop/src/error.rs` exists at current `main` HEAD.
- [ ] `crates/resetprop/src/lib.rs` exists with the module block at lines 21-35.
- [ ] `crates/resetprop/Cargo.toml` declares `libc = "0.2"` (line 14) and `tempfile = "3"` dev-dep (line 17) — no other deps introduced.

(Source: P01 spec, Preconditions; REGISTRY §5, §6.)

## Branch

- [ ] Branch `feat/P01-foundation` created from latest `main` (per REGISTRY §4, row "P01").
- [ ] All commits follow `feat(seal):`, `test(seal):`, or `refactor(seal):` prefix per REGISTRY §2.
- [ ] No commits merged to `main` without Gate 2 PASS.

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: Module skeleton + 7 Error variants

- [x] Implementation: `crates/resetprop/src/seal/mod.rs` exists, declares `pub mod maps; pub mod ptrace;`, re-exports `MapEntry`, `parse_maps`, `UserPtRegs`, `remote_syscall`, `ptrace_seize`, `ptrace_interrupt`, `ptrace_detach`, `wait_stop`, `getregset`, `setregset`, and defines `pub type Pid = libc::pid_t;`. **Partial:** submodule declarations (`mod.rs:11-12`) and `Pid` alias (`mod.rs:15`) landed; re-exports intentionally deferred to T2/T3 so each intermediate commit compiles against empty placeholder submodules (documented in `mod.rs:3-8`). Re-exports complete incrementally at T2 (for `maps::*`) and T3/T4 (for `ptrace::*`).
- [x] Implementation: `crates/resetprop/src/seal/mod.rs` declares the two public types with the locked field layout — `pub struct SealRecord { pub name: String, pub arena_path: PathBuf, pub tier: SealTier, pub sealed_at: SystemTime }` and `pub enum SealTier { Arena, Prop }` (per REGISTRY §1 rows "`SealRecord` fields" and "`SealTier` variants"). Evidence: `seal/mod.rs:20-35`.
- [x] Implementation: `crates/resetprop/src/error.rs` enum (lines 5-14 baseline) grown by 7 variants in order: `PtraceAttach(std::io::Error)`, `PtraceScope`, `ArenaAlreadySealed(PathBuf)`, `ArenaNotMapped(PathBuf)`, `ElfParse(String)`, `SymbolNotFound(String)`, `HookInstallFailed(String)`. Evidence: `error.rs:14-20`.
- [x] Implementation: `Display` impl extended with one arm per new variant; `Error::source` returns `Some(e)` for `PtraceAttach(e)`, `None` for the remaining six; `From<std::io::Error>` untouched. Evidence: `error.rs:37-49` (Display arms), `error.rs:56-61` (source), `error.rs:66-73` (From unchanged).
- [x] Implementation: `crates/resetprop/src/lib.rs` carries `mod seal;` immediately after line 32 (`mod wait;`). Evidence: `lib.rs:33`.
- [x] Test: `cargo check -p resetprop` exits 0. (3 dead_code warnings expected — `SealRecord`/`SealTier`/`Pid` are consumed by P02/P04 per REGISTRY §3 Domain Ownership; not suppressed with `#[allow]` per anti-paper-over policy.)
- [x] Test: `cargo test -p resetprop --lib error::` passes with 0 failures (no pre-existing test regressed). Raw: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out`.
- [x] Test: `grep -n "mod seal;" crates/resetprop/src/lib.rs` reports a match on line 33. Raw: `33:mod seal;`.

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [x] **Optimality** — Considered alternative approach? Is this the most elegant within constraints? Notes: Two alternatives evaluated. (A) Write the `pub use maps::*` / `pub use ptrace::*` re-exports in T1 with stub items in the placeholder submodule files so `cargo check` passes — rejected because stub item signatures would encode assumptions about T2/T3/T4 types (e.g. `fn parse_maps(pid: i32)` vs `pid_t`) and either force duplicate maintenance or mask drift when T2/T3 land. (B) Chosen — ship submodule declarations + public types now, defer re-exports to the task that introduces each item. This keeps every commit on `feat/P01-foundation` independently green (atomic discipline per REGISTRY §2 row 6) and makes re-export content authoritative to the task that owns the symbol. Documented at `seal/mod.rs:3-8` so auditors and downstream tasks see the intent.
- [x] **Completeness** — Deliverable fully met spec §Tasks T1? Notes: Yes. All five implementation bullets in P01-checklist.md §Task 1 map to concrete code locations (seal/mod.rs:11-14 submodules + Pid, 20-35 SealRecord/SealTier; error.rs:14-20 variants, 37-49 Display, 56-61 source; lib.rs:33 `mod seal;`). FR-01/FR-03/FR-04..FR-12 satisfied in this task. FR-02 partially satisfied (declarations done; re-exports deferred to T2/T3 by design). TC-01/TC-05/TC-08 all green. Anti-scope AS-01..AS-09 not violated — only the 5 declared files touched; Cargo.toml untouched; zero `unsafe` blocks introduced.
- [x] **Correctness** — Edge cases walked through (list them): (1) `From<std::io::Error>` impl deliberately left unchanged so `?` conversions keep classifying EACCES/EPERM → `PermissionDenied`, everything else → `Io`; `PtraceAttach` is constructed explicitly in T3 via `io::Error::last_os_error()`, never implicitly, avoiding ambiguity between generic IO and ptrace-specific errors. (2) `Error::source` wildcard `_ => None` covers the six non-wrapping variants (PtraceScope, ArenaAlreadySealed, ArenaNotMapped, ElfParse, SymbolNotFound, HookInstallFailed) without breaking exhaustiveness or requiring six explicit arms — minimal diff per simplicity policy. (3) `mod seal;` placed between `mod wait;` (private, line 32) and `pub mod inspect;` (public, line 34) — private visibility matches the wait/persist/bionic pattern because P02/P04 will re-export seal items via `pub use seal::{...}` in a later phase, not `pub mod seal;`. (4) `SealTier` derives `Copy` + `PartialEq` + `Eq` — legal for a two-variant fieldless enum; enables cheap match arms in future `--seals` listing output and in P02/P04 record construction. `SealRecord` does NOT derive `Copy` because `String`/`PathBuf` fields forbid it; `Clone` is sufficient for anticipated list-and-display use cases per REGISTRY §3 Domain Ownership row `lib.rs` (public API surface P02/P04). (5) Commit atomicity verified: each of `65b5a25`, `b0917f2`, `07d9238` compiles independently; no intermediate commit leaves the tree broken. (6) Placeholder files `seal/maps.rs` and `seal/ptrace.rs` are 1 line each (doc-comment only) — they do not satisfy FR-13..FR-29 (that's T2/T3/T4 scope) but their mere existence is what keeps `pub mod` declarations resolvable; intentional.

### Task 2: `/proc/<pid>/maps` parser

- [x] Implementation: `crates/resetprop/src/seal/maps.rs` defines `pub struct MapEntry { pub start: u64, pub end: u64, pub perms: [u8; 4], pub offset: u64, pub path: Option<PathBuf> }`. Evidence: `maps.rs:17-23`.
- [x] Implementation: `pub fn parse_maps(pid: libc::pid_t) -> Result<Vec<MapEntry>>` reads `/proc/<pid>/maps` via `std::fs::read_to_string` and decodes hex `start-end perms offset dev inode path` columns. Evidence: `maps.rs:32-42` (signature + `read_to_string`), `maps.rs:50-117` (`parse_line` helper doing the column decode).
- [x] Implementation: `pub fn find_by_path<'a>(entries: &'a [MapEntry], path: &Path) -> Option<&'a MapEntry>` performs exact-path match. Evidence: `maps.rs:45-47` using `e.path.as_deref() == Some(path)`.
- [x] Implementation: Three unit tests defined: `test_maps_parse_minimal_line`, `test_maps_parse_deleted_suffix`, `test_maps_find_by_path_matches`. Evidence: `maps.rs:123`, `maps.rs:134`, `maps.rs:141` — names verbatim from spec.
- [x] Test: `cargo test -p resetprop --lib seal::maps` reports `3 passed; 0 failed`. Raw: `test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 58 filtered out`.
- [x] Test: `cargo check -p resetprop` exits 0. (8 dead_code warnings — 3 carried from T1 plus 5 new from `MapEntry`/`parse_maps`/`find_by_path`/`parse_line`/`Pid` not yet consumed externally; not suppressed per anti-paper-over policy. Full-lib test sweep confirms zero regressions: `61 passed; 0 failed` vs T1 baseline 58.)

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [x] **Optimality** — Notes: Chosen shape is a flat `parse_line(&str, pid_t) -> Result<Option<MapEntry>>` helper called by `parse_maps` over `contents.lines()`. Alternatives considered: (A) inline the parser inside `parse_maps` — rejected because tests require unit access to line parsing without touching the filesystem; factoring the helper is mandatory for testability. (B) use `regex` crate for column extraction — rejected by REGISTRY §1 row 3 (forbidden crates) and unnecessary: `split_whitespace` handles the collapsed-column case correctly since real maps paths never contain whitespace (the kernel writes them via `seq_path`, escaping spaces). (C) use `splitn(6, char::is_whitespace)` — works but awkward for the "remainder joined back" path extraction; `split_whitespace().collect::<Vec<_>>()` on the tail is clearer. The shipped version is 158 lines including doc comments, 3 tests, and inline commentary explaining the kernel's `" (deleted)"` marker invariant (`fs/proc/task_mmu.c` show_map_vma). Non-doc code is well under 100 LOC. The `pub(super)` visibility on `parse_line` is minimum-scope: tests in the same file need it, nothing else should.
- [x] **Completeness** — Notes: FR-13 (MapEntry fields verbatim) at maps.rs:17-23. FR-14 (`parse_maps` signature + `read_to_string`) at maps.rs:32-35. FR-15 (hex start-end + 4-byte perms) at maps.rs:72-79. FR-16 (strip `" (deleted)"` suffix only) at maps.rs:99-100. FR-17 (`find_by_path` exact-match) at maps.rs:45-47. Re-export slice at `seal/mod.rs:38` (`pub use maps::{MapEntry, parse_maps};`) — `find_by_path` deliberately NOT re-exported because the P01 spec §Tasks T1 enumerates the re-export surface and omits it; consumers (P02/P03) use `seal::maps::find_by_path` qualified. TC-03 (3 passed) and TC-04 (no regression — 61 total) verified with raw `cargo test` output. Anti-scope AS-01..AS-09 intact: no edits to ptrace.rs/error.rs/lib.rs/Cargo.toml, no new dep, no `unsafe`, no CLI flags.
- [x] **Correctness** — Edge cases: (1) `" (deleted)"` suffix is stripped ONLY when it is the exact 10-byte suffix of the joined path string — so `/tmp/foo (deleted)` → `/tmp/foo` but `/tmp/bar.deleted` or `/tmp/baz (deleted).swp` stay verbatim. Verified by `test_maps_parse_deleted_suffix` asserting `Path::new("/tmp/foo")` without the marker. (2) Pseudo-paths `[vdso]`, `[stack]`, `[heap]` do not end with ` (deleted)` and pass through untouched — important for P02/P03 arena scanning where these entries appear in `/proc/1/maps`. (3) Malformed lines route to `Error::AreaCorrupt(format!("/proc/{pid}/maps: <detail>"))` — reusing the existing `AreaCorrupt` variant rather than introducing an eighth error variant keeps T1's error surface unchanged and matches the spirit of "data we read from the kernel is not in the expected shape" (the variant's original intent for corrupt property arenas). (4) Empty lines and trailing newlines → `Ok(None)` from `parse_line`, skipped during collection (`maps.rs:53-56`). (5) `find_by_path` uses `e.path.as_deref() == Some(path)` — the `.as_deref()` call converts `Option<PathBuf>` to `Option<&Path>` which correctly compares against the `&Path` argument; a `None` entry (no path column) cannot match and is skipped. (6) No `unsafe` blocks in maps.rs (pure-safe path — no ptrace, no FFI at this layer per REGISTRY §3 row `seal/maps.rs`). (7) Each commit verified to compile independently: `fa02dc3` builds on top of the 4 prior commits without needing the `mod.rs` re-export (because `find_by_path`/`MapEntry`/`parse_maps` are all reachable via the `pub mod maps;` declaration already shipped in T1); `2ad4557` then adds the re-export cleanly. (8) Minor drift noted by agent: doc comment at `maps.rs:28-29` cites `error.rs:61-68` for the `From<io::Error>` impl, but the actual location post-T1 is `error.rs:66-73` — off by 5 lines. Not blocking Gate 1 (cosmetic comment drift, not a code defect), flagged for later cleanup.

### Task 3: ptrace attach/detach + register IO

- [x] Implementation: `crates/resetprop/src/seal/ptrace.rs` declares constants `PTRACE_CONT=7`, `PTRACE_DETACH=17`, `PTRACE_GETREGSET=0x4204`, `PTRACE_SETREGSET=0x4205`, `PTRACE_SEIZE=0x4206`, `PTRACE_INTERRUPT=0x4207`, `NT_PRSTATUS=1`, `ARM64_SVC_0=0xd400_0001`, `ARM64_BRK_0=0xd420_0000`. Evidence: `ptrace.rs:27-46`. Also `NR_GETPID=172` added (used by T5's smoke test) per dispatch directive.
- [x] Implementation: `#[repr(C)] #[derive(Clone, Copy, Default)] pub struct UserPtRegs { pub regs: [u64; 31], pub sp: u64, pub pc: u64, pub pstate: u64 }` present. Evidence: `ptrace.rs:93-99`.
- [x] Implementation: `const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);` guarded by `#[cfg(target_arch = "aarch64")]`. Evidence: `ptrace.rs:106-107`. Verified on aarch64-linux-android target — `cargo check --target aarch64-linux-android` exits 0 with the assert engaged.
- [x] Implementation: `pub fn ptrace_seize(pid: Pid) -> Result<()>`, `pub fn ptrace_interrupt(pid: Pid) -> Result<()>`, `pub fn wait_stop(pid: Pid) -> Result<i32>`, `pub fn getregset(pid: Pid) -> Result<UserPtRegs>`, `pub fn setregset(pid: Pid, regs: &UserPtRegs) -> Result<()>`, `pub fn ptrace_detach(pid: Pid) -> Result<()>` all present. Evidence: `ptrace.rs:149-273`. All take `Pid` alias (imported via `use super::Pid;`), not raw `libc::pid_t`.
- [x] Implementation: Failing `ptrace(PTRACE_SEIZE, ...)` calls with `errno == EPERM` classify via `/proc/sys/kernel/yama/ptrace_scope` read to `Error::PtraceScope`; other failures map to `Error::PtraceAttach(io::Error::last_os_error())`. Evidence: `ptrace.rs:118-133` (`classify_seize_err` helper), called from `ptrace.rs:149-159`. Scope value `>=1` → `PtraceScope`; `==0` or read failure → `PtraceAttach`.
- [x] Implementation: Every `unsafe` block has a `// SAFETY:` comment (REGISTRY §2 row 12). Evidence: `grep -c "// SAFETY:" ptrace.rs` = 6; `grep -c "unsafe {" ptrace.rs` = 6. Pairing at lines 150/153, 166/167, 187/190, 217/222, 245/247, 263/264.
- [x] Test: `cargo check -p resetprop` exits 0 on aarch64 (size assert engages). Raw: `Finished dev profile in 4.29s` on `--target aarch64-linux-android`.
- [x] Test: `cargo check -p resetprop` exits 0 on x86_64 (size assert `#[cfg]`-gated off). Raw: `Finished dev profile in 1.01s`. Full-lib test sweep: `63 passed; 0 failed` (was 61; +2 agent-added sanity tests `constants_match_canonical_values` + `size_assert`).

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [x] **Optimality** — Notes: Chosen shape: constants at top, one `classify_seize_err` helper for the EPERM+yama branch, one `last_ptrace_err` one-liner wrapping `io::Error::last_os_error()` for the generic path, six function wrappers. Alternatives considered and rejected: (A) inline the yama read into `ptrace_seize` — rejected because testability and readability benefit from a separate helper; (B) use a `?`-chain with `map_err` — rejected because the EPERM branch has side effects (reading a file), which reads poorly inside a combinator chain. The constants use `as _` casts at call sites rather than `as c_int` per the agent's correct observation that glibc's `libc::ptrace` declares `c_uint` while bionic uses `c_int`; `as _` is the portable idiom (matches linux-arm64-abi.md §12 reference skeleton). The agent also correctly noted that `WIFSTOPPED`/`WSTOPSIG` are `pub const fn` in `libc 0.2.183`, so wrapping them in `unsafe {}` would emit `unused_unsafe` warnings — removed. Both are senior-engineer judgment calls that improve on the dispatch's literal text.
- [x] **Completeness** — Notes: FR-18 (UserPtRegs layout) at ptrace.rs:93-99. FR-19 (aarch64-gated 272-byte assert) at ptrace.rs:106-107. FR-20 (ptrace_seize + yama classification) at ptrace.rs:118-133, 149-159. FR-21 (ptrace_interrupt) at 163-178. FR-22 (wait_stop raw status + WIFSTOPPED/SIGTRAP verify) at 184-202. FR-23 (getregset/setregset iovec NT_PRSTATUS) at 207-256. FR-24 (ptrace_detach) at 259-273. FR-26 (SAFETY on every unsafe) verified mechanically: 6/6 pairing. TC-01 (cargo check exits 0) green on both targets. TC-09 (SAFETY count ≥ unsafe count) green: 6 ≥ 6. Re-export block at mod.rs:39-43 exports the 7 symbols enumerated by spec §Tasks T1 for the ptrace half. `remote_syscall` correctly NOT re-exported (T4 scope). Anti-scope intact: zero edits to maps.rs/error.rs/lib.rs/Cargo.toml.
- [x] **Correctness** — Edge cases: (1) EPERM under `yama.ptrace_scope=0` does NOT misclassify as `PtraceScope` — the helper reads the file and only flips to `PtraceScope` when the value is `>=1`, so EPERM under scope=0 (usually SELinux or owner mismatch) stays as `PtraceAttach` with the original errno surfaced through `source()`. (2) If `/proc/sys/kernel/yama/ptrace_scope` read itself fails (e.g. namespaced containers without the file), fallback is `PtraceAttach` — errno is preserved, user sees the real cause. (3) `wait_stop` unexpected-stop branch returns `PtraceAttach(io::Error::new(io::ErrorKind::Other, format!("unexpected wait status: 0x{status:x}")))` — this avoids an 8th error variant and threads the raw status through `Display`/`source` for debugging. (4) `getregset` initializes `UserPtRegs::default()` before the call; `ptrace(GETREGSET)` writes at most 272 bytes into it (kernel updates `iov.iov_len`); on success the struct is fully populated. (5) `setregset` casts `&UserPtRegs` to `*mut c_void` for the iovec — kernel only reads, the cast is sound. (6) `wait_stop` uses `libc::__WALL` flag (0x40000000) so it reaps threads outside the default waitset per linux-arm64-abi.md §6. (7) The `NR_GETPID=172` constant is the single ARM64 syscall number added in T3 (others deferred to T4/T5 as appropriate); its only consumer is T5's smoke test asserting `remote_syscall(child_pid, scratch_pc, NR_GETPID, [0;6]) == child_pid as i64`. (8) Commits split atomically: `3477933` adds constants+struct+functions together (agent chose to bundle per dispatch allowance — a 3-way split would have left an intermediate commit with functions referencing not-yet-declared consts); `0d30d9f` adds the re-export block. Both compile in isolation.

### Task 4: `remote_syscall` injector

- [x] Implementation: `pub unsafe fn remote_syscall(pid: Pid, scratch_pc: u64, syscall_no: u64, args: [u64; 6]) -> Result<i64>` present in `seal/ptrace.rs`. Evidence: `ptrace.rs:397-402`.
- [x] Implementation: Saves 8 bytes at `scratch_pc` via `process_vm_readv`; writes 8-byte payload `[0x01,0x00,0x00,0xd4, 0x00,0x00,0x20,0xd4]` (`svc #0 ; brk #0`) via `process_vm_writev`. Payload derived from `ARM64_SVC_0.to_le_bytes()` + `ARM64_BRK_0.to_le_bytes()` at `ptrace.rs:405-409` so the encoding cannot drift from the two public constants at `ptrace.rs:54,59`; save at `ptrace.rs:411-414`, stage at `ptrace.rs:416-418`.
- [x] Implementation: Snapshots regs with `getregset`, sets `work.pc = scratch_pc`, `work.regs[8] = syscall_no`, `work.regs[0..6].copy_from_slice(&args)`, writes with `setregset`. Evidence: `ptrace.rs:421` (snapshot), `ptrace.rs:425-428` (work build), `ptrace.rs:431` (setregset).
- [x] Implementation: Issues `libc::ptrace(PTRACE_CONT, pid, 0, 0)`, then `wait_stop` verifying `WIFSTOPPED && WSTOPSIG == SIGTRAP && ((status >> 16) & 0xffff) == 0`. Evidence: `ptrace.rs:436-446` (PTRACE_CONT + errno handling), `ptrace.rs:452` (`wait_stop` — verifies `WIFSTOPPED && SIGTRAP`), `ptrace.rs:453-461` (event-byte-zero check completes brk-trap classification per §9). Event check kept inside `remote_syscall` rather than inside `wait_stop` because `wait_stop` is general-purpose and must still accept group-stops (event=128) during the initial SEIZE+INTERRUPT transition.
- [x] Implementation: Reads `ret = out.regs[0] as i64`, restores saved regs via `setregset`, restores the 8 saved scratch bytes via `process_vm_writev`. Evidence: `ptrace.rs:464-465` (x0 read), `ptrace.rs:470` (regs restored FIRST), `ptrace.rs:472` (scratch bytes restored LAST) — ordering matches §7 step 9 requirement.
- [x] Implementation: Helper `read_remote` / `write_remote` loops on partial transfers (linux-arm64-abi.md §10). Evidence: `ptrace.rs:294-326` (`read_remote`), `ptrace.rs:341-372` (`write_remote`). Both are module-private (`unsafe fn`, not `pub`), advance local + remote iovecs in lockstep, and treat `n == 0` with bytes outstanding as a stall surfaced via `Error::PtraceAttach` (not infinite loop).
- [x] Test: `cargo check -p resetprop` exits 0. Raw: `Finished dev profile in 0.12s` on x86_64 host; `Finished dev profile in 0.04s` on `--target aarch64-linux-android` with the 272-byte `UserPtRegs` assert engaged. Full-lib sweep: `63 passed; 0 failed` — zero regressions vs T3 baseline 63. Dead-code warnings on `remote_syscall` are expected (public, not yet consumed by P02+); not suppressed with `#[allow]` per anti-paper-over policy.

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [x] **Optimality** — Notes: Injector follows linux-arm64-abi.md §7 verbatim, each of the 9 steps annotated with `// (§7 step N)` comments at `ptrace.rs:411,416,420,423,430,448,463,467`. Two elegance decisions worth calling out: (A) **payload derived from constants, not literals** — `ARM64_SVC_0.to_le_bytes()` + `ARM64_BRK_0.to_le_bytes()` at `ptrace.rs:405-409` keeps the 8-byte blob one hop away from the ARM ARM citations (C6.2.304 / C6.2.41, `ptrace.rs:54,59`), so a future constant correction propagates automatically and cannot silently diverge from the reference. The dispatch flagged this as a preference; adopted. (B) **stall detection in partial-transfer helpers** — `n == 0 && transferred < buf.len()` surfaces as `Error::PtraceAttach` with a descriptive "stalled: X/Y bytes" message at `ptrace.rs:314-322,360-368`, preventing an infinite loop if the kernel returns 0 due to a transient unmapped page without setting `-1`. Alternatives rejected: (1) magic byte literal for the payload — drift-resistance beats one saved line; (2) exposing `read_remote`/`write_remote` as `pub` — P02's consumers should go through higher-level wrappers, keep the helpers module-private; (3) a scope-guard for restore — rejected because §7 step 9 mandates regs-BEFORE-bytes ordering and a naive `Drop` guard would reverse it on early-return paths, breaking the contract the restore ordering exists to satisfy.
- [x] **Completeness** — Notes: FR-25 (9-step §7 algorithm) fully landed at `ptrace.rs:397-475`, every step annotated. FR-26 (SAFETY on every `unsafe`) verified mechanically: `grep -c "// SAFETY:"` = 12, `grep -c "unsafe {"` = 12 (was 6/6 pre-T4; 6 new pairings for the 6 new `unsafe` blocks — 2 in `read_remote`/`write_remote` wrapping the `process_vm_*` FFI calls, 1 in `remote_syscall` wrapping `ptrace(PTRACE_CONT,…)`, 3 in `remote_syscall` forwarding the caller's `scratch_pc` contract down to `read_remote`/`write_remote` calls). All six checkboxes in checklist Task 4 map to concrete file:line evidence above. TC-01 (cargo check exits 0) green on x86_64 AND aarch64-linux-android. No regressions in 63-test lib baseline. Re-export at `seal/mod.rs:43` (`remote_syscall,` appended to the existing `pub use ptrace::{…}` block; 1-line atomic refactor commit). Anti-scope intact: zero new `NR_*` constants (those are P02/P03 scope; `remote_syscall` takes `syscall_no: u64` as a parameter), zero edits to `maps.rs`/`error.rs`/`lib.rs`/`Cargo.toml`, zero new error variants (all failures route through existing `Error::PtraceAttach` via `last_ptrace_err()` or `io::Error::new(Other,…)` per T3's handoff discipline), no integration test (T5 scope). Agent's §6 deviations report: **none** — the payload-from-constants approach was in the dispatch as a preference, not a deviation.
- [x] **Correctness** — Edge cases walked: (1) **Zero-byte transfer with outstanding bytes** caught explicitly as "stalled" error (`ptrace.rs:314-322,360-368`) — prevents infinite loop if kernel returns 0 without setting errno. (2) **Partial transfer advances BOTH iovecs in lockstep** — `local.iov_base = buf.as_{mut_}ptr().add(transferred)`, `remote.iov_base = (remote_addr + transferred as u64) as *mut c_void`, `iov_len = remaining` on both (`ptrace.rs:298-305,345-352`). Lockstep pointer math means no byte is ever read/written twice or skipped. (3) **Restore ordering: regs BEFORE bytes** at `ptrace.rs:470,472` — if the caller resumes the tracee via `ptrace_detach` after `remote_syscall`, pc points back at the saved address (regs-first restore). If the caller re-invokes `remote_syscall` with the same `scratch_pc`, the 8 bytes are pristine (bytes-last restore). Both invariants hold only because the order is regs→bytes, not bytes→regs. Matches §7 step 9 rationale. (4) **`wait_stop` vs `remote_syscall` responsibility split**: `wait_stop` verifies `WIFSTOPPED && WSTOPSIG==SIGTRAP` only — accepts group-stop (event=128) required by the initial SEIZE+INTERRUPT transition. `remote_syscall` additionally checks `event == 0` at `ptrace.rs:453-461` to reject anything other than the brk-trap. Correct separation — if the event check lived in `wait_stop`, T5's initial-stop consumption (event=128) would misfire. (5) **`ptrace(PTRACE_CONT, pid, 0, 0)` uses NULL for addr AND data** per the PTRACE_CONT contract (a non-NULL data word delivers a signal; we don't want that because we staged a deterministic `brk`). (6) **`regs[0..6].copy_from_slice(&args)`** safe because `UserPtRegs::regs` is `[u64; 31]` and the slice is exactly 6 — the AArch64 PCS arg registers `x0..x5`. (7) **`out.regs[0] as i64`** correctly treats `-4095..=-1` as `-errno` per the AArch64 syscall return convention; interpretation is the caller's responsibility. (8) **Scratch-PC alignment** documented as 4-byte-aligned in the function's safety contract (`ptrace.rs:392-396`) — the `svc #0` instruction is 4 bytes so misalignment would segfault on instruction fetch; not enforced in code because it's an `unsafe fn` caller contract. T5's mmap'd page is page-aligned by libc::mmap, which satisfies the 4-byte-align sub-requirement trivially. (9) **Commit atomicity verified**: `e9da006` (feat: implement remote_syscall injector) compiles independently — adds helpers + function + libc imports together (function body references the helpers, so splitting the helpers out would leave an intermediate commit with an unresolved reference). `2cfb549` (refactor: re-export remote_syscall) is a one-line addition to the existing `pub use` block. Both commits compile in isolation, preserving the atomic-commit discipline REGISTRY §2 row 6 demands. (10) **No I-cache-flush race in T4 scope**: `process_vm_writev` hits D-side only, but for T5's single-threaded `pause()`-loop child, the ptrace-stop transition's pipeline flush makes the staged `svc` visible. Multi-core flakiness would require `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` but that's P02/P03 scope. Handoff doc §7 point 3 flags this for T5 — if T5 is flaky on SMP hosts, escalate rather than workaround.

### Task 5: `ptrace_core_smoke.rs` integration test

- [ ] Implementation: `crates/resetprop/tests/ptrace_core_smoke.rs` exists with top-of-file doc-comment documenting `cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1` and CAP_SYS_PTRACE / `/proc/sys/kernel/yama/ptrace_scope <= 1` preconditions.
- [ ] Implementation: `fork_child` helper and `ChildGuard` RAII struct (SIGKILL + `waitpid` on Drop) defined per test-harness-patterns.md §3.
- [ ] Implementation: Single `#[test] #[ignore = "..."] fn remote_getpid_returns_child_pid()` present.
- [ ] Implementation: Test mmaps anonymous `PROT_READ|PROT_WRITE|PROT_EXEC` scratch page pre-fork, child `libc::pause`-loops, parent seizes/interrupts/wait_stops, invokes `remote_syscall(child_pid, scratch_pc, 172, [0;6])`, asserts `ret == child_pid as i64`, then `ptrace_detach`.
- [ ] Test: `cargo test -p resetprop --test ptrace_core_smoke` reports `0 passed; 1 ignored` (default invocation).
- [ ] Test: `cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1` reports `1 passed` when run on a host with `ptrace_scope <= 1` or `CAP_SYS_PTRACE`.

#### Self-Audit Gate 5 (MANDATORY before Functional Requirements review)

- [ ] **Optimality** — Notes: ___________________________
- [ ] **Completeness** — Notes: ___________________________
- [ ] **Correctness** — Edge cases: ___________________________

## Functional Requirements (subsystem-level)

### Module surface (per P01 spec, Scope — Files to CREATE)

- [ ] FR-01: `crates/resetprop/src/seal/mod.rs` declares `pub mod maps;` and `pub mod ptrace;` (per spec §Tasks T1).
- [ ] FR-02: `crates/resetprop/src/seal/mod.rs` exports `MapEntry`, `parse_maps`, `UserPtRegs`, `remote_syscall`, `ptrace_seize`, `ptrace_interrupt`, `ptrace_detach`, `wait_stop`, `getregset`, `setregset`, `Pid` at the module root (per spec §Tasks T1).
- [ ] FR-03: `mod seal;` appears in `crates/resetprop/src/lib.rs` immediately after existing `mod wait;` at line 32 (per resetprop-rs-integration.md §3).

### Error surface (per REGISTRY §1 row 35 and §3)

- [ ] FR-04: `error.rs` enum contains variant `PtraceAttach(std::io::Error)` (per plan §Error variants; REGISTRY §1).
- [ ] FR-05: `error.rs` enum contains variant `PtraceScope` (per plan §Error variants).
- [ ] FR-06: `error.rs` enum contains variant `ArenaAlreadySealed(PathBuf)` (per plan §Error variants).
- [ ] FR-07: `error.rs` enum contains variant `ArenaNotMapped(PathBuf)` (per plan §Error variants).
- [ ] FR-08: `error.rs` enum contains variant `ElfParse(String)` (per plan §Error variants).
- [ ] FR-09: `error.rs` enum contains variant `SymbolNotFound(String)` (per plan §Error variants).
- [ ] FR-10: `error.rs` enum contains variant `HookInstallFailed(String)` (per plan §Error variants).
- [ ] FR-11: `Display` impl renders a stable message for every new variant without panicking on missing arms (per resetprop-rs-integration.md §4, lines 18-31 pattern).
- [ ] FR-12: `Error::source` returns `Some(e)` for `PtraceAttach(e)` and `None` for the other six new variants (per resetprop-rs-integration.md §4, lines 33-40 pattern).

### Maps parser (per P01 spec §Tasks T2)

- [ ] FR-13: `MapEntry` carries `start: u64`, `end: u64`, `perms: [u8; 4]`, `offset: u64`, `path: Option<PathBuf>` with exactly those field names and types (per spec §Tasks T2).
- [ ] FR-14: `parse_maps(pid)` reads `/proc/<pid>/maps` via `std::fs::read_to_string`, returning `Result<Vec<MapEntry>>` on success (per spec §Tasks T2).
- [ ] FR-15: `parse_maps` decodes `start-end` as hex `u64` and `perms` as exactly 4 ASCII bytes per the `/proc/<pid>/maps` format (per `proc(5)` man page convention).
- [ ] FR-16: `parse_maps` strips the trailing `" (deleted)"` marker from `path` when present, so the `PathBuf` reflects the original file name (per spec §Tasks T2, `test_maps_parse_deleted_suffix`).
- [ ] FR-17: `find_by_path(entries, path)` returns `Option<&MapEntry>` with exact-path match semantics (per spec §Tasks T2).

### ptrace core (per linux-arm64-abi.md §1-§7 and P01 spec §Tasks T3-T4)

- [ ] FR-18: `UserPtRegs` is `#[repr(C)]`, `#[derive(Clone, Copy, Default)]`, and layout `regs: [u64; 31]; sp: u64; pc: u64; pstate: u64;` (per linux-arm64-abi.md §3).
- [ ] FR-19: Compile-time assertion `size_of::<UserPtRegs>() == 272` is present under `#[cfg(target_arch = "aarch64")]` (per linux-arm64-abi.md §3; REGISTRY §2 row 11).
- [ ] FR-20: `ptrace_seize(pid)` invokes `libc::ptrace(0x4206, pid, 0, 0)` and maps failure to `Error::PtraceScope` when `errno == EPERM && /proc/sys/kernel/yama/ptrace_scope > 0`, else `Error::PtraceAttach(io::Error::last_os_error())` (per linux-arm64-abi.md §11).
- [ ] FR-21: `ptrace_interrupt(pid)` invokes `libc::ptrace(0x4207, pid, 0, 0)` and maps failures to `Error::PtraceAttach` (per linux-arm64-abi.md §4).
- [ ] FR-22: `wait_stop(pid)` calls `libc::waitpid(pid, &mut status, libc::__WALL)`, verifies `WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP`, and returns the raw status (per linux-arm64-abi.md §6 / §9).
- [ ] FR-23: `getregset(pid)` and `setregset(pid, &regs)` use `libc::iovec { iov_len: 272 }` with `NT_PRSTATUS = 1` and request IDs `0x4204` / `0x4205` (per linux-arm64-abi.md §5).
- [ ] FR-24: `ptrace_detach(pid)` invokes `libc::ptrace(17, pid, 0, 0)` and returns `Result<()>` (per linux-arm64-abi.md §6).
- [ ] FR-25: `remote_syscall(pid, scratch_pc, syscall_no, args)` saves 8 bytes at `scratch_pc`, overwrites with `[0x01,0x00,0x00,0xd4, 0x00,0x00,0x20,0xd4]`, snapshots regs, sets `pc=scratch_pc` / `regs[8]=syscall_no` / `regs[0..6]=args`, issues `PTRACE_CONT=7`, waits for brk-trap, returns `regs[0] as i64`, restores regs and scratch bytes (per linux-arm64-abi.md §7).
- [ ] FR-26: Every `unsafe` block in `seal/ptrace.rs` carries a `// SAFETY:` comment (per REGISTRY §2 row 12).

### Integration test (per P01 spec §Tasks T5; test-harness-patterns.md §3)

- [ ] FR-27: `tests/ptrace_core_smoke.rs` defines `fork_child` + `ChildGuard` helpers; `ChildGuard::drop` issues `libc::kill(pid, SIGKILL)` then `libc::waitpid(pid, _, WNOHANG)` + blocking `waitpid` (per test-harness-patterns.md §3).
- [ ] FR-28: `#[test] #[ignore]` decoration present on the single test, with doc-comment citing `--ignored --test-threads=1` (per test-harness-patterns.md §2, §12).
- [ ] FR-29: Test asserts `remote_syscall(child_pid, scratch_pc, 172, [0;6]) == child_pid as i64` (per spec §Tasks T5).

## Test Criteria

- [ ] TC-01: `cargo check -p resetprop` exits 0 (per spec §Validation).
- [ ] TC-02: `cargo build -p resetprop --release` exits 0 (per spec §Validation).
- [ ] TC-03: `cargo test -p resetprop --lib seal::maps` — `3 passed; 0 failed` (per spec §Tasks T2).
- [ ] TC-04: `cargo test -p resetprop --lib` — all pre-existing tests still pass, 0 failures (per spec §Validation).
- [ ] TC-05: `cargo test -p resetprop --lib error::` — Display + `source` extensions do not regress (per spec §Tasks T1).
- [ ] TC-06: `cargo test -p resetprop --test ptrace_core_smoke` — `0 passed; 1 ignored` (default path; per spec §Tasks T5).
- [ ] TC-07: `cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1` — `1 passed` on a host with `ptrace_scope <= 1` or `CAP_SYS_PTRACE` (per spec §Tasks T5; test-harness-patterns.md §12).
- [ ] TC-08: `grep -n "mod seal;" crates/resetprop/src/lib.rs` reports exactly one match on line 33 (per spec §Tasks T1).
- [ ] TC-09: `grep -c "// SAFETY:" crates/resetprop/src/seal/ptrace.rs` ≥ count of `unsafe` blocks in the file (per REGISTRY §2 row 12).

## Integration Verification

- [ ] IV-01: Consumes: none (P01 is the root per REGISTRY §5; no upstream phase).
- [ ] IV-02: Exposes `seal::ptrace::remote_syscall` to P02 (Tier A) for remote `openat`/`mmap(MAP_PRIVATE|MAP_FIXED)`/`close` (per plan §Tier A implementation step 3-5).
- [ ] IV-03: Exposes `seal::ptrace::{ptrace_seize, ptrace_interrupt, wait_stop, getregset, setregset, ptrace_detach, UserPtRegs}` to P02 and P04 (per REGISTRY §3 Domain Ownership, `ptrace.rs` row).
- [ ] IV-04: Exposes `seal::maps::{MapEntry, parse_maps, find_by_path}` to P02 (arena lookup in `/proc/1/maps`) and P03 (libc.so base lookup) (per plan §Tier A step 2 and §Tier B install sequence step 1).
- [ ] IV-05: Exposes 7 new `Error` variants — `PtraceAttach`, `PtraceScope`, `ArenaAlreadySealed`, `ArenaNotMapped`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed` — consumed by P02 (Arena*), P03 (Elf*, Symbol*), P04 (HookInstallFailed) (per REGISTRY §1 row 35, §3).
- [ ] IV-06: Downstream exposes `SealRecord` and `SealTier` (defined in `seal/mod.rs` per Task 1) to P02 (populates `SealTier::Arena` records) and P04 (populates `SealTier::Prop` records) (per REGISTRY §1 rows "`SealRecord` and `SealTier` types created by P01", "`SealRecord` fields", "`SealTier` variants").

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `PROP_INFO_FIXED` | `96` (REGISTRY §1 row 24; `prop_info.h:89`) | `crates/resetprop/src/info.rs:6` (unchanged; referenced by P04) |
| `PROP_VALUE_MAX` | `92` (REGISTRY §1 row 24; `info.rs:7`) | `crates/resetprop/src/info.rs:7` (unchanged; referenced by P04) |
| `UserPtRegs` size | `272` bytes (linux-arm64-abi.md §3; `asm-arm64/asm/ptrace.h:49-54`) | `crates/resetprop/src/seal/ptrace.rs:<line of size_of assert>` |
| `__NR_getpid` | `172` (linux-arm64-abi.md §1; `asm-generic/unistd.h:461`) | `crates/resetprop/tests/ptrace_core_smoke.rs:<line of invocation>` |
| `__NR_openat` | `56` (linux-arm64-abi.md §1; `asm-generic/unistd.h:158`) | Declared in `seal/ptrace.rs` or consumed in P02; verified in `seal/ptrace.rs:<line>` |
| `__NR_mmap` | `222` (linux-arm64-abi.md §1; `asm-generic/unistd.h:570,886`) | Declared in `seal/ptrace.rs` or consumed in P02; verified in `seal/ptrace.rs:<line>` |
| `__NR_close` | `57` (linux-arm64-abi.md §1; `asm-generic/unistd.h:160`) | Declared in `seal/ptrace.rs` or consumed in P02; verified in `seal/ptrace.rs:<line>` |
| `PTRACE_SEIZE` | `0x4206` (linux-arm64-abi.md §4; `linux/ptrace.h:29`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `PTRACE_INTERRUPT` | `0x4207` (linux-arm64-abi.md §4; `linux/ptrace.h:30`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `PTRACE_GETREGSET` | `0x4204` (linux-arm64-abi.md §4; `linux/ptrace.h:27`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `PTRACE_SETREGSET` | `0x4205` (linux-arm64-abi.md §4; `linux/ptrace.h:28`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `PTRACE_CONT` | `7` (linux-arm64-abi.md §4; `linux/ptrace.h:17`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `PTRACE_DETACH` | `17` (linux-arm64-abi.md §4; `linux/ptrace.h:21`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `NT_PRSTATUS` | `1` (linux-arm64-abi.md §4; `linux/elf.h:301`) | `crates/resetprop/src/seal/ptrace.rs:<line>` |
| `svc #0` encoding | `0xD4000001` (linux-arm64-abi.md §2; ARM ARM C6.2.304) | `crates/resetprop/src/seal/ptrace.rs:<line of ARM64_SVC_0>` |
| `brk #0` encoding | `0xD4200000` (linux-arm64-abi.md §2; ARM ARM C6.2.41) | `crates/resetprop/src/seal/ptrace.rs:<line of ARM64_BRK_0>` |
| `SealTier::Arena` variant | `SealTier::Arena` (per REGISTRY §1 row "`SealTier` variants") | `crates/resetprop/src/seal/mod.rs:<line of SealTier>` |
| `SealTier::Prop` variant | `SealTier::Prop` (per REGISTRY §1 row "`SealTier` variants") | `crates/resetprop/src/seal/mod.rs:<line of SealTier>` |
| `SealRecord` fields | `{ name: String, arena_path: PathBuf, tier: SealTier, sealed_at: SystemTime }` (per REGISTRY §1 row "`SealRecord` fields") | `crates/resetprop/src/seal/mod.rs:<line of SealRecord>` |

## Anti-Scope (explicitly excluded)

- AS-01: No arena remap / remote `MAP_PRIVATE|MAP_FIXED` `mmap` (P02 scope) (per P01 spec Anti-Scope).
- AS-02: No ELF64 parsing, `PT_DYNAMIC` walk, `DT_SYMTAB` / `DT_GNU_HASH` resolution (P03 scope) (per P01 spec Anti-Scope).
- AS-03: No hook-page allocation, ARM64 trampoline, lock-list layout, `__system_property_update` lookup (P04 scope) (per P01 spec Anti-Scope).
- AS-04: No CLI flags (`-sl`, `-sla`, `--seals`, `--unseal`, `--unseal-arena`), no `print_usage()` edits (P05 scope) (per P01 spec Anti-Scope).
- AS-05: No `PropSystem::seal`, `seal_arena`, `unseal`, `unseal_arena`, `seals` methods (P02/P04 scope) (per P01 spec Anti-Scope).
- AS-06: No `SealRecord` or `SealTier` types (P02 scope) (per P01 spec Anti-Scope).
- AS-07: No disk persistence for seal state (deferred per REGISTRY §1 row 15) (per P01 spec Anti-Scope).
- AS-08: No propdetect heuristics (not scoped to v1) (per P01 spec Anti-Scope).
- AS-09: No edits to `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, `appcompat.rs`, `bionic.rs`, `context.rs`, `wait.rs`, `harvest.rs`, `dict.rs`, `inspect.rs`, `mock.rs` (per P01 spec Anti-Scope).

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment completes. NOT after each segment.

- [ ] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template — both persona prompts are inlined there verbatim) with: phase spec path `/home/president/Git-repo-success/resetprop-rs/phases/seal/P01-foundation.md`, checklist path `/home/president/Git-repo-success/resetprop-rs/phases/seal/checklists/P01-checklist.md`, REGISTRY path `/home/president/Git-repo-success/resetprop-rs/phases/seal/REGISTRY-P.md`, code file paths (`crates/resetprop/src/seal/mod.rs`, `crates/resetprop/src/seal/maps.rs`, `crates/resetprop/src/seal/ptrace.rs`, `crates/resetprop/src/error.rs`, `crates/resetprop/src/lib.rs`, `crates/resetprop/tests/ptrace_core_smoke.rs`), branch name `feat/P01-foundation`, External API Verification `YES` with sources `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h`, `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/elf.h`, `/home/president/aosp-android15/bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.h`, `/usr/include/asm-generic/unistd.h`.
- [ ] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block.
- [ ] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block.
- [ ] Both agents dispatched IN PARALLEL (single message, two Agent tool calls).
- [ ] External API Verification confirmed: both agents grep'd/read the listed sources and quoted real signatures for at least `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `NT_PRSTATUS`, `__NR_getpid`, and the `user_pt_regs` struct layout.
- [ ] code-reviewer report saved at `phases/seal/audits/P01-audit.md` — verdict: `{{PASS | NEEDS_FIX}}`.
- [ ] critic report saved at `phases/seal/audits/P01-audit.md` — verdict: `{{PASS | NEEDS_FIX}}`.
- [ ] All CRITICAL findings resolved.
- [ ] All MAJOR findings resolved.
- [ ] MINOR findings logged (not blocking).
- [ ] Re-ran both agents after fixes; both emitted `VERDICT: PASS`.

## Acceptance Gate

- [ ] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes on Optimality, Completeness, Correctness).
- [ ] All FR-01 through FR-29 verified with code location annotations.
- [ ] All TC-01 through TC-09 executed and passing.
- [ ] All IV-01 through IV-05 verified against the P02/P03/P04 consumers declared in REGISTRY §3.
- [ ] No regressions in prerequisite phases (none — P01 is root); pre-existing library tests still pass: `cargo test -p resetprop --lib` exits 0, `cargo test -p resetprop --test device_smoke` (if present) exits 0.
- [ ] Branch `feat/P01-foundation` commits follow `feat(seal):` / `test(seal):` / `refactor(seal):` prefix per REGISTRY §2.
- [ ] All canonical values verified with `file:line` annotations replacing `<line>` placeholders in the Canonical Values table.
- [ ] Gate 2 reports PASS from BOTH `code-reviewer` and `critic` agents (saved at `phases/seal/audits/P01-audit.md`).
- [ ] REGISTRY §4 row "P01 — Foundation: ptrace + maps" updated: `Status = COMPLETE`, `Session(s)` column populated, `Notes` column summarizes deliverables.
- [ ] REGISTRY §7 session log appended with outcome (`COMPLETE`) and both Gate 2 verdicts.
