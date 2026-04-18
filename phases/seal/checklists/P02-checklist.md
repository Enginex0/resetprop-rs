# P02 — Tier A: Arena-Level Seal — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [ ] P01 (Foundation: ptrace + maps) shows COMPLETE in REGISTRY §4
- [ ] `crates/resetprop/src/seal/mod.rs` exists and declares `pub mod ptrace;` + `pub mod maps;`
- [ ] `crates/resetprop/src/seal/ptrace.rs` exports `remote_syscall`, attach/detach helpers, and `UserPtRegs` (REGISTRY §1 "Remote syscall path")
- [ ] `crates/resetprop/src/seal/maps.rs` exports `parse_maps(pid) -> Result<Vec<MapEntry>>`
- [ ] `crates/resetprop/src/error.rs` carries the 7 new seal variants from P01 (`PtraceAttach`, `PtraceScope`, `ArenaAlreadySealed`, `ArenaNotMapped`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`)
- [ ] `main` is up-to-date locally; no uncommitted changes blocking branch creation

(Source: P02 spec, Preconditions; REGISTRY §5 dependency graph)

## Branch

- [ ] Branch `feat/P02-tier-a` created (or resumed) from latest `main`
- [ ] All commits follow `feat(seal):` / `test(seal):` / `docs(seal):` / `refactor(seal):` prefix per REGISTRY §2

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: `find_arena_mapping` in `seal/arena.rs`

- [x] Implementation: `crates/resetprop/src/seal/arena.rs` exists and exports `pub(crate) fn find_arena_mapping(pid: libc::pid_t, arena_path: &Path) -> Result<MapEntry>`
- [x] Implementation: Pure helper `fn find_arena_mapping_in(entries: &[MapEntry], arena_path: &Path) -> Result<MapEntry>` is defined for in-process unit testing (no `/proc` dependency)
- [x] Implementation: Returns `Error::ArenaNotMapped(arena_path.to_path_buf())` when no entry matches
- [x] Implementation: Rejects read-only matches (`perms` starting with `"r-"`) — only entries with `perms` starting with `"rw"` qualify as init's writable view
- [x] Test: `cargo test -p resetprop seal::arena::tests::find_arena_mapping_picks_rw_view` passes
- [x] Test: `cargo test -p resetprop seal::arena::tests::find_arena_mapping_rejects_ro_only_fixture` passes
- [x] Test: `cargo test -p resetprop seal::arena::tests::find_arena_mapping_returns_not_mapped_on_miss` passes

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [x] **Optimality** — Considered: (a) inlining the parse call vs. splitting to `find_arena_mapping_in`; (b) accepting `&str` for `perms` vs. enum flags. Chose split helper + `&str` perms because `maps.rs` already returns `MapEntry { perms: String }` per P01 and we should not re-model it here. Notes: The checklist text is out of date — `MapEntry::perms` is actually `[u8; 4]` as shipped by P01 (`seal/maps.rs:20`, amended during P01 S02 hardening); matched via `entry.perms.starts_with(b"rw")` which is zero-alloc and preserves the parser's locked field shape. Additionally rejected deriving `Clone` on `MapEntry` to return an owned value — that would widen the P01 public surface; instead reconstruct a fresh struct literal in `find_arena_mapping_in` and keep the seam explicit. Rejected returning `Result<&MapEntry>` because the public `find_arena_mapping` owns the `Vec<MapEntry>` from `parse_maps` and a borrowed return would force callers to manage that vec's lifetime.
- [x] **Completeness** — Deliverable meets spec §Tasks T1: function signature matches (`pub(crate) fn find_arena_mapping(pid, arena_path) -> Result<MapEntry>` at `seal/arena.rs:44`), pure helper `find_arena_mapping_in(&[MapEntry], &Path) -> Result<MapEntry>` exists at `seal/arena.rs:27`, `ArenaNotMapped` error surface correct for both miss and ro-only cases (single unified error variant, reuse documented in the doc comment at `seal/arena.rs:14-19`), three fixture-driven unit tests ship with the names required by the checklist (`find_arena_mapping_picks_rw_view`, `find_arena_mapping_rejects_ro_only_fixture`, `find_arena_mapping_returns_not_mapped_on_miss`). `pub mod arena;` added to `seal/mod.rs:13` immediately after `pub mod ptrace;` per brief instruction. T2/T3 surfaces (`remote_remap_private`, `seal_arena`, `unseal_arena`) intentionally absent — they are the next session's work.
- [x] **Correctness** — Edge cases walked: empty maps list → loop falls through and returns `Err(ArenaNotMapped(path))`; entries with `path: None` → `as_deref() == Some(arena_path)` is false so they are skipped cleanly; multiple `rw-p` matches for the same path → first-match-wins via the `for` loop's natural ordering (documented via the doc comment "Returns the first entry"); path with trailing whitespace → P01's parser preserves interior whitespace verbatim (`seal/maps.rs:91-111`) and strips only the exact `" (deleted)"` suffix, so exact-equality comparison works as-is; ro-only match (`b"r-"`) → rejected in the perms check and caller sees `ArenaNotMapped` (same variant, same payload, documented rationale). Path canonicalization is the kernel's responsibility (it normalizes before writing to `/proc/pid/maps`), so `/dev/__properties__/./foo` style paths are not observed in practice.

### Task 2: `remote_remap_private` in `seal/arena.rs`

- [ ] Implementation: `unsafe fn remote_remap_private(pid: libc::pid_t, mapping: &MapEntry, arena_path: &Path) -> Result<()>` is defined and compiles
- [ ] Implementation: Uses `seal::ptrace::attach(pid)` + `seal::ptrace::stage_svc(pid, scratch_pc)` to prepare the tracee (per REGISTRY §1 "Remote syscall path")
- [ ] Implementation: Issues three sequential `seal::ptrace::remote_syscall` calls with syscall numbers `__NR_openat=56`, `__NR_mmap=222`, `__NR_close=57` (linux-arm64-abi.md §1)
- [ ] Implementation: `openat` args are `[AT_FDCWD=-100 as u64, path_ptr, (O_RDONLY|O_NOFOLLOW)=0x20000, 0, 0, 0]`
- [ ] Implementation: `mmap` args are `[mapping.start, mapping.end - mapping.start, (PROT_READ|PROT_WRITE)=0x3, (MAP_PRIVATE|MAP_FIXED)=0x12, remote_fd as u64, 0]`
- [ ] Implementation: Asserts `mmap` return value equals `mapping.start`; any other return wraps into an error (not silently accepted)
- [ ] Implementation: `RemoteSyscallGuard` type exists with `impl Drop` that restores saved registers + 8 scratch bytes + runs `seal::ptrace::detach` unconditionally
- [ ] Implementation: Path bytes for `openat` are written into init's scratch region via `seal::ptrace::process_vm_writev` (or equivalent from P01); the write location is tracked by the guard and restored on Drop
- [ ] Test: `cargo build -p resetprop` succeeds; `grep -n 'impl Drop for RemoteSyscallGuard' crates/resetprop/src/seal/arena.rs` returns one match

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [ ] **Optimality** — Considered: (a) writing path into init's existing stack via `sp - N` vs. a dedicated scratch page (chose existing scratch from P01 — no new allocation); (b) batching `openat`+`mmap`+`close` as one PTRACE_CONT via multiple staged svcs (rejected — `brk #0` resync between svcs is clearer and matches linux-arm64-abi.md §7 contract). Notes: ___________________________
- [ ] **Completeness** — Deliverable meets spec §Tasks T2: guard type exists, three syscalls wired, return-value check, register/scratch restoration bulletproof on error path. Notes: ___________________________
- [ ] **Correctness** — Edge cases walked: `openat` returns `-EACCES` (unexpected — init runs as root, but still propagate with a clear error); `mmap` returns a different address (kernel refused MAP_FIXED — error, not silent success); tracee dies mid-sequence (`ESRCH` from next ptrace call — guard still runs, Drop swallows the errno and leaves a log line only via `eprintln!` in verbose mode); path string length > scratch size (caller's responsibility, document). Notes: ___________________________

### Task 3: `seal_arena` / `unseal_arena` orchestrators

- [ ] Implementation: `pub fn seal_arena(pid: libc::pid_t, arena_path: &Path) -> Result<()>` wraps `find_arena_mapping` + `remote_remap_private` with `MAP_PRIVATE`
- [ ] Implementation: `pub fn unseal_arena(pid: libc::pid_t, arena_path: &Path) -> Result<()>` uses `MAP_SHARED|MAP_FIXED = 0x11` and `O_RDWR|O_NOFOLLOW = 0x20002` to restore init's original view
- [ ] Implementation: `pub fn seal_arena_with_mirror(pid: libc::pid_t, primary: &Path, mirror: Option<&Path>) -> Result<()>` iterates `[primary, mirror]` and short-circuits on first error
- [ ] Implementation: Analogous `unseal_arena_with_mirror` exists
- [ ] Implementation: All four functions are `pub` in `crates/resetprop/src/seal/arena.rs` and re-exported via `seal::arena::*` from `seal/mod.rs`
- [ ] Test: `cargo doc -p resetprop --no-deps` emits rustdoc entries for `seal_arena`, `unseal_arena`, `seal_arena_with_mirror`, `unseal_arena_with_mirror`

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [ ] **Optimality** — Considered: (a) single `seal_arena` taking `&[&Path]` vs. two functions with wrapper (chose two + wrapper — cleaner for the dominant single-path call site); (b) returning `Vec<Error>` on mirror failure vs. first-error-wins (first-error-wins chosen — matches existing `PropSystem::set_stealth` shape). Notes: ___________________________
- [ ] **Completeness** — Deliverable meets spec §Tasks T3: seal + unseal, both with mirror wrappers, both re-exported. Notes: ___________________________
- [ ] **Correctness** — Edge cases walked: double-seal (caller calls `seal_arena` twice on the same path — second call re-runs the remap, which is idempotent at the kernel level because MAP_FIXED replaces the VMA; no corruption, but we log a warning); `unseal_arena` called on a never-sealed arena (remote `mmap(MAP_SHARED|MAP_FIXED)` over an already-shared range is also a no-op at the kernel level — safe); mirror path is `None` → skipped cleanly. Notes: ___________________________

### Task 4: `PropSystem::seal_arena` + `PropSystem::unseal_arena` in `lib.rs`

- [ ] Implementation: `PropSystem::seal_arena(&self, name: &str, value: &str) -> Result<SealRecord>` is defined in `crates/resetprop/src/lib.rs` immediately after `set_stealth_persist` at `lib.rs:497`
- [ ] Implementation: First line of body is `self.set_stealth(name, value)?;` (matches plan §Internal flow step 1)
- [ ] Implementation: Primary arena path resolved via `self.context.as_ref()...resolve(name)` (`context.rs:367-376`) joined with the recorded properties directory base
- [ ] Implementation: Hard guard: `if primary_path == Path::new("/dev/__properties__/properties_serial") { return Err(Error::InvalidKey); }` — runs BEFORE any ptrace call
- [ ] Implementation: Mirror path probed via `self.appcompat.as_ref().and_then(|a| a.mirror_for(filename))` (`appcompat.rs:49-51`); if present, passed to `seal::arena::seal_arena_with_mirror`
- [ ] Implementation: On success, pushes `SealRecord { name, arena_path: primary_path, tier: SealTier::Arena, sealed_at: SystemTime::now() }` into the `OnceLock<Mutex<Vec<SealRecord>>>` static in `seal/mod.rs`
- [ ] Implementation: Duplicate-name guard: linear scan before push; if a record for this `name` already exists with `tier: SealTier::Arena`, overwrite `sealed_at` and return the existing record (do not double-push)
- [ ] Implementation: `PropSystem::unseal_arena(&self, name: &str) -> Result<bool>` mirrors the flow — resolve + mirror detect + `seal::arena::unseal_arena_with_mirror` + remove matching record; returns `Ok(false)` if no record existed; returns `Ok(true)` on successful remove
- [ ] Implementation: No file-permission calls (`chmod`, `fchmod`, `fchown`, `ftruncate`) anywhere in the added code paths (grep verified)
- [ ] Test: `cargo test -p resetprop seal::tests::seal_arena_rejects_properties_serial` passes — asserting `Error::InvalidKey` is returned
- [ ] Test: `cargo test -p resetprop seal::tests::seal_record_roundtrip` passes — record appears in registry after seal, disappears after unseal
- [ ] Test: `cargo test -p resetprop seal::tests::unseal_returns_false_when_not_sealed` passes

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [ ] **Optimality** — Considered: (a) `OnceLock<Mutex<Vec<_>>>` vs. `OnceLock<Mutex<HashMap<String, _>>>` (chose Vec — expected seal count < 20, linear scan is fine, matches plan §Internal flow "in-memory `SealRecord` set"); (b) holding the registry on `PropSystem` vs. module-level static (chose module-level — registry must outlive the short-lived `PropSystem` borrow in CLI dispatch). Notes: ___________________________
- [ ] **Completeness** — Deliverable meets spec §Tasks T4: both methods placed at `lib.rs:497` anchor, stealth-set first, properties_serial guard, mirror detection, registry push, symmetric unseal. Notes: ___________________________
- [ ] **Correctness** — Edge cases walked: `name` not in any context area → `resolve` returns `None` → surface as `Error::NotFound` (consistent with existing `set_stealth` behaviour); `PropSystem` opened with no context (`self.context = None`) → fall back to linear scan over `self.areas` using existing `find_writable` pattern (lib.rs:385-401); mirror detected but init has no mapping for it (`find_arena_mapping` returns `ArenaNotMapped`) → treat as non-fatal warning, proceed; mutex poisoned → recover via `into_inner` with a logged warning. Notes: ___________________________

### Task 5: Integration smoke test `tests/tier_a_child_smoke.rs`

- [ ] Implementation: `crates/resetprop/tests/tier_a_child_smoke.rs` exists
- [ ] Implementation: Top-of-file doc block documents the runner: `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1`
- [ ] Implementation: Helper `fork_child<F: FnOnce() -> !>` matches `test-harness-patterns.md §3` shape
- [ ] Implementation: `ChildGuard(libc::pid_t)` struct with `Drop` that calls `libc::kill(pid, SIGKILL)`, then `libc::waitpid(pid, _, WNOHANG)`, then blocking `libc::waitpid(pid, _, 0)`
- [ ] Implementation: Child body `mmap`s the temp file with `MAP_SHARED|PROT_READ|PROT_WRITE` and writes `SENTINEL_POST=0xBB` at offset 128 every ~10 ms via `std::ptr::write_volatile`
- [ ] Implementation: Parent pre-writes `SENTINEL_PRE=0xAA` at offset 128 before forking
- [ ] Implementation: Parent reads via an independent `std::fs::OpenOptions::read(true).open(path)` to observe the file (the "third observer")
- [ ] Implementation: Baseline assertion: after 100 ms sleep, reader sees `SENTINEL_POST` (MAP_SHARED propagation confirmed)
- [ ] Implementation: Seal invocation: `resetprop::seal::arena::seal_arena(guard.pid(), tmp.path())` (NOT the `PropSystem` method — that is for `pid=1`; this is the raw entry point)
- [ ] Implementation: Parent overwrites on-disk byte back to `SENTINEL_PRE`, sleeps 200 ms, re-reads, asserts byte is still `SENTINEL_PRE`
- [ ] Implementation: Attribute `#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]` is present on the test function
- [ ] Test: `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1` exits 0 on a host with `ptrace_scope <= 1`
- [ ] Test: Default `cargo test -p resetprop` still passes (smoke test is ignored by default)

#### Self-Audit Gate 5 (MANDATORY before Phase-End Audit)

- [ ] **Optimality** — Considered: (a) using a pipe for child-parent handshake vs. plain sleeps (chose sleeps — smoke test, not a race benchmark, and test-harness-patterns.md §4 uses sleeps); (b) reading the file via `File::read_at` vs. seek+read (chose seek+read — matches the reference skeleton byte-for-byte, easier Gate 2 review). Notes: ___________________________
- [ ] **Completeness** — Deliverable meets spec §Tasks T5: fork+guard+baseline+seal+reverify+cleanup; `#[ignore]` attribute present; runner documented in header. Notes: ___________________________
- [ ] **Correctness** — Edge cases walked: child's mmap happens AFTER the parent reads baseline → baseline must race-tolerate (parent sleeps 100 ms before reading — long enough for child to `mmap + write_volatile` once, confirmed by 10 ms loop); temp file unlink during test → `NamedTempFile` keeps the fd open until Drop, Drop runs after `guard` drop, so child always has a valid inode; ptrace_scope == 2 on CI → test is `#[ignore]` and won't be invoked by default; Gate-2 agent running on a non-Linux laptop → test compiles but skips cleanly. Notes: ___________________________

## Functional Requirements (subsystem-level)

### Tier A arena sealing (per plan §Tier A, `aosp-property-system.md`)

- [ ] FR-01: `seal::arena::seal_arena` issues a remote `openat(AT_FDCWD, path, O_RDONLY|O_NOFOLLOW)` via `seal::ptrace::remote_syscall` with syscall number `__NR_openat = 56` (per `linux-arm64-abi.md §1`) — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-02: `seal::arena::seal_arena` issues a remote `mmap(start, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, fd, 0)` — flags mirror `map_prop_area_rw` (prop_area.cpp:99) with `MAP_SHARED` swapped for `MAP_PRIVATE` (per `aosp-property-system.md §7`, plan §Tier A) — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-03: `seal::arena::seal_arena` issues a remote `close(fd)` to clean up the temporary descriptor before detach (per `aosp-property-system.md §13` Tier A checklist) — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-04: Registers and the 8 staged scratch bytes at `scratch_pc` are restored via `RemoteSyscallGuard::drop` on BOTH success and error paths (per `linux-arm64-abi.md §7` "Save/restore 8 bytes") — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-05: `PropSystem::seal_arena` calls `self.set_stealth(name, value)` before any ptrace work (per plan §Internal flow in `seal()` step 1) — verified at crates/resetprop/src/lib.rs:___
- [ ] FR-06: `PropSystem::seal_arena` resolves the primary arena path via `PropertyContext::resolve(name)` (per `resetprop-rs-integration.md §8`, context.rs:367-376) — verified at crates/resetprop/src/lib.rs:___
- [ ] FR-07: `PropSystem::seal_arena` detects and privatizes the appcompat mirror when present via `AppcompatAreas::mirror_for(filename)` (per `aosp-property-system.md §10`, appcompat.rs:49-51) — verified at crates/resetprop/src/lib.rs:___
- [ ] FR-08: `PropSystem::seal_arena` rejects any name whose `PropertyContext::resolve` returns the `properties_serial` arena filename with `Error::InvalidKey` — the rejection occurs BEFORE any ptrace call, regardless of the name's stealth-layer value (per REGISTRY §1 "Arenas NOT to touch"; `aosp-property-system.md §11`; system_properties.cpp:325-333) — verified at crates/resetprop/src/lib.rs:___
- [ ] FR-09: No code path in the P02 diff calls `chmod`, `fchmod`, `fchown`, or `ftruncate` on any `/dev/__properties__/*` inode (per REGISTRY §1 "File permissions: Never modified"; prop_area.cpp:63-68 init-EACCES-abort, prop_area.cpp:111-138 map_fd_ro st_uid/st_gid/mode checks) — verified by grep of crates/resetprop/src/seal/arena.rs and crates/resetprop/src/lib.rs
- [ ] FR-10: On successful `PropSystem::seal_arena`, a `SealRecord { name, arena_path, tier: SealTier::Arena, sealed_at }` is inserted into the in-memory `OnceLock<Mutex<Vec<SealRecord>>>` registry (per plan §Internal flow step 7; REGISTRY §1 "Persistence: Deferred for v1 — in-memory `SealRecord` only") — verified at crates/resetprop/src/seal/mod.rs:___
- [ ] FR-11: `PropSystem::unseal_arena` remaps init's mapping back to `MAP_SHARED|MAP_FIXED = 0x11` over an `O_RDWR|O_NOFOLLOW = 0x20002` remote fd, restoring init's original view (per plan §New public API in lib.rs — `unseal_arena` description) — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-12: `find_arena_mapping` only matches entries whose `perms` field starts with `"rw"` — read-only mappings are rejected even when path matches (per `aosp-property-system.md §7` — init's `map_prop_area_rw` creates the writable view we target) — verified at crates/resetprop/src/seal/arena.rs:___
- [ ] FR-13: The integration smoke test uses an INDEPENDENT third-party reader (`std::fs::OpenOptions::read(true)`) to verify isolation — NOT an inspection of child or parent mappings (per `test-harness-patterns.md §4`) — verified at crates/resetprop/tests/tier_a_child_smoke.rs:___

## Test Criteria

- [ ] TC-01: `cargo build -p resetprop` exits 0 with no warnings (per P02 spec §Validation)
- [ ] TC-02: `cargo test -p resetprop seal::arena` passes all unit tests (per P02 spec §Validation)
- [ ] TC-03: `cargo test -p resetprop seal::tests` passes all `PropSystem`-level unit tests (per P02 spec §Validation)
- [ ] TC-04: `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1` exits 0 on a host with `ptrace_scope <= 1` (per P02 spec §Tasks T5 and §Validation)
- [ ] TC-05: Default `cargo test -p resetprop` (no `--ignored`) passes — proves smoke test is correctly gated (per `test-harness-patterns.md §2`)
- [ ] TC-06: `cargo fmt --check` passes (per REGISTRY §2 coding conventions)
- [ ] TC-07: `cargo clippy -p resetprop -- -D warnings` passes (per REGISTRY §2 coding conventions)
- [ ] TC-08: `grep -n 'chmod\|fchmod\|fchown\|ftruncate' crates/resetprop/src/seal/arena.rs crates/resetprop/src/lib.rs` returns zero matches in the P02 diff (per FR-09)
- [ ] TC-09: `grep -n 'impl Drop for RemoteSyscallGuard' crates/resetprop/src/seal/arena.rs` returns exactly one match (per FR-04)
- [ ] TC-10: `grep -n 'properties_serial' crates/resetprop/src/lib.rs` returns at least one match inside `seal_arena` (per FR-08)

## Integration Verification

- [ ] IV-01: Consumes P01: `seal::ptrace::remote_syscall`, `seal::maps::parse_maps`, `UserPtRegs`, 7 new `Error` variants (`PtraceAttach`, `PtraceScope`, `ArenaAlreadySealed`, `ArenaNotMapped`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`) from `crates/resetprop/src/error.rs` (per REGISTRY §5 dependency graph)
- [ ] IV-02: Consumes existing library: `PropSystem::set_stealth` (lib.rs:458), `PropertyContext::resolve` (context.rs:367-376), `AppcompatAreas::mirror_for` (appcompat.rs:49-51) (per resetprop-rs-integration.md §3, §8, §9)
- [ ] IV-03: Mirrors local precedent: `PropArea::privatize` at `area.rs:230-260` uses `MAP_PRIVATE|MAP_FIXED` over a local mapping; P02's remote variant uses the identical flag combination via `remote_syscall` (per resetprop-rs-integration.md §6)
- [ ] IV-04: Downstream exposes: `PropSystem::seal_arena`, `PropSystem::unseal_arena` — consumed by P05 CLI (`--seal-arena` / `-sla` and `--unseal-arena` flags per plan §New CLI surface)
- [ ] IV-05: Downstream exposes: `seal::arena::seal_arena`, `seal::arena::unseal_arena`, `seal::arena::seal_arena_with_mirror`, `seal::arena::unseal_arena_with_mirror` — also usable by P03/P04 for integration with the Tier B graceful-degradation path (per plan §Graceful degradation)
- [ ] IV-06: Downstream exposes: `SealRecord`, `SealTier::Arena`, and the `OnceLock<Mutex<Vec<SealRecord>>>` registry accessor — consumed by P05 for `--seals` listing (per plan §New public API)
- [ ] IV-07: No breakage in prerequisite phase: `cargo test -p resetprop seal::ptrace` (P01 unit tests) still passes after P02 edits

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `PROT_READ\|PROT_WRITE` | `0x3` (bitwise OR of `PROT_READ=1` + `PROT_WRITE=2`, per Linux `asm-generic/mman-common.h` and `aosp-property-system.md §7` `map_prop_area_rw` prot field) | crates/resetprop/src/seal/arena.rs:___ |
| `MAP_PRIVATE\|MAP_FIXED` | `0x12` (bitwise OR of `MAP_PRIVATE=0x02` + `MAP_FIXED=0x10`, per Linux `asm-generic/mman.h` and `resetprop-rs-integration.md §6` line 247 precedent) | crates/resetprop/src/seal/arena.rs:___ |
| `MAP_SHARED\|MAP_FIXED` (unseal) | `0x11` (bitwise OR of `MAP_SHARED=0x01` + `MAP_FIXED=0x10`, per `aosp-property-system.md §7` original `map_prop_area_rw` shared flag) | crates/resetprop/src/seal/arena.rs:___ |
| `O_RDONLY\|O_NOFOLLOW` | `0x20000` (`O_RDONLY=0` + `O_NOFOLLOW=0x20000` per Linux `asm-generic/fcntl.h`; matches `PropArea::privatize` local precedent at `area.rs:237`) | crates/resetprop/src/seal/arena.rs:___ |
| `O_RDWR\|O_NOFOLLOW` (unseal) | `0x20002` (`O_RDWR=2` + `O_NOFOLLOW=0x20000` per Linux `asm-generic/fcntl.h`) | crates/resetprop/src/seal/arena.rs:___ |
| `AT_FDCWD` | `-100` (per Linux `uapi/linux/fcntl.h` and `linux-arm64-abi.md §12` skeleton) | crates/resetprop/src/seal/arena.rs:___ |
| `__NR_openat` | `56` (`asm-generic/unistd.h:158` per `linux-arm64-abi.md §1`) | crates/resetprop/src/seal/arena.rs:___ |
| `__NR_mmap` | `222` (`asm-generic/unistd.h:570,886` per `linux-arm64-abi.md §1`) | crates/resetprop/src/seal/arena.rs:___ |
| `__NR_close` | `57` (`asm-generic/unistd.h:160` per `linux-arm64-abi.md §1`) | crates/resetprop/src/seal/arena.rs:___ |
| prop_area magic | `0x504f5250` ("PROP" per `prop_area.cpp:49`; REGISTRY §1 "prop_area magic / version / size") | crates/resetprop/src/seal/arena.rs:___ (documented in header comment; not assert-checked because P02 does not parse arena contents — only remaps the VMA) |
| `PA_SIZE` | `128 * 1024 = 131072` (128 KB, per `prop_area.cpp:47`; REGISTRY §1 "prop_area magic / version / size") | crates/resetprop/src/seal/arena.rs:___ (documented in header comment; the remap uses `mapping.end - mapping.start` from `/proc/pid/maps` rather than a hard-coded size, but the expected value is 128 KB) |
| `properties_serial` path | `/dev/__properties__/properties_serial` (REGISTRY §1 "Arenas NOT to touch"; `aosp-property-system.md §11`; system_properties.cpp:325-333) | crates/resetprop/src/lib.rs:___ (inside `PropSystem::seal_arena` guard) |
| appcompat mirror path | `/dev/__properties__/appcompat_override/<filename matching primary>` (per `aosp-property-system.md §10` Appcompat Override — Mirror Writes; REGISTRY §1 row "Scope of v1 arenas") | crates/resetprop/src/lib.rs:___ (inside `PropSystem::seal_arena` mirror detection via `AppcompatAreas::mirror_for`) |
| `SealTier::Arena` | Enum variant constructed by P02; tags every `SealRecord` produced by `PropSystem::seal_arena` (per REGISTRY §1 row "`SealTier` variants"; plan §New public API) | crates/resetprop/src/lib.rs:___ (inside `PropSystem::seal_arena` record push) |

## Anti-Scope (explicitly excluded)

- [ ] AS-01: No per-prop hooking or `__system_property_update` trampoline (P03 / P04 scope) — per P02 spec §Anti-Scope
- [ ] AS-02: No ELF parsing, `DT_SYMTAB` / `DT_GNU_HASH` walk, or `libc.so` base resolution (P03 scope — `seal/elf.rs`) — per P02 spec §Anti-Scope
- [ ] AS-03: No arm64 instruction encoder, trampoline emitter, or lock-list page management (P04 scope — `seal/hook.rs`) — per P02 spec §Anti-Scope
- [ ] AS-04: No CLI surface, `--seal-arena` / `-sla` flag, `print_usage` edits, or `resetprop-cli` changes (P05 scope) — per P02 spec §Anti-Scope
- [ ] AS-05: No persistence of `SealRecord` to `/data/property/`, KSU/Magisk module, or `--replay-seals` command (deferred per plan §Persistence and REGISTRY §1) — per P02 spec §Anti-Scope
- [ ] AS-06: No modification of `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, or `appcompat.rs` (plan §Files modified — "No changes required") — per P02 spec §Anti-Scope
- [ ] AS-07: No file-permission or ownership changes to any `/dev/__properties__/*` inode at any point (REGISTRY §1 "File permissions: Never modified"; prop_area.cpp:63-68, 111-138) — per P02 spec §Anti-Scope
- [ ] AS-08: No remapping of `/dev/__properties__/properties_serial` — the `PropSystem::seal_arena` guard rejects it (REGISTRY §1 "Arenas NOT to touch"; system_properties.cpp:325-333) — per P02 spec §Anti-Scope
- [ ] AS-09: No propdetect signature integration, `propdetect` heuristic changes, or user-facing docs — per P02 spec §Anti-Scope

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment completes. NOT after each segment.

- [ ] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template) with: phase spec path `phases/seal/P02-tier-a.md`, checklist path `phases/seal/checklists/P02-checklist.md`, REGISTRY path `phases/seal/REGISTRY-P.md`, code file paths (`crates/resetprop/src/seal/arena.rs`, `crates/resetprop/src/lib.rs`, `crates/resetprop/src/seal/mod.rs`, `crates/resetprop/tests/tier_a_child_smoke.rs`), branch name `feat/P02-tier-a`, External API Verification flag YES with sources listed in spec
- [ ] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block
- [ ] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block
- [ ] Both agents dispatched IN PARALLEL (single message, two Agent tool calls)
- [ ] Because `External API Verification: YES`, both agents grep'd/read `aosp-android15/bionic/libc/system_properties/prop_area.cpp` and `system_properties.cpp` and quoted real signatures/constants (not paraphrased)
- [ ] Both agents verified the `properties_serial` rejection path (FR-08) by reading the `PropSystem::seal_arena` source
- [ ] Both agents verified the `MAP_PRIVATE|MAP_FIXED` flag is actually used in the remote `mmap` call site (FR-02) — not just named in a doc comment
- [ ] code-reviewer report saved at `phases/seal/audits/P02-audit.md` — verdict: PASS | NEEDS_FIX
- [ ] critic report saved at `phases/seal/audits/P02-audit.md` — verdict: PASS | NEEDS_FIX
- [ ] All CRITICAL findings resolved
- [ ] All MAJOR findings resolved
- [ ] MINOR findings logged (not blocking)
- [ ] Re-ran both agents after fixes; both emitted `VERDICT: PASS`

## Acceptance Gate

- [ ] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes for Optimality / Completeness / Correctness)
- [ ] All 13 FRs verified (each annotated with a file:line)
- [ ] All 10 TCs executed and passing
- [ ] All 7 IVs verified (upstream P01 consumption + downstream P05 readiness)
- [ ] No regressions in prerequisite P01: `cargo test -p resetprop seal::ptrace` exits 0; `cargo test -p resetprop seal::maps` exits 0
- [ ] Branch `feat/P02-tier-a` commits clean; all use conventional commits with `feat(seal):` / `test(seal):` / `docs(seal):` / `refactor(seal):` prefix per REGISTRY §2
- [ ] All 12 canonical values verified with file:line annotation
- [ ] All 9 AS items confirmed not violated
- [ ] Gate 2 reports PASS from BOTH code-reviewer and critic
- [ ] REGISTRY §4 row for "P02 — Tier A: arena-level seal" updated to `COMPLETE`
- [ ] REGISTRY §7 session log appended with session date, outcome, and audit verdict
