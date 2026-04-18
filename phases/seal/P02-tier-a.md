# P02: Tier A — Arena-Level Seal via Remote MAP_PRIVATE|MAP_FIXED

## Objective

Implement the Tier A arena-wide seal: attach to init (PID 1), locate its
writable mapping of a telephony property arena, and remap that range as
`MAP_PRIVATE|MAP_FIXED` in init's address space so init's future writes
become copy-on-write and never propagate to other processes. Expose the
behaviour through two new public `PropSystem` methods (`seal_arena` /
`unseal_arena`) and prove correctness with a forked-child integration
smoke test.

## Preconditions

- [ ] P01 (Foundation: ptrace + maps) shows COMPLETE in REGISTRY §4
- [ ] `crates/resetprop/src/seal/mod.rs` exists and declares `pub mod ptrace;` and `pub mod maps;`
- [ ] `crates/resetprop/src/seal/ptrace.rs` exports `remote_syscall`, attach/detach helpers, and `UserPtRegs` (per REGISTRY §1 — "Remote syscall path: ptrace SEIZE + INTERRUPT ... GETREGSET/SETREGSET with NT_PRSTATUS iovec")
- [ ] `crates/resetprop/src/seal/maps.rs` exports `parse_maps(pid) -> Result<Vec<MapEntry>>` and `MapEntry { start, end, perms, path }`
- [ ] `crates/resetprop/src/error.rs` carries the 7 new variants introduced in P01 (`PtraceAttach`, `PtraceScope`, `ArenaAlreadySealed`, `ArenaNotMapped`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`) — per `resetprop-rs-integration.md §4`
- [ ] Files that must exist: `crates/resetprop/src/lib.rs`, `crates/resetprop/src/context.rs`, `crates/resetprop/src/appcompat.rs`, `crates/resetprop/src/area.rs`

## Scope

### Files to CREATE

| File | Purpose |
|------|---------|
| `crates/resetprop/src/seal/arena.rs` | Tier A implementation: `find_arena_mapping`, `remote_remap_private`, `seal_arena`, `unseal_arena`. Pure `libc` FFI built on `seal::ptrace` + `seal::maps`. |
| `crates/resetprop/tests/tier_a_child_smoke.rs` | Forked-child integration test proving the remote remap blocks subsequent writes from reaching the backing file. `#[ignore]`-gated; serial runner. |

### Files to MODIFY

| File | Changes |
|------|---------|
| `crates/resetprop/src/seal/mod.rs` | Add `pub mod arena;` declaration. `SealRecord` and `SealTier` types are defined by P01; P02 constructs `SealTier::Arena` records only. Expose `SEALS: OnceLock<Mutex<Vec<SealRecord>>>` registry accessor. |
| `crates/resetprop/src/lib.rs` | Add two new `PropSystem` methods — `seal_arena(&self, name, value) -> Result<SealRecord>` and `unseal_arena(&self, name) -> Result<bool>` — adjacent to `set_stealth_persist` at `lib.rs:497`. No changes to existing methods. |

## Reference Material

Read ONLY these at session start:

| File | Sections | Est. Tokens | Why |
|------|----------|-------------|-----|
| `phases/seal/references/aosp-property-system.md` | §3 Update call trace, §7 map_prop_area_rw, §8 map_fd_ro, §10 appcompat mirror, §11 properties_serial, §13 Tier A checklist, §15 addresses-touched table | ~4500 | Grounds every AOSP claim: init mmaps RW + MAP_SHARED, file perms must stay 0644 root:root, appcompat mirror lives in same arena family, `properties_serial` is the global wake channel and MUST stay shared. |
| `phases/seal/references/linux-arm64-abi.md` | §1 syscall numbers, §2 calling convention, §4 PTRACE requests, §6 attach/detach lifecycle, §7 staging svc #0, §11 failure modes, §12 minimal skeleton | ~3800 | Remote `openat`/`mmap`/`close` syscall sequence; register layout for `UserPtRegs`; `scratch_pc` restoration contract; `EPERM`/`ESRCH` decoding. |
| `phases/seal/references/resetprop-rs-integration.md` | §3 PropSystem methods (lib.rs:497 anchor), §4 Error pattern, §6 PropArea::privatize (area.rs:230-260), §8 PropertyContext::resolve (context.rs:367-376), §9 AppcompatAreas::mirror_for (appcompat.rs:49-51) | ~3100 | Exact integration anchors: mirror the local `privatize` flag recipe (`MAP_PRIVATE|MAP_FIXED` at area.rs:247), reuse `resolve` to get the arena filename, call `mirror_for` to detect the appcompat mirror. |
| `phases/seal/references/test-harness-patterns.md` | §2 yama gating, §3 sacrificial child + ChildGuard, §4 full Tier A skeleton, §10 temp-file + signal-safe cleanup, §12 runner invocation | ~3400 | Copy-ready fork helper, `#[ignore]` rationale, `--test-threads=1` invariant, exact MAP_SHARED reader vs child's MAP_SHARED writer topology. |
| `/home/president/aosp-android15/bionic/libc/system_properties/prop_area.cpp` | Lines 47-50 (constants), 55-109 (map_prop_area_rw), 111-138 (map_fd_ro), 60-68 (EACCES abort) | ~600 | External-API verification source of truth: init's init-side open flags, the exact stat checks `map_fd_ro` applies, and the EACCES abort that makes file-perm modification lethal. |

## External API Verification

- **Required**: YES
- **Sources to verify against**:
  - `/home/president/aosp-android15/bionic/libc/system_properties/prop_area.cpp` — `map_prop_area_rw` (lines 55-109), `map_fd_ro` (lines 111-138), EACCES abort (lines 63-68), constants (lines 47-50)
  - `/home/president/aosp-android15/bionic/libc/system_properties/system_properties.cpp` — `Update` path lines 270-336 (dirty_backup copy, serial bump, futex wake), appcompat mirror writes (lines 278-296, 305-315), `properties_serial` global wake (lines 325-333)
  - `phases/seal/references/aosp-property-system.md` — derived summary (§3, §7, §8, §10, §11)
  - `phases/seal/references/linux-arm64-abi.md` — `__NR_openat=56`, `__NR_mmap=222`, `__NR_close=57`, `svc #0 = 0xD4000001`, `NT_PRSTATUS=1`, `user_pt_regs = 272 B`
  - `/home/president/Git-repo-success/resetprop-rs/crates/resetprop/src/area.rs` lines 230-260 — local `PropArea::privatize` precedent (same `MAP_PRIVATE|MAP_FIXED` recipe, local-process version)

Gate 2 agents MUST grep these sources and quote actual bytes / flag values before emitting PASS.

## Tasks (Max 5 Per Session)

1. **Task 1 — `find_arena_mapping`**: In `crates/resetprop/src/seal/arena.rs`, implement `fn find_arena_mapping(pid: libc::pid_t, arena_path: &Path) -> Result<MapEntry>` that calls `seal::maps::parse_maps(pid)` and returns the first entry whose `path` equals `arena_path` and whose `perms` starts with `"rw"` (init's writable view). Return `Error::ArenaNotMapped(arena_path.to_path_buf())` when no matching entry exists, and a distinct error (reuse `ArenaNotMapped` with the same payload; a comment documents the fallback) if the only match has perms starting with `"r-"` (read-only view, meaning caller targeted the wrong PID). Unit-test via a pure string-input variant `find_arena_mapping_in(parsed: &[MapEntry], arena_path: &Path) -> Result<MapEntry>` so the parse step stays in `maps.rs`. — Files: `crates/resetprop/src/seal/arena.rs` — Verifies: `cargo test -p resetprop seal::arena::tests::find_arena_mapping_picks_rw_view` passes; `find_arena_mapping_in` returns `ArenaNotMapped` when given a fixture with only an `r-xp` mapping for the same path.

2. **Task 2 — `remote_remap_private`**: Implement `unsafe fn remote_remap_private(pid: libc::pid_t, mapping: &MapEntry, arena_path: &Path) -> Result<()>` in the same file. Attach via `seal::ptrace::attach` (SEIZE + INTERRUPT + `waitpid(__WALL)`), stage `svc #0; brk #0` at a scratch PC via `seal::ptrace::stage_svc`, run `remote_syscall(pid, scratch_pc, __NR_openat=56, [AT_FDCWD as u64, path_ptr, (O_RDONLY|O_NOFOLLOW) as u64, 0, 0, 0])` to get a remote fd, then `remote_syscall(pid, scratch_pc, __NR_mmap=222, [mapping.start, mapping.end - mapping.start, (PROT_READ|PROT_WRITE) as u64, (MAP_PRIVATE|MAP_FIXED) as u64, remote_fd as u64, 0])` and finally `remote_syscall(pid, scratch_pc, __NR_close=57, [remote_fd as u64, 0, 0, 0, 0, 0])`. Use a guard type `RemoteSyscallGuard` with `Drop` that always runs `seal::ptrace::restore_scratch` + `seal::ptrace::detach` so registers and the 8 staged bytes at `scratch_pc` are restored even on `?`-propagated error returns. The remote `mmap` return value must equal `mapping.start`; any other return is wrapped in `Error::SealArenaError` (or reuse of the closest existing variant). — Files: `crates/resetprop/src/seal/arena.rs` — Verifies: hand-traced register tape in doc comment matches linux-arm64-abi.md §12 skeleton; `cargo build -p resetprop` compiles clean; guard exists (grep `impl Drop for RemoteSyscallGuard`).

3. **Task 3 — `seal_arena` / `unseal_arena` orchestrators**: Implement `pub fn seal_arena(pid: libc::pid_t, arena_path: &Path) -> Result<()>` as `find_arena_mapping(pid, arena_path)?` then `unsafe { remote_remap_private(pid, &mapping, arena_path) }`. Implement `pub fn unseal_arena(pid: libc::pid_t, arena_path: &Path) -> Result<()>` with the same shape except the `mmap` call uses `MAP_SHARED|MAP_FIXED = 0x11` over an RW-opened fd (`__NR_openat` with `O_RDWR|O_NOFOLLOW = 0x20002`) to restore init's original view. Both functions accept an optional secondary path via a thin wrapper `seal_arena_with_mirror(pid, primary, mirror: Option<&Path>)` that iterates `[primary, mirror]` — keeping the single-path entry point for callers that already know there is no mirror. Neither function opens the file on the parent side; all fd acquisition is remote. — Files: `crates/resetprop/src/seal/arena.rs` — Verifies: public items compile; `cargo doc -p resetprop --no-deps` emits entries for both functions.

4. **Task 4 — `PropSystem::seal_arena` / `PropSystem::unseal_arena`**: In `crates/resetprop/src/lib.rs`, insert the two new methods immediately after `set_stealth_persist` at `lib.rs:497`. `seal_arena(&self, name: &str, value: &str) -> Result<SealRecord>` does, in order: (a) `self.set_stealth(name, value)?` (existing path at `lib.rs:458`); (b) resolve the primary arena filename via `self.context.as_ref()?.resolve(name)` (`context.rs:367-376`), join with `/dev/__properties__/` — or `self.open_dir`'s recorded base — to form the full path; (c) **reject immediately** with `Error::InvalidKey` if the resolved path equals `/dev/__properties__/properties_serial` (REGISTRY §1 "Arenas NOT to touch"); (d) probe for the appcompat mirror via `self.appcompat.as_ref().and_then(|a| a.mirror_for(filename))` (`appcompat.rs:49-51`) — if present, capture its path; (e) call `seal::arena::seal_arena(1, primary_path)`; (f) if mirror path captured, call `seal::arena::seal_arena(1, mirror_path)`; (g) push a `SealRecord { name: name.to_string(), arena_path: primary_path, tier: SealTier::Arena, sealed_at: SystemTime::now() }` into an `OnceLock<Mutex<Vec<SealRecord>>>` held as a module-level static in `seal::mod`, guarded against duplicate names by a linear scan; (h) return the record. `unseal_arena(&self, name: &str) -> Result<bool>` mirrors the flow: resolve + mirror detect + call `seal::arena::unseal_arena(1, ...)` for each path + remove matching `SealRecord`s; returns `Ok(false)` if no record existed. Never chmod or ftruncate the arena file at any point (REGISTRY §1 "File permissions: Never modified"). — Files: `crates/resetprop/src/lib.rs`, `crates/resetprop/src/seal/mod.rs` — Verifies: `cargo test -p resetprop seal::tests::seal_arena_rejects_properties_serial` passes; `cargo test -p resetprop seal::tests::seal_record_roundtrip` passes (the record makes it into the static vec and is retrievable).

5. **Task 5 — Integration smoke test `tier_a_child_smoke.rs`**: Create `crates/resetprop/tests/tier_a_child_smoke.rs` following `test-harness-patterns.md §4` verbatim-structure. The test: (a) creates a `tempfile::NamedTempFile` sized to 4 × 4096 bytes; (b) pre-writes `SENTINEL_PRE = 0xAA` at byte offset 128; (c) forks a child that `mmap`s the file `MAP_SHARED|PROT_READ|PROT_WRITE`, then enters a loop writing `SENTINEL_POST = 0xBB` at offset 128 every 10 ms via `std::ptr::write_volatile`; (d) parent sleeps 100 ms, opens the file through a second independent `std::fs::OpenOptions::read(true).open(...)` (the "third observer" read path), reads one byte from offset 128, and asserts it equals `SENTINEL_POST` (baseline: pre-seal MAP_SHARED propagation works); (e) parent calls `resetprop::seal::arena::seal_arena(guard.pid(), tmp.path())`; (f) parent overwrites the on-disk byte back to `SENTINEL_PRE` with a plain `File::write_all`; (g) parent sleeps 200 ms; (h) parent re-reads via the independent reader and asserts the byte is still `SENTINEL_PRE` — child's post-seal writes never reached the file. Cleanup is a `ChildGuard(pid)` struct whose `Drop` calls `libc::kill(pid, SIGKILL)` then `waitpid(pid, _, WNOHANG)` + blocking `waitpid(pid, _, 0)`. Decorate with `#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]`. Include a doc-header comment block that documents the runner: `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1`. — Files: `crates/resetprop/tests/tier_a_child_smoke.rs` — Verifies: `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1` exits 0 on a Linux host with `/proc/sys/kernel/yama/ptrace_scope <= 1`; default `cargo test -p resetprop` still passes (test is `#[ignore]`-skipped).

## Approach

1. **Exact AOSP fidelity, one flag swap.** The remote `mmap` is `map_prop_area_rw`'s `PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0` recipe (prop_area.cpp:99) with `MAP_SHARED` replaced by `MAP_PRIVATE`. Every other flag matches because init already validated them; we do not need to re-derive them. This keeps the seal's footprint on init's internal state to one VMA flag bit flip. Citation: `aosp-property-system.md §7 map_prop_area_rw` + `area.rs:230-260` local precedent.
2. **Never modify file permissions on the arena.** `map_fd_ro` (prop_area.cpp:111-138) rejects any arena whose `st_uid != 0`, `st_gid != 0`, or mode bits include `S_IWGRP|S_IWOTH`. Init's `map_prop_area_rw` aborts on `EACCES` (prop_area.cpp:63-68). Consequence: `seal_arena` must never `chmod`, `fchmod`, or `fchown` the arena file — doing so would lock every reader out and deadlock init on its next reload. The seal is strictly a VMA-private overlay inside init's address space; the inode on `/dev/__properties__/` stays root:root 0644 throughout (REGISTRY §1).
3. **Never privatize `properties_serial` (MUST).** `SystemProperties::Update` bumps `serial_pa->serial()` and calls `__futex_wake(serial_pa->serial(), INT32_MAX)` (system_properties.cpp:325-333). That counter lives in a separate file, `/dev/__properties__/properties_serial`, and it is the global wake channel that every property reader polls. Privatizing it leaves init's increments stranded on a private page and breaks system-wide property-change notifications. `PropSystem::seal_arena` MUST reject any name whose `PropertyContext::resolve` returns the `properties_serial` arena filename with `Error::InvalidKey` BEFORE any ptrace work begins. Citation: REGISTRY §1 row "Arenas NOT to touch"; `aosp-property-system.md §11 properties_serial — Global Notification Channel`.
4. **Appcompat mirror must be sealed in the same call.** For Android 14+, `Update` writes both the main `prop_info` and the mirror `prop_info` in `/dev/__properties__/appcompat_override/<ctx>` (system_properties.cpp:278-296, 305-315). Sealing only the primary would leave the mirror as a live write target that leaks the un-sealed value to apps that read the override area. Detection uses `self.appcompat.as_ref().and_then(|a| a.mirror_for(filename))` (appcompat.rs:49-51); when the mirror exists, we seal it under the same `seal_arena` call before returning the `SealRecord`. Citation: `aosp-property-system.md §10 Appcompat Override — Mirror Writes`.
5. **Remote syscall guard ensures atomic rollback on error.** `remote_remap_private` stages an `svc #0; brk #0` blob at a scratch PC in init's text, saves `UserPtRegs`, then issues three remote syscalls. A Rust guard type (`RemoteSyscallGuard`) owns the `(pid, saved_regs, scratch_pc, saved_bytes)` tuple; its `Drop` impl runs the restore sequence unconditionally. This mirrors the `linux-arm64-abi.md §7` "Save/restore 8 bytes (not 4)" rule — the stager wrote `svc + brk`, so we restore eight. If any of `openat` / `mmap` / `close` fails mid-sequence, the guard still detaches cleanly and init is never left with corrupted scratch bytes. Errors propagate via `?` with the wall-clock cost of one extra REGSET restore.
6. **In-memory `SealRecord` registry only; no disk persistence.** Per REGISTRY §1 "Persistence: Deferred for v1 — in-memory `SealRecord` only" and plan §Decisions locked for this release. The registry is a `OnceLock<Mutex<Vec<SealRecord>>>` module-level static in `seal/mod.rs`; `PropSystem::seal_arena` pushes on success, `PropSystem::unseal_arena` removes by name. No `std::fs` writes, no `persist/mod.rs` coupling. A follow-up release (outside v1 scope per REGISTRY §1 Persistence row) can layer `--replay-seals` on top of the same vec shape without touching Tier A.
7. **Integration test isolates the MAP_SHARED→MAP_PRIVATE transition via a third reader.** Reading the backing file through an independent `File::open` is the cleanest proof-of-isolation: we are not inspecting init's maps (which requires ptrace in the test) or the child's writes (which requires `process_vm_readv`). A plain `pread` on the inode sees whatever the child's MAP_SHARED mapping wrote — until we remap it MAP_PRIVATE, after which the child's subsequent writes are COW'd into a private page and the inode's bytes stay at whatever the parent last wrote. This is the same isolation check an operator runs on a live device with `getprop` after `seal_arena` (plan §Verification — Test 22).
8. **Branch: `feat/P02-tier-a` (per REGISTRY §2).**

## Validation

```bash
# Off-device: library builds clean with the new arena module.
cargo build -p resetprop

# Off-device: unit tests (includes the find_arena_mapping string-input variant).
cargo test -p resetprop seal::arena

# Off-device: the in-memory registry round-trip test.
cargo test -p resetprop seal::tests

# Off-device: integration smoke test — requires ptrace_scope<=1 on the host.
cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1

# Formatting + lints stay green for the new files.
cargo fmt --check
cargo clippy -p resetprop -- -D warnings
```

Prose assertions for the smoke test:

- Pre-seal: an independent reader observes the child's `0xBB` sentinel byte (MAP_SHARED works).
- Post-seal: parent overwrites the on-disk byte to `0xAA`, sleeps 200 ms while the child keeps writing `0xBB`, and the reader still sees `0xAA`. This proves the remote MAP_PRIVATE remap isolated the child's writes.
- No zombie child is left behind: `ChildGuard::drop` runs on both success and panic paths.

## Anti-Scope

- AS-01: No per-prop hooking or `__system_property_update` trampoline (P03 / P04 scope).
- AS-02: No ELF parsing, `DT_SYMTAB` / `DT_GNU_HASH` walk, or `libc.so` base resolution (P03 scope — `seal/elf.rs`).
- AS-03: No arm64 instruction encoder, trampoline emitter, or lock-list page management (P04 scope — `seal/hook.rs`).
- AS-04: No CLI surface, `--seal-arena` / `-sla` flag, `print_usage` edits, or `resetprop-cli` changes (P05 scope).
- AS-05: No persistence of `SealRecord` to `/data/property/`, KSU/Magisk module, or `--replay-seals` command (deferred per plan §Persistence and REGISTRY §1 "Persistence: Deferred for v1").
- AS-06: No modification of `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, or `appcompat.rs` (plan §Files modified — "No changes required").
- AS-07: No file-permission or ownership changes to any `/dev/__properties__/*` inode at any point in the flow (REGISTRY §1 "File permissions: Never modified"; prop_area.cpp:63-68, 111-138).
- AS-08: No remapping of `/dev/__properties__/properties_serial` — the guard at `PropSystem::seal_arena` rejects it outright (REGISTRY §1 "Arenas NOT to touch"; system_properties.cpp:325-333).
- AS-09: No propdetect signature integration, `propdetect` heuristic changes, or user-facing docs (deferred per plan §Decisions locked).
