# P01: Foundation — ptrace core + maps parser

## Objective

Create the `seal/` module tree's root (`mod.rs`, `maps.rs`, `ptrace.rs`) with a working `/proc/<pid>/maps` parser, typed ptrace attach/detach primitives on `PTRACE_SEIZE`/`PTRACE_INTERRUPT`, a `UserPtRegs` ARM64 register struct whose size is statically asserted at 272 bytes, and a remote-syscall injector that stages `svc #0 ; brk #0` at a caller-supplied scratch PC — all consumed by P02 (Tier A arena), P03/P04 (Tier B hook), and bounded by seven new typed `Error` variants added to `error.rs`.

## Preconditions

- [ ] None (first phase).
- [ ] Files that must exist: `crates/resetprop/src/error.rs`, `crates/resetprop/src/lib.rs`, `crates/resetprop/Cargo.toml`.

## Scope

### Files to CREATE

| File | Purpose |
|------|---------|
| `crates/resetprop/src/seal/mod.rs` | Seal module root — re-exports `MapEntry`, `parse_maps`, `UserPtRegs`, ptrace primitives, `remote_syscall`; defines the `Pid` type alias, the module-private `Seized` RAII guard used by P02/P04, and the public types `SealRecord { name, arena_path, tier, sealed_at }` + `SealTier { Arena, Prop }` (per REGISTRY §1 — consumed by P02/P04) |
| `crates/resetprop/src/seal/maps.rs` | `/proc/<pid>/maps` line parser: `MapEntry { start, end, perms, offset, path }` + `parse_maps(pid) -> Result<Vec<MapEntry>>` + `find_by_path` helper used by P02/P03 for arena/libc.so lookup |
| `crates/resetprop/src/seal/ptrace.rs` | ARM64 ptrace core: `UserPtRegs` (272 B), `ptrace_seize`, `ptrace_interrupt`, `wait_stop`, `getregset`, `setregset`, `ptrace_detach`, `remote_syscall` (stages `svc #0 ; brk #0` and returns `x0`) |

### Files to MODIFY

| File | Changes |
|------|---------|
| `crates/resetprop/src/error.rs` | Add 7 new `Error` variants (`PtraceAttach(std::io::Error)`, `PtraceScope`, `ArenaAlreadySealed(PathBuf)`, `ArenaNotMapped(PathBuf)`, `ElfParse(String)`, `SymbolNotFound(String)`, `HookInstallFailed(String)`) to the enum at lines 5-14; extend the `Display` impl (lines 18-31) with matching arms; extend `Error::source` (lines 33-40) to return `Some(e)` for `PtraceAttach(e)` and `None` for the other six. No change to `From<std::io::Error>`. |
| `crates/resetprop/src/lib.rs` | Add `mod seal;` after line 32 (`mod wait;`) inside the existing module block at lines 21-35; no `pub use` yet (public API lands in P02/P04). |

## Reference Material

Read ONLY these at session start:

| File | Sections | Est. Tokens | Why |
|------|----------|-------------|-----|
| `/home/president/Git-repo-success/resetprop-rs/phases/seal/REGISTRY-P.md` | §1 Locked Decisions, §2 Coding Conventions, §3 Domain Ownership, §6 Key Paths | ~2500 | Locks dependency policy (libc only), module paths, commit scope `feat(seal):`, branch `feat/P01-foundation`, `repr(C)` + size-assert convention for `UserPtRegs` (§2 row 11) |
| `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/linux-arm64-abi.md` | Full file (§1-§12) | ~4000 | Exact syscall numbers (`__NR_openat=56`, `__NR_mmap=222`, `__NR_close=57`, `__NR_getpid=172`), `PTRACE_*` constants, `struct user_pt_regs` 272-byte layout, GETREGSET/SETREGSET iovec pattern, SEIZE+INTERRUPT+waitpid lifecycle, `svc #0 ; brk #0` staging algorithm (§7), `process_vm_readv/writev` signatures (§10), minimal Rust skeleton (§12) |
| `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/resetprop-rs-integration.md` | §3 lib.rs module block (lines 21-35), §4 error.rs pattern (lines 5-49), §14 integration map | ~3200 | Exact insertion point for `mod seal;` (after line 32), `From<io::Error>` and `Error::source` patterns to mirror, dependency order `ptrace.rs → maps.rs → mod.rs` |
| `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/test-harness-patterns.md` | §2 yama gating, §3 sacrificial child + `ChildGuard`, §12 invocation | ~2600 | `#[ignore]` doc-comment form, `--ignored --test-threads=1` rationale, `fork_child` helper, `ChildGuard` RAII reap-on-Drop pattern, why self-ptrace fails (tracer cannot attach to itself) |
| `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h` | Lines 17, 21, 27-31 | ~400 | Authoritative source for `PTRACE_CONT=7`, `PTRACE_DETACH=17`, `PTRACE_GETREGSET=0x4204`, `PTRACE_SETREGSET=0x4205`, `PTRACE_SEIZE=0x4206`, `PTRACE_INTERRUPT=0x4207` — Gate 2 agents must quote from this file |
| `/usr/include/asm-generic/unistd.h` | Lines 158, 160, 461, 570/886 | ~200 | Authoritative source for `__NR_openat=56`, `__NR_close=57`, `__NR_getpid=172`, `__NR_mmap=222` — Gate 2 External API Verification |

## External API Verification

- **Required**: YES
- **Sources to verify against**:
  - `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/ptrace.h` — `PTRACE_CONT`, `PTRACE_DETACH`, `PTRACE_GETREGSET`, `PTRACE_SETREGSET`, `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, `PTRACE_EVENT_STOP`
  - `/home/president/aosp-android15/bionic/libc/kernel/uapi/linux/elf.h` — `NT_PRSTATUS = 1`
  - `/home/president/aosp-android15/bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.h` — `struct user_pt_regs` layout (lines 49-54)
  - `/usr/include/asm-generic/unistd.h` — `__NR_openat`, `__NR_close`, `__NR_mmap`, `__NR_getpid`, `__NR_process_vm_readv`, `__NR_process_vm_writev`
  - `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/linux-arm64-abi.md` — consolidated citations, §Citations table

## Tasks (Max 5 Per Session)

1. **Task 1 — Module skeleton + 7 Error variants + `SealRecord`/`SealTier` types**: Create `crates/resetprop/src/seal/mod.rs` declaring `pub mod maps; pub mod ptrace;` plus module-level re-exports (`pub use maps::{MapEntry, parse_maps}; pub use ptrace::{UserPtRegs, remote_syscall, ptrace_seize, ptrace_interrupt, ptrace_detach, wait_stop, getregset, setregset};`) and a `pub type Pid = libc::pid_t;` alias. Inside `seal/mod.rs` also declare the public types `pub struct SealRecord { pub name: String, pub arena_path: PathBuf, pub tier: SealTier, pub sealed_at: SystemTime }` and `pub enum SealTier { Arena, Prop }` (field layout locked by REGISTRY §1 rows "`SealRecord` fields" and "`SealTier` variants"); these types are created here so P02 (Tier A) and P04 (Tier B) can construct records without any definitional ambiguity. Extend `error.rs:5-14` with the 7 new variants listed in the Scope table; extend `Display` with one `match` arm per variant; extend `Error::source` to surface the `io::Error` inside `PtraceAttach`. Insert `mod seal;` in `lib.rs` after line 32. — Files: `crates/resetprop/src/seal/mod.rs`, `crates/resetprop/src/error.rs`, `crates/resetprop/src/lib.rs` — Verifies: `cargo check -p resetprop` passes; `cargo test -p resetprop --lib error::` continues to pass; `grep -n "mod seal" crates/resetprop/src/lib.rs` reports line 33.
2. **Task 2 — `/proc/<pid>/maps` parser**: Implement `seal/maps.rs` with `pub struct MapEntry { pub start: u64, pub end: u64, pub perms: [u8; 4], pub offset: u64, pub path: Option<PathBuf> }` and `pub fn parse_maps(pid: libc::pid_t) -> Result<Vec<MapEntry>>` that reads `/proc/<pid>/maps` via `std::fs::read_to_string`, splits line-by-line, and decodes hex `start-end perms offset dev inode path` columns. Provide `pub fn find_by_path<'a>(entries: &'a [MapEntry], path: &Path) -> Option<&'a MapEntry>` that matches an exact path (used by P02 for arena lookup and P03 for `libc.so` lookup). Add 3 unit tests: `test_maps_parse_minimal_line` (one-line input with no path), `test_maps_parse_deleted_suffix` (path ending `" (deleted)"` must land inside `path` without the suffix being treated as part of the file), `test_maps_find_by_path_matches`. — Files: `crates/resetprop/src/seal/maps.rs` — Verifies: `cargo test -p resetprop --lib seal::maps` reports 3 passing tests; `cargo check -p resetprop` clean.
3. **Task 3 — ptrace attach/detach + register IO**: Implement `seal/ptrace.rs` constants (`PTRACE_CONT=7`, `PTRACE_DETACH=17`, `PTRACE_GETREGSET=0x4204`, `PTRACE_SETREGSET=0x4205`, `PTRACE_SEIZE=0x4206`, `PTRACE_INTERRUPT=0x4207`, `NT_PRSTATUS=1`, `ARM64_SVC_0=0xd4000001`, `ARM64_BRK_0=0xd4200000`) and the `UserPtRegs` struct: `#[repr(C)] #[derive(Clone, Copy, Default)] pub struct UserPtRegs { pub regs: [u64; 31], pub sp: u64, pub pc: u64, pub pstate: u64 }` guarded by `const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);`. Implement `pub fn ptrace_seize(pid)`, `pub fn ptrace_interrupt(pid)`, `pub fn wait_stop(pid) -> Result<i32>` (returns the raw wait status; verifies `WIFSTOPPED && WSTOPSIG == SIGTRAP`), `pub fn getregset(pid) -> Result<UserPtRegs>`, `pub fn setregset(pid, regs: &UserPtRegs) -> Result<()>` (both using `iovec { iov_len: 272 }` with `NT_PRSTATUS`), `pub fn ptrace_detach(pid) -> Result<()>`. Every failing `libc::ptrace` call maps to `Error::PtraceAttach(io::Error::last_os_error())`; failures whose `errno == EPERM` on the initial `SEIZE` map to `Error::PtraceScope` after a fallback read of `/proc/sys/kernel/yama/ptrace_scope`. Each `unsafe` block carries a `// SAFETY:` comment per REGISTRY §2 row 12. — Files: `crates/resetprop/src/seal/ptrace.rs` — Verifies: `cargo check -p resetprop` clean; `cargo test -p resetprop --lib seal::ptrace::size_assert` passes (compile-time assert); `rustc --print cfg | grep target_arch=\"aarch64\"` optional — constants compile on any arch but the size assert trips on non-arm64 hosts, so wrap the assert in `#[cfg(target_arch = "aarch64")]`.
4. **Task 4 — `remote_syscall` injector**: In `seal/ptrace.rs` add `pub unsafe fn remote_syscall(pid: Pid, scratch_pc: u64, syscall_no: u64, args: [u64; 6]) -> Result<i64>`. Algorithm per linux-arm64-abi.md §7: (a) `process_vm_readv` 8 bytes at `scratch_pc` into a `[u8; 8]` save buffer; (b) `process_vm_writev` the 8-byte payload `[0x01,0x00,0x00,0xd4, 0x00,0x00,0x20,0xd4]` to `scratch_pc`; (c) `getregset(pid)` → `saved`; (d) build `work = saved` with `work.pc = scratch_pc`, `work.regs[8] = syscall_no`, `work.regs[0..6].copy_from_slice(&args)`; (e) `setregset(pid, &work)`; (f) `libc::ptrace(PTRACE_CONT, pid, 0, 0)`; (g) `wait_stop(pid)` expecting brk-trap (WIFSTOPPED && WSTOPSIG==SIGTRAP && event==0); (h) `getregset` and read `ret = out.regs[0] as i64`; (i) `setregset(pid, &saved)` to restore; (j) `process_vm_writev` the save buffer back to `scratch_pc`. Thin helpers `read_remote(pid, addr, &mut buf)` and `write_remote(pid, addr, &buf)` wrap `process_vm_readv`/`process_vm_writev` with partial-transfer loops per linux-arm64-abi.md §10. — Files: `crates/resetprop/src/seal/ptrace.rs` — Verifies: `cargo check -p resetprop` clean; no unit test at this layer (exercised by Task 5 integration test).
5. **Task 5 — `ptrace_core_smoke.rs` integration test**: Create `crates/resetprop/tests/ptrace_core_smoke.rs` following test-harness-patterns.md §3: a `fork_child` helper and `ChildGuard` (`Drop` sends `SIGKILL` + `waitpid`). Single test `remote_getpid_returns_child_pid` marked `#[ignore = "requires ptrace_scope<=1; run with cargo test --test ptrace_core_smoke -- --ignored --test-threads=1"]`. Body: (1) parent mmaps an anonymous `PROT_READ|PROT_WRITE|PROT_EXEC` page at a known address (for the child to inherit via COW after fork), writes `svc #0 ; brk #0` into it; (2) `fork_child` child body mmaps that same page (or relies on COW inheritance), then enters a `loop { libc::pause(); }`; (3) parent `ptrace_seize` + `ptrace_interrupt` + `wait_stop`; (4) `remote_syscall(child_pid, scratch_pc, __NR_getpid=172, [0;6])`; (5) assert `ret == child_pid as i64`; (6) `ptrace_detach`; `ChildGuard::drop` reaps. Top-of-file doc-comment documents the runner invocation and the CAP_SYS_PTRACE / `/proc/sys/kernel/yama/ptrace_scope` preconditions. — Files: `crates/resetprop/tests/ptrace_core_smoke.rs` — Verifies: `cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1` reports `1 passed` when run with `ptrace_scope <= 1`; `cargo test -p resetprop --test ptrace_core_smoke` (without `--ignored`) reports `0 passed; 1 ignored`.

## Approach

1. **Dependency order drives file creation order.** Implement in the order `ptrace.rs → maps.rs → mod.rs → error.rs additions → lib.rs insertion → integration test`, which mirrors the compile-order table at resetprop-rs-integration.md §14. `ptrace.rs` has no intra-module deps; `maps.rs` has no intra-module deps; `mod.rs` re-exports from both. The integration test imports only `resetprop::seal::{ptrace::*, maps::*}`.
2. **Single-dep policy (REGISTRY §1 row 2).** No `nix`, no `goblin`. Raw `libc::ptrace`, raw `libc::process_vm_readv`/`process_vm_writev`, `std::fs::read_to_string` for `/proc/<pid>/maps`. The three new source files compile against `libc = "0.2"` alone.
3. **Error ergonomics.** `Error::PtraceAttach(std::io::Error)` wraps the raw `errno` from failing ptrace calls so CLI error output (`eprintln!("resetprop: {e}")` at `crates/resetprop-cli/src/main.rs:10`) stays consistent. `Error::PtraceScope` is the pre-classified variant the CLI can match on to suggest `echo 0 > /proc/sys/kernel/yama/ptrace_scope`. The remaining five variants (`ArenaAlreadySealed`, `ArenaNotMapped`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`) are declared here but only raised by P02/P03/P04 — P01 must not `return Err` with any of them (REGISTRY §3 Domain Ownership splits responsibility).
4. **`UserPtRegs` layout guard.** `const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);` under `#[cfg(target_arch = "aarch64")]` — the assert is the tripwire if a contributor accidentally pads or reorders fields (REGISTRY §2 row 11). Non-arm64 hosts skip the assert so `cargo check` on x86_64 dev boxes still passes; the integration test is already ptrace-gated.
5. **Scratch PC strategy for the smoke test.** Pre-mmap an anonymous RWX page in the parent before `fork()` so the address is inherited by the child. No need to hunt `libc.so` padding or bootstrap a remote `mmap` in P01 — that bootstrap is P03/P04 scope. The test exists to prove the injector round-trips a real syscall; real init attachment is P05's on-device validation.
6. **Safety comments.** Every `unsafe` block in `ptrace.rs` (ptrace FFI, `process_vm_*` FFI, size-assert dereference) prepends a `// SAFETY:` line explaining the invariant (matches REGISTRY §2 row 12). The audit agents will scan for missing comments in Gate 2.
7. Branch: `feat/P01-foundation` (per REGISTRY §2, single branch across segments).

## Validation

```bash
# All three new modules compile and the library builds unchanged.
cargo check -p resetprop
cargo build -p resetprop --release

# New unit tests pass; existing tests unaffected.
cargo test -p resetprop --lib seal::maps                # 3 new tests pass
cargo test -p resetprop --lib                           # all existing tests still pass
cargo test -p resetprop --lib error::                   # Display + source extended

# Integration test compiles and is listed as ignored by default.
cargo test -p resetprop --test ptrace_core_smoke        # 0 passed; 1 ignored

# Manual ptrace gate (requires /proc/sys/kernel/yama/ptrace_scope <= 1 or CAP_SYS_PTRACE).
cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1
# Expected: test remote_getpid_returns_child_pid ... ok

# Binary-size guard (REGISTRY §2 row 17).
ls -l target/release/libresetprop.rlib                  # size growth bounded (no new deps)
```

## Anti-Scope

- No arena remap / `MAP_PRIVATE|MAP_FIXED` remote mmap (P02 scope).
- No ELF64 parsing, `PT_DYNAMIC` walk, `DT_SYMTAB` / `DT_GNU_HASH` resolution (P03 scope).
- No hook-page allocation, ARM64 trampoline encoding, lock-list layout, `__system_property_update` symbol lookup (P04 scope).
- No CLI flags (`-sl`, `-sla`, `--seals`, `--unseal`, `--unseal-arena`), no `print_usage()` edits (P05 scope).
- No `PropSystem::seal`, `seal_arena`, `unseal`, `unseal_arena`, `seals` public API surface — these methods are introduced by P02 and P04 (P02/P04 scope).
- `SealRecord`, `SealTier` types ARE declared in this phase (Task 1) per REGISTRY §1 row "`SealRecord` and `SealTier` types created by P01"; P02 and P04 consume them. No `seal_arena` public API surface — that lands in P02.
- No persistence: no disk writes for seal state (deferred release-wide per REGISTRY §1 row 15).
- No propdetect heuristics for Tier A / Tier B signatures (noted in plan §Touchpoints, not scoped to v1).
- No changes to `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, `appcompat.rs`, `bionic.rs`, `context.rs`, `wait.rs`, `harvest.rs`, `dict.rs`, `inspect.rs`, `mock.rs` — P01 is purely additive to `seal/` + two touch-ups to `error.rs` and `lib.rs`.
