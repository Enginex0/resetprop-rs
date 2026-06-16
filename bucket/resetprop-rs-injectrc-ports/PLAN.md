# resetprop-rs — injectrc capability ports

## Context

### What this plan covers

Four discrete capability ports from `5ec1cff/injectrc` (cloned at `/home/president/Git-repo-success/Phantom-veil/injectrc/`) into `resetprop-rs/crates/resetprop/src/seal/`. Each port lands an independent improvement; together they harden the seal subsystem against OEM SELinux divergence, add observability that today does not exist, unlock future hook targets beyond bionic exports, and widen device coverage beyond arm64.

### Why these four (and not the other four)

Of the eight injectrc techniques surveyed this session, four were ruled out as not applicable to resetprop-rs's model:

1. `epoll_pwait` syscall-stop sync (`injector.cpp:47-48`) — your `RemoteAttach` SEIZE+INTERRUPT + `getregset` snapshot/restore at `seal/arena.rs:318, 373` already gives deterministic register state.
2. openat-intercept race-write (`injector.cpp:264-289`) — pattern specific to feeding init's `Parser::ParseConfig` a memfd path; your `write_remote` writes hook bytes directly.
3. `android_dlopen_ext` with `USE_LIBRARY_FD | FORCE_LOAD` (`injector.cpp:186-189`) — they load a full .so with `DT_INIT`; your trampoline is 140-byte raw shellcode at `seal/hook.rs:1008` with no dynamic-linker involvement.
4. `RemoteAttach` RAII guard equivalent (`injector.cpp:40-44` `run_finally`) — already present at `seal/arena.rs:190-231`.

The four selected ports are below, in recommended sequencing order.

---

## Known defects in the current seal subsystem (discovered 2026-06-16)

Found during a head-to-head ptrace-injection audit of the seal engine against
ReZygisk's `loader/src/ptracer/`. These are **independent of the four ports
below** — they exist in the shipped Tier B path today. Fix them before the
on-device Tier B acceptance gate (P05); nothing in off-device CI exercises them.

### Defect A — Tier B lock-list `.advance` walker mis-encoded (CONFIRMED, HIGH)

`HOOK_BODY_TEMPLATE` word 22 at `seal/hook.rs:875` is `0x3841_054b`, commented
`ldrb w11, [x10], #1`, but the post-index immediate `imm9` (bits [20:12])
decodes to **16** — i.e. `ldrb w11, [x10], #16`. The correct encoding is
`0x3840_154b` (LE bytes `4b 15 40 38`; the template ships `4b 05 41 38`).

- **Effect**: the `.advance` "scan past this entry's NUL" loop steps `x10` by
  **16 bytes per byte** instead of 1, overshooting every lock-list entry
  boundary. The outer `.next_entry` loop then misaligns, compares garbage, and
  can run off the 1024-byte lock-list region past the sentinel. **Tier B
  per-property seal is broken for any lock list with more than one entry** (a
  single-entry non-match only "works" by landing in the zero-filled tail).
- **Why CI stays green**: the unit test
  `build_hook_body_bytes_advance_block_scans_past_nul` at `seal/hook.rs:1874`
  asserts the **same wrong constant**, so template→bytes→assert round-trips and
  cannot catch it. Tier B functional acceptance is deferred to the on-device P05
  run, so nothing exercises the real walk off-device.
- **Scope**: lone bad word — words 0,1,7,8,9,10,11,20,21 and the 13-word STRCMP
  inner loop are all verified correct.
- **Fix**: set the constant at `seal/hook.rs:875` to `0x3840_154b` AND correct
  the asserted constant in the test at `seal/hook.rs:1874`. One-line
  `fix(seal):` change.
- **Status**: UNFIXED as of 2026-06-16.

### Defect B — no thread-group stop; init's sibling threads run live through the Tier B patch (HIGH, design)

`RemoteAttach::new` (`seal/arena.rs:203-206`) does `PTRACE_SEIZE` +
`PTRACE_INTERRUPT` on **PID 1 only** and never enumerates `/proc/1/task/*`.
Linux ptrace is per-**thread**: seizing the thread-group leader stops only that
one thread, so init's sibling threads keep running for the whole attach window.

- **Effect**: if another init thread calls `__system_property_update` after the
  trampoline's low word lands (`seal/hook.rs:1129`) but before the i-cache
  `membarrier` SYNC_CORE (`seal/hook.rs:1187`) — or mid lock-list write — it can
  fetch a half-patched / stale-i-cache instruction stream and crash or corrupt
  **PID 1** (→ kernel panic / bootloop). `wait_stop(__WALL)` reaps only the
  seized thread.
- **Contrast**: ReZygisk never hits this — it injects into a freshly-`execve`'d
  zygote that is single-threaded by construction; it never patches live init.
- **Note**: Tier A (`MAP_FIXED` arena remap) is largely immune — a fixed remap
  is atomic, no torn instructions. This is specifically a Tier B
  trampoline-patch hazard.
- **Fix**: before any Tier B text patch, enumerate `/proc/1/task/*` and
  `SEIZE`+`INTERRUPT` every thread (resume all on completion) so init is fully
  frozen across the poke→i-cache-sync window.
- **Status**: UNFIXED as of 2026-06-16.

### Minor — bootstrap-page leak on arena cold-error paths

On early error paths between the bootstrap-page `mmap` and the final `munmap`
(e.g. path-too-long at `seal/arena.rs:418`, openat failure at `:441`), the 4 KiB
bootstrap page is not freed before return — a bounded 4 KiB leak in init on cold
paths only. The success path frees it (`:491-498`).

---

## Port 1 — memfd_create + setfilecon SELinux relabel

### Current state

`seal/hook.rs:434-577` implements the file-backed hook page via a three-step disk dance:

1. `write_host_hook_file` (`:451`) writes `hook-<pid>-<nanos>.bin` under `HOOK_FILE_DIR = "/data/adb/resetprop-rs"` (`:58`).
2. `mmap_file_backed_in_tracee` (`:492`) has init `openat()` the host path, `mmap()` it `PROT_R|X`, then `close()`.
3. The host file is `remove_file`'d (`:442`) immediately after mmap; init retains the mapping via the deleted-inode mechanism.

The host-file directory dependency is the load-bearing risk. The comment at `:312-316` makes it explicit: this works only because `adb_data_file:file { execute map }` is in init's SELinux allow list. If a future OEM strips that allow (the policy change is local and reasonable), `mmap_file_backed_in_tracee` fails with EACCES and Tier B install dies.

### What changes

Replace the host-file path with the injectrc memfd pattern (`injector.cpp:60-71`):

1. Remote `memfd_create("phantom-veil-hook", MFD_CLOEXEC)` inside init via existing `remote_syscall_via_poke`.
2. From the host, open `/proc/1/fd/<remote_fd>` and `fwrite` the 4 KiB hook page bytes.
3. Apply `setfilecon` to `/proc/1/fd/<remote_fd>` setting the SELinux context to match `/system/lib64/libc.so`'s file context (the relabel — `injector.cpp:183`, impl at `ptrace_utils.cpp:744-755`).
4. Remote `mmap(NULL, 4096, PROT_R|X, MAP_PRIVATE, remote_fd, 0)` inside init.
5. Remote `close(remote_fd)`. Mapping persists via the same deleted-inode mechanism; no host disk turd.

### Files

- **Edit** `crates/resetprop/src/seal/hook.rs`:
  - Remove `HOOK_FILE_DIR` (`:58`), `write_host_hook_file` (`:451-468`), `install_file_backed_hook_page` (`:434-444`).
  - Replace `mmap_file_backed_in_tracee` (`:492-511`) with a memfd-based variant.
  - Update the docstring at `:299-316` to reflect the new SELinux contract (relabel-to-libc, not adb_data_file-allowlist).
- **Add** `crates/resetprop/src/seal/selinux.rs` (~40 lines):
  - FFI binding for `setfilecon(const char *path, const char *con)` from libselinux.
  - Function `get_libc_so_context()` reads `/system/lib64/libc.so`'s context via `getfilecon` (or `lgetfilecon`).
  - Function `set_remote_fd_context(pid, remote_fd, context)` wraps the `/proc/<pid>/fd/<fd>` setfilecon call.
- **Edit** `crates/resetprop/Cargo.toml`:
  - Add `selinux-sys` dep (or hand-roll the two FFI symbols if dep introduction is undesirable — pick at implementation time).

### Risks / unknowns

- **Single-dep minimalism (verified)**: `resetprop-rs/crates/resetprop/Cargo.toml:13-14` declares exactly ONE runtime dep: `libc = "0.2"` (plus `tempfile` for dev). Adding `selinux-sys` violates this convention. Recommend hand-rolling the two FFI symbols (`setfilecon`, `getfilecon`) directly via `extern "C"` declarations against `libselinux.so` — zero new Cargo deps, ~30 lines of unsafe FFI. Decision deferred to implementation but the default lean is "FFI-only, no crate".
- **libselinux availability on target devices**: Android ships libselinux in `/system/lib64/`. Linking is dynamic. Verify with `adb shell ls /system/lib64/libselinux.so` on a target device before committing the FFI approach.
- **setfilecon EPERM in non-root contexts**: resetprop-rs already requires root for ptrace; same requirement covers setfilecon. No new privilege surface.
- **Performance**: memfd is faster than the disk path (no fsync, no inode allocation on /data). No regression expected.

### Acceptance

1. `cargo test -p resetprop` passes (existing tests use mocked install paths — should be unaffected; verify).
2. New unit test: `seal/hook.rs` install round-trip with mocked remote syscalls confirms memfd path returns a non-zero address.
3. On-device smoke test: Tier B install + seal_prop + unseal_prop sequence on a real device shows zero `/data/adb/resetprop-rs/hook-*.bin` residue at any point during the install window (`adb shell ls /data/adb/resetprop-rs/` returns nothing).
4. SELinux denial absence verified via `adb shell dmesg | grep avc` after install — no AVC denials related to `adb_data_file:file:execute` or our memfd.

---

## Port 2 — kmsg fd snoop for in-init observability

### Current state

There is no observability into what init's `__system_property_update` trampoline does at runtime. When a Tier B install misbehaves (lock-list walker hits the wrong entry, strcmp loop terminates wrong, prologue restore fails), the only diagnostic is logcat from system_server processes which only show downstream effects.

### What changes

Port the injectrc kmsg snoop pattern (`injector.cpp:213-232, 289-302`):

1. After `RemoteAttach::new`, scan `/proc/1/fd/*` symlinks. Any link target equal to `/dev/kmsg` is a kmsg fd. Persist the set of remote fd numbers in `HookHandle` (new field `kmsg_fds: Vec<u64>`).
2. Add a CLI subcommand `resetprop-cli observe-init [--duration <secs>]` that ptraces init under syscall-trace mode and dumps any `write(kmsg_fd, ...)` calls to stdout with the buffer contents read via `process_vm_readv`.
3. Optionally integrate the snoop into existing seal_prop / unseal_prop windows when `--verbose` is passed — gives free observability during the brief ptrace windows we already hold.

### Files

- **Add** `crates/resetprop/src/seal/kmsg_observer.rs` (~150 lines):
  - `discover_kmsg_fds(pid: Pid) -> Result<Vec<u64>>` — scans `/proc/<pid>/fd/`.
  - `snoop_kmsg_writes_for_duration(pid: Pid, kmsg_fds: &[u64], duration: Duration, out: &mut impl Write) -> Result<()>` — syscall-trace loop matching `injector.cpp:254-310`.
- **Edit** `crates/resetprop/src/seal/hook.rs`:
  - Add `kmsg_fds: Vec<u64>` to `HookHandle` (`:144-173`).
  - Populate in `install_init_hook` (`:335`) before detach.
- **Edit** `crates/resetprop-cli/src/main.rs`:
  - The CLI uses a hand-rolled flag parser at `main.rs:17-100` (state machine over `args`), NOT clap subcommands. The existing flag pattern at `:42-100` enumerates `--seal`, `--unseal`, `--stealth`, `--compact`, `--wait`, `--timeout`, etc. Add `--observe-init` as a new flag alongside these; use the existing `arg_val` helper to read an optional duration parameter (`--observe-init --duration 5`). Do NOT introduce clap or a subcommand model — the project's minimalism is intentional.

### Risks / unknowns

- **Throughput**: init writes to kmsg sparingly during normal operation. A 1-second observation window typically yields 0-3 lines. No log-rate concern.
- **Race with init crashes**: if init crashes mid-snoop, ptrace detach surfaces as `ESRCH`. Existing `RemoteAttach::drop` handles this gracefully.
- **Interaction with concurrent Tier B install**: do not run `observe-init` while a Tier B install is in progress on the same machine — both would ptrace init and conflict. Document at the CLI level.

### Acceptance

1. `cargo test -p resetprop` passes; new unit tests for `discover_kmsg_fds` against a synthetic `/proc/<pid>/fd/` fixture.
2. On-device positive trigger: invoke `setprop persist.pv.kmsg-probe-<rand> hello` from a shell session WHILE `resetprop-cli observe-init --duration 5` is running. Init writes a corresponding entry to kmsg ("init: starting service..."-class log line). Assert observe-init captures at least one kmsg line during the window. A bare "exit code 0 with no output" run is NOT a sufficient gate — it would pass a no-op implementation.
3. Tier B install with `--verbose` shows captured kmsg lines if init writes any during the install window.

---

## Port 3 — `.gnu_debugdata` XZ mini-symtab parser

### Current state

`seal/elf.rs:249` `parse_libc_elf` walks `PT_DYNAMIC` to find `DT_SYMTAB` / `DT_STRTAB` / `DT_GNU_HASH`. This resolves any symbol present in libc's `.dynsym` — including the target `__system_property_update`. It does **not** resolve symbols that exist only in `.gnu_debugdata`, the XZ-compressed mini-symtab that vendor ROMs ship alongside stripped binaries for crash reporters.

### Why port this anyway

Today there is no consumer. Tomorrow, if you want to hook init's *internal* C++ symbols (the `Parser::ParseConfig`-class targets injectrc resolves at `payload.cpp:21-24, 111-114`), `.dynsym` won't have them — init strips that table — and you'd need `.gnu_debugdata`. Porting now keeps the door open without committing to using it. Per your "capability door" priority signal in selecting all four ports.

### What changes

Extend `parse_libc_elf` to optionally parse `.gnu_debugdata`:

1. After PT_DYNAMIC walk, locate `.gnu_debugdata` via section header table (currently the parser only walks program headers — extend to section headers when needed). The section header offset is at `Elf64_Ehdr.e_shoff` already read by `read_struct::<Elf64_Ehdr>` at `seal/elf.rs:266`.
2. Read the section bytes, decompress as XZ, parse the result as a nested ELF (the mini-symtab is a tiny ELF with `.symtab` + `.strtab` sections).
3. Merge the discovered symbols into `LibcElfView`'s lookup surface: when `resolve_symbol` (`seal/elf.rs:624`) misses on both GNU_HASH and linear `.dynsym`, fall through to the debug symtab.

### Files

- **Edit** `crates/resetprop/src/seal/elf.rs`:
  - Add section header walk (new types: `Elf64_Shdr`) + lookup by section name (.shstrtab).
  - Add `gnu_debugdata_view: Option<DebugSymtabView>` field to `LibcElfView` (`:172-185`).
  - Extend `resolve_symbol` (`:624`) with debug-symtab fallback.
- **Add** `crates/resetprop/src/seal/xz_decoder.rs` (~50 lines wrapping a pure-Rust XZ decoder):
  - Function `decode(compressed: &[u8]) -> Result<Vec<u8>>`.
- **Edit** `crates/resetprop/Cargo.toml`:
  - Add `lzma-rs` (pure Rust, no C deps) for XZ decode. Alternative: port injectrc's `xz-embedded` to Rust (significant work, defer unless `lzma-rs` proves unsuitable).

### Risks / unknowns

- **Single-dep minimalism (same concern as Port 1)**: adding `lzma-rs` would be the second non-libc runtime dep. The minimalism choice at `Cargo.toml:13-14` is intentional. Two paths:
  - Accept `lzma-rs` as the cost of the gnu_debugdata capability (small crate, pure Rust, no transitive deps).
  - Port injectrc's `elf_parser/xz-embedded/` C sources to Rust (~600 lines of decompressor, more work).
  - Default lean: accept `lzma-rs` for this port since the alternative is genuine reinvention; document the choice in `Cargo.toml` with a comment.
- **`lzma-rs` no_std compatibility**: verify at implementation time. resetprop-rs is std-only currently (it's a userspace CLI) so this is moot — but if any portion needs to compile no_std, check.
- **Empty `.gnu_debugdata`**: some OEMs strip even the mini-symtab. Parser must treat absence as a no-op, not an error — `resolve_symbol` falls back to current behavior in that case.
- **Section header parsing introduces new ELF surface**: section headers can be malformed independently of program headers. Mirror the bounds-check rigor of the existing `read_struct` calls.

### Acceptance

1. `cargo test -p resetprop` passes; new unit tests using a synthetic ELF with embedded `.gnu_debugdata`.
2. `parse_libc_elf` against a real Android `libc.so` (one with `.gnu_debugdata`, one without) returns successfully in both cases.
3. `resolve_symbol("__system_property_update")` still resolves via GNU_HASH (no regression).
4. New test: `resolve_symbol("<symbol-only-in-debugdata>")` succeeds against a fixture libc.

---

## Port 4 — Multi-arch register glue (arm32, x86_64, x86, riscv64)

### Current state

`seal/ptrace.rs:113-118` defines `UserPtRegs` as `[u64; 31] + sp + pc + pstate` — the aarch64 layout. The size assertion at `:126` is `target_arch = "aarch64"` only. Constants at `:83-89` (`ARM64_SVC_0`, `ARM64_BRK_0`) hardcode arm64 trap encodings. `remote_syscall` at `:512` and `remote_syscall_via_poke` at `:627` use `regs[8] = syscall_no; regs[0..=5] = args` — the aarch64 calling convention.

### What changes

Generalize to support all five injectrc-supported architectures via cfg-gated per-arch modules.

Per architecture, the implementation needs:

| Arch | Syscall reg | Arg regs | Trap insn | Breakpoint insn | NT_PRSTATUS size |
|---|---|---|---|---|---|
| arm64 | x8 | x0..x5 | `svc #0` (0xd4000001) | `brk #0` (0xd4200000) | 272 |
| arm32 | r7 | r0..r5 | `svc #0` (0xef000000) | `bkpt #0` (0xe1200070) | 72 |
| x86_64 | rax | rdi,rsi,rdx,r10,r8,r9 | `syscall` (0x0f05) | `int3` (0xcc) | 216 |
| x86 | eax | ebx,ecx,edx,esi,edi,ebp | `int 0x80` (0xcd80) | `int3` (0xcc) | 68 |
| riscv64 | a7 | a0..a5 | `ecall` (0x00000073) | `ebreak` (0x00100073) | 280 |

Reference: `injectrc/init_injector/ptrace_utils.hpp:25-65` has the C++ equivalent layout.

### Files

- **Refactor** `crates/resetprop/src/seal/ptrace.rs`:
  - Extract per-arch register layout into `seal/ptrace/arch/` submodule directory:
    - `arch/aarch64.rs` (current code, moved verbatim)
    - `arch/arm.rs`
    - `arch/x86_64.rs`
    - `arch/x86.rs`
    - `arch/riscv64.rs`
  - Each module exports: `UserPtRegs`, `TRAP_INSN`, `BRK_INSN`, `set_syscall_args(regs: &mut UserPtRegs, nr: u64, args: [u64; 6])`, `get_syscall_return(regs: &UserPtRegs) -> i64`, `NT_PRSTATUS_SIZE`.
  - Top-level `seal/ptrace.rs` becomes a cfg-dispatched façade.
- **Edit** existing call sites in `seal/arena.rs`, `seal/hook.rs` to use the arch-neutral interface rather than `regs[8]`, `regs[0..6]` literals.
- **Edit** `.cargo/config.toml` (verified existing content): the file already declares linker stanzas for `aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android` (`.cargo/config.toml:1-13`). Four of the five injectrc-supported arches are already linker-ready. Only `riscv64` is absent. Add a `riscv64-linux-android` (or `riscv64gc-unknown-linux-gnu`) stanza ONLY if the NDK at the project's target version ships `riscv64-linux-android*-clang`; if not, defer RISC-V and ship Port 4 covering the four already-configured arches.

### Risks / unknowns

- **NT_PRSTATUS size correctness (UNVERIFIED for non-aarch64)**: only the aarch64 value of 272 is verified at the source level via `seal/ptrace.rs:126`'s `const _: () = assert!(...)`. The other four values in the table (arm32=72, x86_64=216, x86=68, riscv64=280) are taken from injectrc's `ptrace_utils.hpp:25-65` and reference material, NOT yet verified against the NDK's `bionic/libc/kernel/uapi/asm-<arch>/asm/ptrace.h`. Implementation-time work item: open each header, confirm the value, add a per-arch `assert!(...)` mirroring the aarch64 pattern. Do this BEFORE the cross-compile build to surface mismatches at compile-time, not link-time.
- **Test fixture portability (verified)**: `crates/resetprop/tests/ptrace_core_smoke.rs:30` declares `#![cfg(target_arch = "aarch64")]` — file-level gate. The file compiles to an empty test binary on non-aarch64 targets per its own header comment at `:9-19`. For per-arch coverage, EITHER author sibling test files (`ptrace_core_smoke_x86_64.rs`, etc.) each with their own `#![cfg(target_arch = ...)]`, OR refactor to a single test file with per-arch helper modules. The sibling-file approach matches the existing project test style and requires zero refactor to the existing aarch64 test.
- **CI infrastructure cost**: adding 4 cross-compile targets to CI is non-trivial — each needs an NDK or equivalent toolchain. Track separately if your CI infrastructure isn't already multi-target.
- **Real-world use cases for non-aarch64**: emulator (x86_64), older devices (arm32, x86), and far-future RISC-V Android devices. None are urgent. This is future-proofing, not solving a present problem.
- **NDK version pinning required**: the project's target NDK release determines whether `riscv64-linux-android*-clang` is shipped. Pin the NDK version in the plan before answering RISC-V scope. Implementation-time check: `ls $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/ | grep clang` against the resolved NDK path. If RISC-V is absent, Port 4 ships covering the four already-configured arches and tracks RISC-V as future work.
- **Per-arch sibling test files are Port 4 scope, not deferred**: `tests/ptrace_core_smoke.rs:30` gates the whole file behind aarch64. To make acceptance #5 non-vacuous, Port 4 authors sibling files `ptrace_core_smoke_x86_64.rs`, `ptrace_core_smoke_arm.rs`, etc., each with its own `#![cfg(target_arch = ...)]` and per-arch trap encoding fixtures. Count this in the cost estimate.

### Acceptance

1. `cargo build --target aarch64-linux-android -p resetprop` still succeeds (no regression).
2. `cargo build --target x86_64-linux-android -p resetprop` succeeds (new).
3. `cargo build --target armv7-linux-androideabi -p resetprop` succeeds (new).
4. `cargo build --target i686-linux-android -p resetprop` succeeds (new).
5. `cargo test -p resetprop --target <each>` passes the cfg-gated test surface.
6. (Optional) On-device smoke test of Tier A seal on an x86_64 Android emulator confirms the x86_64 register glue works at runtime.

---

## Recommended sequencing

Independent in code surface; recommended order is by cost-to-value:

1. **Port 1 (memfd + setfilecon)** first — smallest, lands cleanly inside existing `seal/hook.rs`. Validates the refactor approach against existing test harness. 1-2 day estimate (realistic).
2. **Port 2 (kmsg snoop)** second — independent. Adds observability that benefits debugging ports 3 + 4 later. 3-4 day estimate (the kmsg_observer.rs syscall-trace loop is one day; integration into HookHandle + CLI flag wiring + positive-trigger test fixture is the rest).
3. **Port 3 (gnu_debugdata)** third — bigger surface, no immediate consumer. 4-6 day estimate. The 3-5 day range was optimistic; section-header walk is entirely new code in `seal/elf.rs` (currently program-header-only), and XZ-decoder selection + integration carries its own bounds-check rigor work.
4. **Port 4 (multi-arch)** last — lowest immediate value. 7-10 day floor (4 arches) covering: per-arch register layout authoring, per-arch trap/breakpoint encoding, NT_PRSTATUS size verification against UAPI headers, per-arch sibling test files, and CI cross-target verification. Add 3-5 days if RISC-V stays in scope (NDK toolchain spelunking + register layout).

All four are independent of the prop/ submodule kernel work — different crate, different reviewers. Three parallel tracks possible: Tier B userspace ports (these four), prop/ kernel submodule (`/home/president/.claude/plans/lets-go-through-your-imperative-aho.md`), and ongoing daily phase-δ work.

---

## Verification (across all four ports)

### Regression gate

After each port, before merge:

1. `cargo test -p resetprop` — all existing tests pass.
2. `cargo test -p resetprop --target aarch64-linux-android` — cross-compile tests still pass (currently the canonical target).
3. `cargo clippy -p resetprop -- -D warnings` — no new clippy regressions.
4. On-device Tier B install + 10 seal_prop / unseal_prop cycles on a real device — same observable behavior as before the port.

### Integration with phantom-veil

`resetprop-rs` is a submodule of phantom-veil per `.gitmodules`. After each port lands:

1. Update phantom-veil's submodule pin.
2. Run phantom-veil's telephony test app `RUN_ALL` against the updated resetprop-rs.
3. Confirm zero new FAILs vs the pre-port baseline.

### T13 graceful degradation invariant

These ports must NOT change resetprop-rs's role as the userspace fallback for the kernel-rewire architecture (per the prop/ submodule plan). After all four ports:

1. With `pv.ko` absent, seal_prop / unseal_prop must behave identically to today.
2. The CLI surface (`resetprop-cli` flags) must remain backwards-compatible — no breaking changes to existing subcommands.

---

## ReZygisk parity — every way ReZygisk's ptrace injection beats ours

Source: head-to-head audit (2026-06-16) of our `seal/` engine against
ReZygisk's `loader/src/ptracer/` + `loader/src/injector/` (cloned at
`/home/president/Git-repo-success/ReZygisk/`). This is a complete gap inventory
for the planner to bucket into tasks. Every row carries file:line on **both**
sides. ReZygisk paths are relative to `/home/president/Git-repo-success/ReZygisk/`;
ours are relative to `crates/resetprop/src/`.

**Two gaps are already tracked elsewhere in this file — do NOT double-bucket:**
G2 (thread-group stop) is "Known defects → Defect B"; G3 (multi-arch) is Port 4.
They are listed here only so the inventory is complete.

### Architecture contrast (why G1 is the root gap)

```
ReZygisk — recoverable target:
  monitor ──SEIZE + O_TRACEFORK──▶ init (PID 1)   [tripwire ONLY, never written]
     │  on fork → exec(app_process)
     ▼
  zygisk-ptrace ──SEIZE──▶ zygote child ──CSOLoader──▶ libzygisk.so mapped
     (disposable, O_EXITKILL)            drive to entry → call entry()
  bug here  ⇒  one zygote dies  ⇒  throttled restart   (system survives)

Ours — catastrophic target:
  resetprop ──SEIZE + INTERRUPT──▶ init (PID 1) ──POKEDATA──▶ trampoline + hook page
     (transient, detaches after)               PATCH WRITTEN INTO PID 1
  bug here  ⇒  PID 1 faults  ⇒  kernel panic / bootloop   (system dies)
```

### Gap table

| # | Gap | ReZygisk does | Ours (current) | Verdict |
|---|-----|---------------|----------------|---------|
| G1 | Never writes into init (blast radius) | `monitor.c:545` SEIZE init as tripwire; inject into disposable zygote `monitor.c:694,755`; `O_EXITKILL` `ptracer.c:484`; restart throttle `monitor.c:405-423` | init IS the patch target: `mod.rs:23`, `arena.rs:302`, `hook.rs:1104` | **Mitigate** — cannot replicate (see note) |
| G2 | Thread-group stop | injects at single-threaded post-`execve` `monitor.c:694` | seizes PID 1 only, never `/proc/1/task/*` `arena.rs:203-206` | **ADOPT** — already Defect B |
| G3 | Multi-arch (arm64/arm32/x86_64/x86) | `utils.c:234-307`, `:359-439`; reloc `remote_csoloader.c:530-643` | arm64-only `ptrace.rs:111-118`; gated `lib.rs:761,803,832` | **ADOPT** — already Port 4 |
| G4 | Stealth / anti-detection | custom linker hides `.so` from solist (README; `remote_csoloader.c:684`); `__dl_*` redirect `:483-499`; ptrace_message reset `ptrace_clear.c:39` | zero artifact hiding; only unlink → `(deleted)` `hook.rs:442`, `maps.rs:106-108` | **Optional / large** |
| G5 | General function-call remote primitive | `remote_call` `utils.c:225`; SIGSEGV-return `:325-332` | syscall-only `ptrace.rs:650` | **Optional** — build on demand |
| G6 | Hardened wait-loop + maturity | `wait_for_trace` `utils.c:1043`, `wait_for_ptrace_syscall_stop` `:835` (absorb spurious stops, 4× retry) | `wait_stop` one-shot, errors on any unexpected stop `ptrace.rs:254-263`; Tier B never run on-device | **ADOPT** — partial, cheap |
| G7 | ifunc/HWCAP + multi-hash symbol resolution | GNU→SysV→linear `elf_util.c:656`; STT_GNU_IFUNC w/ HWCAP `:746-787` | GNU→linear only, no ifunc `elf.rs:622-629` | **Optional** — `__system_property_update` doesn't need it |

### G1 — Blast radius (MITIGATE; cannot replicate)

ReZygisk is safer mostly because it chose a recoverable target. We **cannot**
copy that: sealing requires altering init's own `__system_property_update` /
arena behavior, so init must be the target. The value here is mitigation —
shrink the probability and cost of a PID-1 fault:

- **M1 — init-identity guard.** Today there is no check that PID 1 is really
  init before patching (audit weakness). Add: verify `/proc/1/comm`==`init`
  (or `/proc/1/cmdline`) and that the resolved libc row is the expected APEX
  `libc.so` before any poke. Files: `seal/hook.rs:335` (`install_init_hook`),
  `seal/arena.rs:310` (`remote_remap_private`). Acceptance: patching a non-init
  PID 1 stand-in is rejected with a typed error before any write.
- **M2 — verify-after-write.** After writing the 16-byte trampoline
  (`seal/hook.rs:1129-1134`), read it back via `process_vm_readv` and compare
  before committing the i-cache sync; on mismatch, revert via the existing
  `revert_trampoline` (`seal/hook.rs:1046`) and abort. Acceptance: a forced
  torn write is detected and rolled back, init prologue intact.
- **M3 — dry-run / `--check` mode.** Resolve symbol + parse maps + locate the
  scratch slot WITHOUT poking, so an operator validates on a device before the
  real patch. Files: `seal/hook.rs`, `resetprop-cli/src/main.rs` flag wiring.
- **M4 — install throttle.** If a seal install has hard-failed N times this
  boot, refuse further attempts (mirrors `monitor.c:405-423` philosophy) to
  avoid bootloop-on-retry. Shared with G6/R3.

Priority: **M1 + M2 are cheap and the highest-value safety work in this file**
after Defect A/B.

### G2 — Thread-group stop (ADOPT — see "Known defects → Defect B")

Cross-reference only. ReZygisk injects when the target is single-threaded by
construction (`monitor.c:694`, post-`execve`); we never freeze init's siblings
(`arena.rs:203-206`). The fix (enumerate `/proc/1/task/*`, SEIZE+INTERRUPT each,
resume on completion) and full rationale live in the Known defects section.
**Highest-value adoptable safety fix in the file.**

### G3 — Multi-arch (ADOPT — see Port 4)

Cross-reference only. ReZygisk handles 4 arches across call/syscall/gadget/reloc
(`utils.c:234-307`, `:359-439`; `remote_csoloader.c:530-643`); we are arm64-only
(`ptrace.rs:111-118`; `lib.rs:761,803,832`). Already fully scoped as Port 4.

### G4 — Stealth / anti-detection (OPTIONAL, large; overlaps deferred propdetect work)

ReZygisk treats detection-resistance as a first-class goal: its custom linker
maps `libzygisk.so` without registering it in the system linker's solist
(README "defeating any linker-based detection"; `remote_csoloader.c:684`), plus
`__dl_*` redirection (`remote_csoloader.c:483-499`) and a seccomp-based
`ptrace_message` reset (`ptrace_clear.c:39`, self-disables on kernel ≥5.10
`:17-44`). We hide nothing:

- **S1 — hook-page disguise.** Our hook page is already file-backed RX
  (`seal/hook.rs:557-565`) — give its backing file a benign, legit-looking path
  so the mapping in `/proc/1/maps` doesn't read as an odd injected region.
- **S2 — prologue-signature resistance.** The patched first 16 bytes of
  `__system_property_update` (`seal/hook.rs:1127-1134`) are trivially detected
  by diffing against on-disk libc. Hard to fully hide with an inline trampoline;
  either document as a known signature or evaluate a less-detectable hook style
  (e.g. PLT/GOT-on-callers, as ReZygisk's injected lib uses).
- **S3 — at-rest trace hygiene (partial win, keep it).** We detach after each
  op, so init shows no resident `TracerPid` — *better* than ReZygisk's
  persistent init SEIZE for at-rest detection. Preserve this property in any
  thread-group-stop change (G2) — re-detach all task threads.

Note: S1–S2 overlap the **deferred propdetect-signature work** (REGISTRY
post-v1). Recommend bucketing as one "Tier B detection-resistance" workstream,
lower priority than G1/G2.

### G5 — General function-call remote primitive (OPTIONAL — build on demand)

ReZygisk's `remote_call` (`utils.c:225`) invokes arbitrary functions in the
tracee: per-ABI arg marshalling, LR set to an invalid `return_addr`, return
detected via SIGSEGV-at-return (`utils.c:325-332`). Ours can only issue raw
syscalls (`remote_syscall_via_poke`, `ptrace.rs:650`) — sufficient for Tier A/B.

- Add `remote_funcall(pid, func_addr, args, return_addr)` in `seal/ptrace.rs`
  reusing our existing save/restore discipline, with an invalid-return-addr or
  brk-at-scratch-return trap.
- **Do not build speculatively.** Tag "unlock when a port needs it" — e.g.
  Port 3's `.gnu_debugdata` C++ internal-symbol hooking may require calling a
  libc function in init. Cross-ref Port 3.

### G6 — Hardened wait-loop + maturity (ADOPT — partial, cheap)

ReZygisk's wait wrappers absorb spurious `SIGCHLD`/seccomp/group-stops and retry
(`wait_for_trace` `utils.c:1043`; `wait_for_ptrace_syscall_stop` `utils.c:835`,
up to 4×). Our `wait_stop` (`ptrace.rs:254-263`) accepts exactly one expected
stop and errors (`Error::PtraceUnexpectedStatus`) on anything else.

- **R1 — spurious-stop tolerance.** Make `wait_stop` (`ptrace.rs:254`) loop,
  re-`CONT`ing benign group-stops / `SIGCHLD` instead of failing the whole op —
  reduces flaky aborts when attaching to a busy init. Keep the strict
  expected-event check for the *final* awaited stop.
- **R2 — on-device Tier B acceptance (the P05 gate).** Run install + multi-prop
  seal/unseal against real init on aarch64 — this is what surfaces Defect A.
  Validation work, not code; highest-confidence gate.
- **R3 — install throttle.** Shared with M4 above.

### G7 — ifunc/HWCAP + multi-hash symbol resolution (OPTIONAL)

ReZygisk resolves GNU-hash → SysV-hash → linear (`elf_util.c:656`) and actually
runs `STT_GNU_IFUNC` resolvers with the right HWCAP (`elf_util.c:746-787`); it
resolves "locally + rebase to remote base" (`utils.c:174,:209`). Ours is
GNU-hash → linear, no SysV path, no ifunc (`elf.rs:622-629`). This only matters
if a future target symbol is an ifunc or lives in a SysV-hash-only libc;
`__system_property_update` is a plain exported function and needs none of it.

- Add SysV `.hash` fallback + `STT_GNU_IFUNC` resolution in `seal/elf.rs`.
- Low priority. Tag "unlock when targeting ifunc / non-GNU-hash symbols."

### Recommended bucketing for the planner

- **P0 — correctness + safety on the current target (do first):** Defect A fix;
  G2 (Defect B, thread-group stop); G1/M1 (init-identity guard); G1/M2
  (verify-after-write); G6/R1 (spurious-stop tolerance); G6/R2 (on-device
  acceptance).
- **P1 — coverage + operability:** G3 (Port 4, multi-arch, already scoped);
  G1/M3 (dry-run); G1/M4 + G6/R3 (install throttle).
- **P2 — capability doors / detection (build when a consumer needs them):**
  G4 (stealth S1–S2); G5 (function-call primitive); G7 (ifunc/SysV-hash).

P2 items match the existing "capability door" philosophy of Ports 3–4 — port
when a downstream target requires them, not speculatively.

---

## Open items (tracked for after implementation begins)

1. **libselinux binding path** (Port 1): selinux-sys crate vs hand-rolled FFI vs cc-rs build — pick at implementation time based on dependency budget. Default lean: hand-rolled FFI to preserve single-dep minimalism.
2. **XZ decoder choice** (Port 3): lzma-rs (pure Rust) vs xz2 (C) vs port injectrc's xz-embedded. Default to lzma-rs unless dependency-minimalism review rejects it.
3. **NDK version pin** (Port 4): the plan must pin the target NDK release before answering RISC-V scope. Once pinned, verify riscv64-linux-android clang presence; defer RISC-V if absent.
4. **REGISTRY.md amendments**: introducing per-resetprop commits will require `REGISTRY.md §2` to add a `feat(resetprop):` scope alongside the existing `feat(module):`, `feat(hooks):`, `feat(companion-location):`, `feat(companion-telephony):`, `feat(shared):`, `chore(docs):`. File the §2 amendment in the same commit that opens Port 1.
5. **Cross-CI cost** (Port 4): if adding 4 new cross-compile targets explodes CI runtime, gate non-aarch64 builds behind a `--multi-arch` workflow trigger rather than running on every PR.
