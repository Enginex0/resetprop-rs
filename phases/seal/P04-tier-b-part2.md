# P04: Tier B Part 2 — ARM64 Trampoline + Lock-List Mechanics

## Objective

Complete Tier B per-property sealing by implementing the ARM64 A64 instruction encoder, the hook body generator, the trampoline installer, the append/compact lock-list mechanics, and the `PropSystem::seal` / `PropSystem::unseal` / `PropSystem::seals` public API. This phase converts the `HookHandle` + hook page that P03 produced into an operational hook: init's next call to `__system_property_update` with a sealed name short-circuits to `mov w0, #0; ret` without mutating the arena.

## Preconditions

- [ ] P03 (Tier B pt1: ELF + hook page) shows COMPLETE in REGISTRY §4
- [ ] Files that must exist: `crates/resetprop/src/seal/hook.rs` (skeleton with `HookHandle`, `install_init_hook` stage-A+B), `crates/resetprop/src/seal/elf.rs` (exposes `resolve_symbol`), `crates/resetprop/src/seal/ptrace.rs` (remote syscall + `process_vm_writev` helpers), `crates/resetprop/src/seal/mod.rs` (exposes `SealRecord`, `SealTier` defined by P01)
- [ ] `crates/resetprop/src/seal/mod.rs` registry accessor (`OnceLock<Mutex<Vec<SealRecord>>>`) is present — defined by P01; P02 and P04 are independent consumers per REGISTRY §5 parallel tracks
- [ ] Branch `feat/P03-tier-b-part1` merged to main

## Scope

### Files to CREATE

None. The original Tier B spec listed an off-device sacrificial-child integration test (`crates/resetprop/tests/tier_b_child_smoke.rs`), but P04.2 T3 removed it per Gate 2 round-1 critic CRITICAL 2 — the host binary fails `is_libc_row`'s `/libc.so`-suffix filter, and Rust resolves the child's `#[no_mangle] __system_property_update` call via intra-module branch, bypassing the patched `.dynsym` entry even with `--export-dynamic`. Tier B functional acceptance moves to the aarch64 on-device run in P05.

### Files to MODIFY

| File | Changes |
|------|---------|
| `crates/resetprop/src/seal/hook.rs` | Add (1) A64 encoder submodule of `const fn` helpers (`svc`, `brk`, `ret`, `br`, `blr`, `ldr_literal`, `add_imm64`, `movz`, `movk`, `cbz`, `cbnz`, `b_rel`, `ldrb_imm`, `nop`, `isb`) with fixed opcode consts; (2) pure deterministic helper `build_hook_body_bytes(lock_list_vaddr, saved_prologue_vaddr, return_addr) -> Vec<u8>` generating strcmp-loop hook body — no ptrace, unit-testable; (3) `install_trampoline(handle)` calls `build_hook_body_bytes(...)` then writes the bytes at `hook_page + HOOK_BODY_OFFSET` and the 16-byte trampoline at `handle.target_fn`; (4) remote `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` primary i-cache sync with `isb`-staged fallback; (5) `seal_prop(handle, name)` append-before-length-update lock-list writer; (6) `unseal_prop(handle, name)` compaction walker |
| `crates/resetprop/src/lib.rs` | Add `PropSystem::seal(name, value) -> Result<SealRecord>` adjacent to `set_stealth_persist` at lib.rs:497; lazy-init `OnceLock<Mutex<Option<HookHandle>>>` holds the installed hook; add `PropSystem::unseal(name) -> Result<bool>`; add `PropSystem::seals() -> Result<Vec<SealRecord>>` returning a clone of the in-memory registry; register mutations via the shared `SealRecord` registry defined by P01 |

## Reference Material

Read ONLY these at session start:

| File | Sections | Est. Tokens | Why |
|------|----------|-------------|-----|
| `phases/seal/references/arm64-a64-encoding.md` | Full file (Instruction Table, Rust const-fn encoder module, Absolute-target trampoline, Strcmp loop skeleton, Hook body sketch, i-cache invalidation options) | ~3800 | Canonical opcode values, `trampoline_to()`, `HOOK_BODY` skeleton with patch points, i-cache rationale |
| `phases/seal/references/aosp-property-system.md` | §1 prop_info Layout, §3 SystemProperties::Update Full Call Trace, §6 `__system_property_update` libc Export | ~1600 | Confirms `x0=prop_info*`, `x1=value`, `w2=len` ABI and `pi->name` at offset 96 |
| `phases/seal/references/linux-arm64-abi.md` | §1 Syscall numbers (table), §10 process_vm_readv/writev, §11 Failure Modes | ~1300 | `__NR_membarrier = 283`, `process_vm_writev` semantics for lock-list + trampoline writes |
| `phases/seal/references/test-harness-patterns.md` | §2 CAP_SYS_PTRACE gating, §3 Sacrificial child pattern, §5 Tier B test skeleton, §11 Assertions | ~1400 | Test binary skeleton: `#[no_mangle] extern "C" fn __system_property_update`, `PinnedPi`, `read_remote_value` via `process_vm_readv` |
| `phases/seal/references/resetprop-rs-integration.md` | §3 lib.rs public surface (lines 291–596), §4 Error variants, §14 seal/ module integration map | ~1800 | `set_stealth` at lib.rs:458, `set_stealth_persist` at lib.rs:497 — exact placement neighbors for new methods |

## External API Verification

Set this flag if the phase uses external APIs. Gate 2 agents MUST grep/read these sources to verify signatures.

- **Required**: YES
- **Sources to verify against**:
  - `/home/president/aosp-android15/bionic/libc/system_properties/system_properties.cpp` — `SystemProperties::Update` at lines 270–336 confirms ABI and write-order (backup → dirty-set → value copy → serial store → futex wake)
  - `/home/president/aosp-android15/bionic/libc/system_properties/include/system_properties/prop_info.h` — `static_assert(sizeof(prop_info) == 96)` at line 89 confirms `PROP_INFO_NAME_OFFSET = 96`
  - `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/arm64-a64-encoding.md` — authoritative opcode values for every encoder (`NOP=0xd503201f`, `RET=0xd65f03c0`, `ISB=0xd5033fdf`, `SVC0=0xd4000001`, `BRK0=0xd4200000`, `ldr x16,[pc,#8]=0x58000050`, `br x16=0xd61f0200`), strcmp loop, hook body skeleton, i-cache invalidation trade-offs
  - `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/aosp-property-system.md` — `__system_property_update` ABI on arm64 (x0=pi, x1=value, w2=len; pi->name at +96)
  - `/home/president/Git-repo-success/resetprop-rs/phases/seal/references/linux-arm64-abi.md` — `__NR_membarrier = 283`, `process_vm_writev` partial-transfer semantics, yama ptrace_scope gating

## Tasks (Max 5 Per Session)

1. **Task 1**: Implement A64 encoder submodule in `hook.rs` — fixed opcode consts (`NOP=0xd503201f`, `RET=0xd65f03c0`, `ISB=0xd5033fdf`, `SVC0=0xd4000001`, `BRK0=0xd4200000`, `LDR_X16_PC8=0x58000050`, `BR_X16=0xd61f0200`) plus `const fn` helpers (`svc`, `brk`, `ret`, `br`, `blr`, `ldr_literal`, `add_imm64`, `movz`, `movk`, `cbz`, `cbnz`, `b_rel`, `ldrb_imm`, `nop`, `isb`); each encoder ≤5 lines with bit-field `assert!` on immediate ranges; unit test disassembles a constructed trampoline back to `ldr x16,[pc,#8]; br x16; <target u64 LE>` bytes — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: `cargo test -p resetprop --lib seal::hook::encoder` compiles and passes bit-range assertion tests
2. **Task 2**: Implement the pure encoder helper `pub fn build_hook_body_bytes(lock_list_vaddr: u64, saved_prologue_vaddr: u64, return_addr: u64) -> Vec<u8>` producing the strcmp-loop hook body: (a) `cbz x0, .fallthrough` guards null `prop_info*`, (b) `add x9, x0, #96` loads `&pi->name` using `PROP_INFO_NAME_OFFSET = 96`, (c) outer loop over lock-list entries with null-sentinel `cbz w11, .fallthrough`, (d) inner strcmp loop (13-word `STRCMP_BODY` spliced at the stub), (e) match branch → `movz w0, #0; ret`, (f) fallthrough restores 4 saved prologue words then `ldr x16, =return_addr; br x16` back to `target_fn + 16`. The function operates on a local `Vec<u8>`, takes 3 parameters, is pure (no ptrace, no `process_vm_writev`), and is unit-testable without a tracee. Unit test `test_build_hook_body_bytes_roundtrip` round-trips the byte output by decoding the first words (null-guard, `add x9`, strcmp entry), the match-exit pair (`movz w0, #0; ret`), and the trailing literals (`RESTORE_TARGET = return_addr`, `LOCK_LIST = lock_list_vaddr` as little-endian u64s) — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_roundtrip` decodes expected opcodes at each fixed index without invoking `process_vm_writev`
3. **Task 3**: Implement the remote installer `install_trampoline(handle: &mut HookHandle) -> Result<()>` — (a) call `build_hook_body_bytes(saved_prologue, lock_list_vaddr, return_addr)` and write the returned `Vec<u8>` into `handle.hook_page + HOOK_BODY_OFFSET` (HOOK_BODY_OFFSET = 1024 inside the lock-list-first layout: bytes 0..=1023 reserved for the lock-list region with the initial empty-list sentinel NUL at byte 0) via `process_vm_writev`; (b) write 16-byte trampoline `[LDR_X16_PC8, BR_X16, target_lo, target_hi]` at `handle.target_fn` (overwriting `handle.saved_prologue`) via `process_vm_writev`; (c) i-cache sync — primary: remote `membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE=0x40, ...)` then `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE=0x80, ...)` via `__NR_membarrier = 283` (REGISTER first per `arm64-a64-encoding.md:422` — SYNC_CORE returns -EPERM until the caller registers); fallback on `EINVAL`/`ENOSYS`: single `isb` (`0xd5033fdf`) staged into a scratch slot in libc.text and executed via ptrace register flip (`pc = scratch_pc`, then `brk`-staged resume); returns `Error::HookInstallFailed` on all write failures. The installer contains no opcode encoding of its own — the deterministic byte layout lives entirely in `build_hook_body_bytes` — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: `cargo test -p resetprop --lib seal::hook` compiles + all 29 hook tests pass; on-device functional acceptance (hook actually blocks init's sealed-prop writes) runs in P05 per P04.2 T3.
4. **Task 4**: Implement lock-list mechanics in `hook.rs` — `seal_prop(handle: &HookHandle, name: &str) -> Result<()>` appends the null-terminated name before the empty-list sentinel at `handle.hook_page + LOCK_LIST_OFFSET` using `process_vm_writev` in this exact order: (1) write the new-entry bytes (name + NUL) to the slot *past* the current list tail, (2) write the trailing empty-entry sentinel NUL at `tail + name.len() + 1`, (3) only after step 2 succeeds, advance the length counter held inside `HookHandle` — this is the atomic-append invariant so the hook's iterator never observes a half-written entry. `unseal_prop(handle: &HookHandle, name: &str) -> Result<bool>` walks the list, compacts remaining entries left over the removed slot (descending memmove via `process_vm_readv` + `process_vm_writev`), then rewrites the trailing sentinel and decrements the length. Returns `Ok(false)` if name not in list — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: unit test `test_lock_list_append_then_remove` on a local fake hook page asserts byte layout after each op
5. **Task 5**: Wire `PropSystem` API in `lib.rs` adjacent to `set_stealth_persist` at lib.rs:497 — (a) add field `hook_handle: OnceLock<Mutex<Option<HookHandle>>>` on `PropSystem`; (b) `pub fn seal(&self, name: &str, value: &str) -> Result<SealRecord>` first rejects `properties_serial` resolution with `Error::InvalidKey` BEFORE any ptrace work (guard matches P02 `seal_arena`); then binds `let arena_path = self.context.as_ref().ok_or(Error::NotFound)?.resolve(name).ok_or(Error::NotFound)?.to_string();` from `PropertyContext::resolve` (`context.rs:367-376`); then calls `self.set_stealth(name, value)?`, then lazy-initializes the hook under `OnceLock` via `seal::hook::install_init_hook(1)` if `None`, then calls `seal::hook::seal_prop(handle, name)?`, then appends `SealRecord { name: name.to_string(), arena_path, tier: SealTier::Prop, sealed_at: SystemTime::now() }` to the shared in-memory `SealRecord` registry (defined by P01 in `seal/mod.rs`); (c) `pub fn unseal(&self, name: &str) -> Result<bool>` calls `seal::hook::unseal_prop(handle, name)?`, removes matching record from the registry, returns the bool; (d) `pub fn seals(&self) -> Result<Vec<SealRecord>>` returns a clone of the registry contents — Files: `crates/resetprop/src/lib.rs` — Verifies: `cargo build -p resetprop` plus `cargo test -p resetprop --lib` passes. Host-side integration test for Tier B is deliberately absent per P04.2 T3 (critic CRITICAL 2); acceptance moves to P05's aarch64 on-device run against real init.

## Approach

1. **Why the hook modifies only the first 16 bytes of `__system_property_update`.** The trampoline layout (`ldr x16,[pc,#8]; br x16; <u64 target>`) is documented in `arm64-a64-encoding.md` §Absolute-target trampoline as exactly 16 bytes / 4 instructions. AOSP libc's `__system_property_update` wrapper's real prologue is longer than 16 bytes (typical AAPCS64 prologue is `stp x29, x30, [sp, #-N]!; mov x29, sp; ...`), so 16 stolen bytes land cleanly on four 4-byte-aligned full-instruction boundaries — no half-instruction split risk. The four saved prologue words are re-materialized inside the hook body's fallthrough path (`STOLEN_START = 13` in the `HOOK_BODY` skeleton). Any PC-relative word among the stolen four (`b`, `bl`, `b.cond`, `cbz`, `cbnz`, `ldr literal`, `adr`, `adrp`) is re-materialized through `MOVZ`/`MOVK` + `BR` — raw relocation to a new address is unsafe (arm64-a64-encoding.md §Hook body sketch, install-time patching rules).
2. **Why lock-list writes must precede the length update.** The hook body executes without any synchronization with the tracer — on init's very next call to `__system_property_update` it walks the list linearly with `ldrb w11, [x10]` and stops at a NUL sentinel. If the tracer bumped the length counter before fully writing the new-entry bytes, the hook would read bytes of a half-written entry (or past-the-end uninitialized bytes) and either false-match or false-miss. The atomic-append invariant (write entry bytes → write trailing sentinel → bump length counter) guarantees the hook always sees a well-formed list: either the old shorter list (with its original trailing sentinel still in place, since we appended *past* that sentinel's old slot without clobbering it) or the fully-formed longer list.
3. **Why `membarrier PRIVATE_EXPEDITED_SYNC_CORE` over `__clear_cache`.** `__clear_cache` would require resolving `libc.so!__clear_cache` in the tracee and setting up a remote call frame — a second symbol-resolution dependency on top of `__system_property_update`. `membarrier` uses only syscall 283 + cmd byte `0x80` (per `linux-arm64-abi.md §1`), zero symbol plumbing. The trade-off from `arm64-a64-encoding.md §i-cache invalidation options` is that `membarrier` does not invalidate i-cache lines directly — it synchronises cores. This is adequate here because `process_vm_writev` goes through the kernel's mm path and issues the `dcache→icache` maintenance implicitly on the destination VMA pages for freshly-written executable content on arm64. The `isb`-staged fallback covers cores that were already pre-fetched; accepting the narrow first-invocation race on kernels < 4.16 is the documented compromise. Combined coverage: the `membarrier` primary handles typical Android kernels (≥ 4.14 with SYNC_CORE backported or ≥ 4.16 upstream), the `isb` fallback handles the minority where `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` returns `EINVAL`.
4. **Hook-page layout constants.** `LOCK_LIST_OFFSET = 0`, `HOOK_BODY_OFFSET = 1024`, `LOCK_LIST_CAPACITY = 1024` — byte 0 is the initial empty-list sentinel NUL (written by P03 when the page was allocated); bytes 0..=1023 are reserved for the lock-list region; hook body starts at byte 1024. The list grows from offset 0 toward the hook body; `seal_prop` refuses any append whose sentinel offset would reach or exceed `LOCK_LIST_CAPACITY`. The 4 KB hook page accommodates the 1024-byte list plus the 140-byte hook body (35 words post-STRCMP-splice per P04.2 T1: 5-word outer-loop header, 2-word pointer rebind, 13-word STRCMP splice, 2-word `.on_match`, 3-word `.advance` scan-past-NUL, 4-word stolen prologue, 2-word tail branch, 2 u64 literals). Bytes 1164..=4095 remain spare. The earlier spec draft listed `HOOK_BODY_OFFSET = 4` — that value was a typo corrected during P04 T3 implementation and confirmed in P04.2 T4.
5. **Shared registry defined by P01.** `SealRecord` and `SealTier` are defined by P01; the `OnceLock<Mutex<Vec<SealRecord>>>` registry lives in `seal/mod.rs` and is populated by whichever tier seals first. P04 pushes `SealTier::Prop` entries; P02 pushes `SealTier::Arena` entries on its own parallel track (REGISTRY §5). `PropSystem::seals()` returns a clone of the combined list. `PropSystem::unseal(name)` filters by `tier == Prop` before delegating to `unseal_prop`; `PropSystem::unseal_arena(name)` (P02) filters by `tier == Arena`. No tier-crossing dispatch.
6. **Reject `properties_serial` at the CLI entry-point (MUST).** `PropSystem::seal` MUST reject any name whose `PropertyContext::resolve` returns the `properties_serial` arena filename with `Error::InvalidKey` BEFORE any ptrace work occurs — the same guard `PropSystem::seal_arena` carries in P02. Even though Tier B's hook targets `__system_property_update` (not the serial counter write path), a consistent rejection boundary prevents user confusion when falling back between tiers for the same name. Citation: REGISTRY §1 row "Arenas NOT to touch"; `aosp-property-system.md §11 properties_serial — Global Notification Channel`.
7. Branch: `feat/P04-tier-b-part2` (per REGISTRY §2 — one branch across all 5 tasks in this single-segment phase).

## Validation

```bash
cargo build -p resetprop                       # compiles; no warnings
cargo test -p resetprop --lib seal::hook       # encoder + build_hook_body + lock-list unit tests pass
cargo test -p resetprop                        # full regression over P01..P03 modules passes
cargo clippy -p resetprop --no-deps --lib --tests -- -D warnings   # clippy clean
```

Tier B functional acceptance (hook actually blocks init's sealed-prop
writes) runs on-device in P05 against real init on aarch64 Android.
The off-device sacrificial-child integration test listed in the
original spec was removed in P04.2 T3 per Gate 2 round-1 critic
CRITICAL 2 — see `phases/seal/REGISTRY-P.md §8` for the rationale.

## Operational Envelope

Tier B ships two known operational limits. Both are accepted for the
operator-initiated seal use case (a handful of sensitive keys locked
for the lifetime of the boot) and are therefore not defects against
the stated scope.

### Lock-list capacity

The hook page is a single 4 KiB RWX mapping. Bytes 0..=1023 hold the
lock-list entries (`LOCK_LIST_CAPACITY = 1024`); bytes 1024..=1163
hold the 140-byte hook body (`HOOK_BODY_OFFSET = 1024`); the remainder
of the page is unused. Each entry costs `name_len + 1` bytes (name +
NUL separator); the list also ends in a trailing sentinel NUL. At an
average bionic property name of ~25 bytes, the list saturates at ~37
entries and `seal_prop` rejects further seals with
`HookInstallFailed("capacity exceeded (...)")`.

If a future use case needs a larger lock-list, the path is a two-page
layout: one RW list page, one RX body page, optional unmapped guard
page. Cost: +4 KiB to init's working set and one extra remote `mmap`
call at install.

### Stage-A attach-window stall

`install_init_hook` observes libc.so's ELF metadata, resolves
`__system_property_update` via GNU_HASH, re-parses `/proc/<pid>/maps`,
allocates the remote hook page via `remote_syscall_via_poke(NR_MMAP)`,
and snapshots the 16-byte target prologue — all inside one
`RemoteAttach` window with init ptrace-stopped. Observed wall-clock:
15-40 ms on a modern ARM64 handset (Snapdragon-class SoC, bionic
libc.so ~1.2 MiB, ~5000 `.dynsym` entries). Any thread that blocks on
init for a property write during this window waits out the full
stall: zygote, system_server, and init-launched daemons.

The stall is accepted for the operator-initiated one-shot path. If a
future phase needs a shorter attach window, the parts to amortise are
the ELF parse and the GNU_HASH walk — a pre-install cache keyed on
libc inode + mtime would let stage-A skip straight to the hook-page
mmap.

## Anti-Scope

- No CLI flag wiring (`-sl`, `--seal`, `--unseal`, `--seals`) — P05 scope (CLI + docs + on-device)
- No persistence of seals to disk (`SealRecord` is in-memory only) — deferred per plan §Decisions locked
- No arena remap logic (`seal_arena`/`unseal_arena`) — P02 scope, already complete
- No ELF parsing, symbol resolution, hook-page allocation, or `install_init_hook` stage-A+B — P03 scope, already complete
- No propdetect heuristics for Tier B trampoline signature — plan §Touchpoints for propdetect noted but not scoped to v1
- No README updates — P05 scope
- No `tests/device-stress-test.sh` modifications — P05 scope
