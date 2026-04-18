# P04 — Tier B Part 2: ARM64 Trampoline + Lock-List Mechanics — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [ ] P03 (Tier B pt1: ELF + hook page) shows COMPLETE in REGISTRY §4
- [ ] `crates/resetprop/src/seal/hook.rs` exists with `HookHandle`, `install_init_hook` stage-A+B (hook page allocated, saved prologue bytes captured, ELF symbol resolved)
- [ ] `crates/resetprop/src/seal/elf.rs` exposes `resolve_symbol` for `__system_property_update`
- [ ] `crates/resetprop/src/seal/ptrace.rs` exposes remote-syscall injector + `process_vm_writev`/`readv` helpers
- [ ] `crates/resetprop/src/seal/mod.rs` exports `SealRecord` and `SealTier::{Arena, Prop}` (defined by P01) plus the `OnceLock<Mutex<Vec<SealRecord>>>` registry accessor
- [ ] P02 and P04 are on parallel tracks per REGISTRY §5 — P04 does not depend on P02

(Source: P04 spec, Preconditions; REGISTRY §5)

## Branch

- [ ] Branch `feat/P04-tier-b-part2` created (or resumed) from latest main
- [ ] All commits follow `feat(seal):` / `fix(seal):` / `test(seal):` prefix per REGISTRY §2

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: A64 encoder submodule with fixed opcode consts and `const fn` helpers

- [x] Implementation: `crates/resetprop/src/seal/hook.rs` contains an inner `encoder` submodule with `pub const NOP: u32 = 0xd503201f;`, `pub const RET_X30: u32 = 0xd65f03c0;`, `pub const ISB_SY: u32 = 0xd5033fdf;`, `pub const SVC_0: u32 = 0xd4000001;`, `pub const BRK_0: u32 = 0xd4200000;`, `pub const LDR_X16_PC8: u32 = 0x58000050;`, `pub const BR_X16: u32 = 0xd61f0200;` plus `const fn` helpers for `svc`, `brk`, `ret`, `br`, `blr`, `ldr_literal`, `add_imm64`, `movz`, `movk`, `cbz`, `cbnz`, `b_rel`, `ldrb_imm`, `nop`, `isb`; each helper ≤5 lines with `assert!` guarding its immediate range (e.g., `imm12 < 4096`, signed branch offset fits 26 bits, imm19 fits ×4 range) — verified at `crates/resetprop/src/seal/hook.rs:407-540` (module body), consts at `hook.rs:426-444`, helpers at `hook.rs:447-539`
- [x] Test: `cargo test -p resetprop --lib seal::hook::encoder` — unit test reconstructs `trampoline_to(0x0000_7fff_abcd_1234)` from the helpers, asserts bytes `50 00 00 58  00 02 1f d6  34 12 cd ab  ff 7f 00 00` — verified by `trampoline_from_helpers_matches_reference` at `crates/resetprop/src/seal/hook.rs:655` (18/18 hook tests pass, full lib suite 107 passed, 0 failed)

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [x] **Optimality** — Considered alternative approach? Could a single encoder macro replace the `const fn`s? Is every helper ≤5 lines as the spec requires? Notes: Considered a `macro_rules!` variant that would fold all 15 encoders into one `enc!(name, mask, fields...)` invocation, but rejected because (a) per-helper doc-comments citing ARM DDI 0487 section numbers would become macro arguments and lose IDE hover, (b) `const fn` invocation participates in compile-time evaluation at call sites inside `const { }` while declarative macros expand to non-const tokens unless every input is itself `const`, and (c) the spec mandates exactly these 15 named entry points — a macro wrapper would add a layer of indirection for zero code-size saving under monomorphisation. Every helper is inside the ≤5-line budget: the three widest (`ldr_literal` at `hook.rs:476-481`, `cbz` at `hook.rs:502-507`, `cbnz` at `hook.rs:510-515`) each use exactly 5 body lines (one combined `rt < 32 && byte_offset % 4 == 0` assert, one `let imm19 = byte_offset / 4`, one `fits_signed(imm19, 19)` assert, one encoded-word return).
- [x] **Completeness** — Deliverable fully met spec §Tasks T1 (all 15 helpers + 7 consts present, all have immediate-range `assert!`)? Notes: All 7 consts present (`NOP=0xd503_201f` at `hook.rs:426`, `RET_X30=0xd65f_03c0` at `hook.rs:429`, `ISB_SY=0xd503_3fdf` at `hook.rs:432`, `SVC_0=0xd400_0001` at `hook.rs:435`, `BRK_0=0xd420_0000` at `hook.rs:438`, `LDR_X16_PC8=0x5800_0050` at `hook.rs:441`, `BR_X16=0xd61f_0200` at `hook.rs:444`) and pinned against REGISTRY §1 row `Trampoline LDR opcode for ldr x16,[pc,#8]` + references/arm64-a64-encoding.md lines 71-75, 285-286 via the `opcodes_match_canonical_values` test at `hook.rs:681`. All 15 helpers present: `svc` at `hook.rs:447`, `brk` at `hook.rs:452`, `ret` at `hook.rs:457`, `br` at `hook.rs:463`, `blr` at `hook.rs:469`, `ldr_literal` at `hook.rs:476`, `add_imm64` at `hook.rs:484`, `movz` at `hook.rs:490`, `movk` at `hook.rs:496`, `cbz` at `hook.rs:502`, `cbnz` at `hook.rs:510`, `b_rel` at `hook.rs:518`, `ldrb_imm` at `hook.rs:526`, `nop` at `hook.rs:532`, `isb` at `hook.rs:537`. Every helper that accepts a runtime register index or immediate carries an `assert!` guard: `rn/rd/rt < 32`, `imm12 < 4096`, `hw < 4`, `byte_offset % 4 == 0`, `fits_signed(imm19, 19)`, `fits_signed(imm26, 26)`. `svc`/`brk` accept the full `u16` domain of imm16 by construction (no assert needed — the type already bounds it). `nop`/`isb` return const opcodes and take no arguments. Module-level `#[allow(dead_code)]` at `hook.rs:406` is intentional: T2/T3 in this same phase are the first consumers of the symbols.
- [x] **Correctness** — Edge cases walked through: (1) imm12 = 4095 vs 4096 (should assert), (2) signed branch offset = 2^25 vs 2^25 + 4 (should assert), (3) `movz` `hw` field out-of-range, (4) register index 31 vs 32 boundary: (1) `add_imm64_rejects_imm12_equal_to_4096` at `hook.rs:700` exercises the boundary — imm12=4095 is accepted (bit 12 is zero), imm12=4096 panics at `assert!((imm12 as u32) < (1 << 12))` at `hook.rs:485`; `ldrb_imm_rejects_imm12_equal_to_4096` at `hook.rs:776` covers the same boundary for the LDRB unsigned-offset form. (2) `b_rel_rejects_imm26_overflow` at `hook.rs:768` uses `1 << 27` bytes = `2^25` words, one past the signed-26-bit positive limit `2^25 - 1`; the negative limit `-2^25` is still accepted. (3) `movz_rejects_hw_equal_to_4` at `hook.rs:744` and `movk_rejects_hw_equal_to_4` at `hook.rs:750` exercise the `hw < 4` invariant — `hw=3` accepted (LSL #48 on Xd), `hw=4` panics. (4) `ret_rejects_rn_equal_to_32` at `hook.rs:712`, `br_rejects_rn_equal_to_32` at `hook.rs:718`, `blr_rejects_rn_equal_to_32` at `hook.rs:724`, and `add_imm64_rejects_rd_equal_to_32` at `hook.rs:706` cover the 5-bit register-index boundary — `rn=31` (XZR/SP) accepted, `rn=32` panics at `assert!(rn < 32)`. The imm19 ×4 invariant is covered by both `ldr_literal_rejects_unaligned_offset` at `hook.rs:730` (`byte_offset=2` violates the `% 4 == 0` guard) and `ldr_literal_rejects_imm19_overflow` at `hook.rs:736` (`1 << 20` bytes = `2^18` words, one past the signed-19-bit positive limit `2^18 - 1`). Trampoline round-trip verified byte-for-byte at `hook.rs:655` against REGISTRY §1 canonical bytes.

### Task 2: `build_hook_body_bytes` — pure encoder helper emitting strcmp-loop hook body

- [x] Implementation: `pub fn build_hook_body_bytes(saved_prologue: [u8; 16], lock_list_vaddr: u64, return_addr: u64) -> Vec<u8>` returns encoded instruction bytes: `cbz x0, .fallthrough` → `add x9, x0, #96` → `ldr x10, =LOCK_LIST` → outer loop (`ldrb w11, [x10]` → `cbz w11, .fallthrough` → strcmp stub) → match exit (`movz w0, #0; ret`) → advance (`add x10, x10, #1; b .next_entry`) → fallthrough (4 saved prologue words + `ldr x16, =RESTORE_TARGET; br x16`) → literal `RESTORE_TARGET = return_addr` → literal `LOCK_LIST = lock_list_vaddr`. Body length matches `HOOK_BODY_BYTES` (23 words × 4 = 92 bytes per `arm64-a64-encoding.md §Hook body sketch`). The function operates on a local `Vec<u8>`, takes 3 parameters, is pure (no ptrace, no `process_vm_writev`), and is unit-testable without a tracee — verified at `crates/resetprop/src/seal/hook.rs:617-644` (function body), with `HOOK_BODY_TEMPLATE` const at `hook.rs:556-580` and patch-point consts (`STOLEN_START=13` at `hook.rs:584`, `RESTORE_LIT=19` at `hook.rs:586`, `LOCK_LIST_LIT=21` at `hook.rs:588`). Saved prologue is passed as `[u8; 16]` first argument per the user-locked signature; three-argument public shape preserved.
- [x] Test: `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_roundtrip` — round-trips the byte output: word 0 = `0xb400_01a0` (cbz x0, +52), word 1 = `0x9101_8009` (add x9, x0, #96), word 6 = `0x5280_0000` (movz w0, #0), word 7 = `0xd65f_03c0` (ret), STOLEN_START bytes 52..68 mirror `saved_prologue`, RESTORE_TARGET u64 at bytes 76..84 equals `return_addr`, LOCK_LIST u64 at bytes 84..92 equals `lock_list_vaddr` — verified at `crates/resetprop/src/seal/hook.rs:895-953` (21 tests pass, full lib suite 110 passed / 0 failed).
- [x] Test: `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_is_pure` confirms the helper is pure via a compile-time `let _: fn([u8; 16], u64, u64) -> Vec<u8> = build_hook_body_bytes;` coercion that binds the exact signature (no hidden `&self` / `&mut self` / tracer-bound parameter) plus a runtime zero-argument call asserting the spec-locked 92-byte length — verified at `crates/resetprop/src/seal/hook.rs:966-972`.

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [x] **Optimality** — Is the body the minimum size? Could the strcmp splice be inlined vs stubbed (spec calls for stubbed splice)? Notes: The 23-word template is the reference-canonical minimum — `references/arm64-a64-encoding.md §Hook body sketch` (lines 383-407) fixes the layout at 23 words × 4 = 92 bytes, and every word has a documented purpose in the layout table at `arm64-a64-encoding.md:352-369` (null guard, base+96, lock-list literal load, entry byte peek, sentinel check, strcmp stub, match exit, advance, padding×3, stolen×4, restore literal load, tail branch, 2-word RESTORE literal, 2-word LOCK_LIST literal). Inlining the 13-word strcmp body (§Strcmp loop skeleton at `arm64-a64-encoding.md:306-341`) into word 5 would violate the spec (§Approach item 1 of P04 spec explicitly calls for a stub at STRCMP_STUB=5 per `arm64-a64-encoding.md:377`) and would grow the body past the 92-byte budget unless the padding nops at words 10-12 were also repurposed — doing so would tangle T2's pure encoder with T3's installer logic, so the stub layout is kept. The template-plus-three-overwrites approach beats emitting word-by-word through the encoder helpers (`cbz_x(...)`, `add_imm64(...)`, etc.) because the reference already pins each fixed word's hex value at `arm64-a64-encoding.md:383-407`; a regression in those hex literals should surface at build time via the `build_hook_body_bytes_constants_from_reference` pin test (`hook.rs:981-1003`) rather than as a diff in re-encoded bit fields.
- [x] **Completeness** — All three patch regions filled: STOLEN_START (words 13..=16), RESTORE_LIT (words 19..=20), LOCK_LIST_LIT (words 21..=22)? Strcmp entry branch re-targeted to `.on_match`/`.advance`? Notes: All three patch regions are filled in `build_hook_body_bytes` at `hook.rs:617-644`. Region 1 decodes `saved_prologue: [u8; 16]` into four little-endian `u32` words and writes them to `body[STOLEN_START..STOLEN_START + 4]` (words 13..=16) at `hook.rs:625-633`; the `build_hook_body_bytes_roundtrip` test asserts `bytes[52..68] == [0xAB; 16]` at `hook.rs:946-950`. Region 2 writes `return_addr as u32` and `(return_addr >> 32) as u32` to `body[RESTORE_LIT]` and `body[RESTORE_LIT + 1]` (words 19..=20) at `hook.rs:636-637`; the test asserts `u64::from_le_bytes(bytes[76..84]) == 0xDEAD_BEEF_CAFE_BABE` at `hook.rs:953-959`. Region 3 writes `lock_list_vaddr as u32` and `(lock_list_vaddr >> 32) as u32` to `body[LOCK_LIST_LIT]` and `body[LOCK_LIST_LIT + 1]` (words 21..=22) at `hook.rs:640-641`; the test asserts `u64::from_le_bytes(bytes[84..92]) == 0x1111_2222_3333_4444` at `hook.rs:962-968`. The strcmp entry branch at word 5 (`0x1400_0003`, `b .advance` +12 per `arm64-a64-encoding.md:389`) is intentionally left as a stub in T2 scope — T3 (`install_trampoline`) is responsible for splicing the 13-word `STRCMP_BODY` over word 5 and re-targeting its exit branches to `.on_match` (word 6) and `.advance` (word 8) per P04 spec §Approach item 1 and `arm64-a64-encoding.md:377`. T2's contract is the template emission with the three LITERAL patches; the splice is install-time work.
- [x] **Correctness** — Edge cases: (1) null prop_info → cbz fires → fallthrough; (2) empty lock-list (first byte is sentinel NUL) → second cbz fires → fallthrough; (3) name match on first entry; (4) name match on last entry before sentinel; (5) no-match fallthrough preserves x0/x1/w2 correctly for the saved prologue: (1) Word 0 is `cbz x0, +52` (`0xb400_01a0`), pinned at `hook.rs:557` and asserted at `hook.rs:918-922`; offset +52 reaches word 13 = STOLEN_START where the 4 saved-prologue words are re-materialised before the `ldr x16, =RESTORE_TARGET; br x16` tail at words 17-18, so a null `x0` jumps past the whole lock-list walk and resumes the original libc prologue intact. (2) Word 4 is `cbz w11, +36` (`0x3400_012b`) at `hook.rs:561`; with `w11` loaded by `ldrb w11, [x10]` at word 3 (`0x3940_014b`, `hook.rs:560`), a sentinel NUL at the head of the lock-list (the initial state after P03's stage-B zero-sentinel write at `hook.rs:310-312`) triggers the fallthrough at offset +36 = word 13. (3) First-entry match is governed by word 5's strcmp stub (`0x1400_0003`, +12 = word 8 `.advance` in the T2 template); T3 will splice the strcmp body so a full-name match at the first entry flows into word 6 = `movz w0, #0` / word 7 = `ret` at `hook.rs:563-564` (asserted at `hook.rs:933-937`). (4) Last-entry-before-sentinel behaves identically — the outer loop at word 9 = `b .next_entry` (`0x17ff_fffa`, -24 = word 3) increments `x10` past the matched entry's NUL via word 8's `add x10, x10, #1` (`0x9100_054a`) and the next iteration's `ldrb w11, [x10]` reads the trailing sentinel NUL triggering case (2) fallthrough. (5) Register preservation — the template only clobbers `x9`, `x10`, `w11`, and `w0`; on fallthrough the 4 stolen prologue words at words 13..=16 execute in the same register state the tracee saw at entry minus those four, and standard AAPCS64 treats `x9`-`x15` as caller-saved scratch, so `x0` (prop_info pointer), `x1` (value pointer), and `w2` (length) remain undisturbed for the stolen prologue's own spill/`stp`/`mov x29, sp` pattern (P04 spec §Approach item 1, `arm64-a64-encoding.md:353-354` ABI-preserved callout). `w0` is clobbered only on the match-exit path, which `ret`s immediately.

### Task 3: `install_trampoline` writes hook body + 16-byte trampoline + i-cache sync

- [ ] Implementation: `pub fn install_trampoline(handle: &mut HookHandle) -> Result<()>` — (1) computes lock_list_vaddr = `handle.hook_page + LOCK_LIST_OFFSET` (=0), hook_body_vaddr = `handle.hook_page + HOOK_BODY_OFFSET` (=4), return_addr = `handle.target_fn + 16`; (2) calls `build_hook_body_bytes(lock_list_vaddr, saved_prologue_vaddr, return_addr)` to get a `Vec<u8>`, then writes the result at hook_body_vaddr via `process_vm_writev`; (3) writes 16-byte `[LDR_X16_PC8.to_le_bytes(), BR_X16.to_le_bytes(), (hook_body_vaddr as u64).to_le_bytes_lo, hi]` at `handle.target_fn`; (4) i-cache sync: primary path calls `remote_syscall(pid, __NR_membarrier=283, [MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE=0x80, 0, 0, 0, 0, 0])`, fallback on `EINVAL`/`EPERM` stages `ISB_SY=0xd5033fdf` at a scratch slot and flips `pc` for a single step; (5) returns `Error::SealHookError(String)` on any write failure; installer contains no opcode-encoding logic — bytes come entirely from `build_hook_body_bytes`
- [ ] Test: `cargo test -p resetprop --test tier_b_child_smoke -- --ignored --test-threads=1` reaches the final assertion block without `Err(Error::SealHookError(_))`; parent's `install_init_hook(...)` + `install_trampoline(...)` both return `Ok`

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [ ] **Optimality** — Why two writes (body first, trampoline second) rather than one? Because hook body must be materialized before init may be scheduled onto the trampoline — ordering matters. Notes: ___________________________
- [ ] **Completeness** — Both writes confirmed via `process_vm_readv` echo before returning Ok? i-cache sync attempted on BOTH paths (primary + fallback)? Error surface maps correctly to `SealHookError`? Notes: ___________________________
- [ ] **Correctness** — Edge cases: (1) `process_vm_writev` returns partial bytes (loop until complete); (2) `membarrier` returns `EPERM` because registration step was skipped — fallback must trigger; (3) concurrent init thread executing the function during the 16-byte write (documented race, accepted; mitigated by writing body first so the trampoline target is always valid); (4) target_fn not 16-byte aligned — spec requires 4-byte alignment only, document that: ___________________________

### Task 4: Lock-list mechanics — `seal_prop` append, `unseal_prop` compact

- [ ] Implementation: `pub fn seal_prop(handle: &HookHandle, name: &str) -> Result<()>` rejects `name` containing interior NUL, computes tail offset from `handle.lock_list_len`, writes `name.as_bytes()` + NUL via `process_vm_writev` at `handle.hook_page + LOCK_LIST_OFFSET + tail`, writes trailing empty-sentinel NUL at the new end, only then advances `handle.lock_list_len` (held in tracer-side `HookHandle`, plus optional mirror in the hook page header if the hook body reads length vs. relies on sentinel — spec says sentinel-only, so length is tracer-side). `pub fn unseal_prop(handle: &HookHandle, name: &str) -> Result<bool>` reads the entire lock-list region via `process_vm_readv`, searches for exact `name\0` match, if found writes the compacted buffer (shift subsequent entries left over the removed slot, write new trailing sentinel) back via `process_vm_writev` and returns `Ok(true)`; returns `Ok(false)` if not present
- [ ] Test: `cargo test -p resetprop --lib seal::hook::lock_list` — `test_lock_list_append_then_remove` on a locally allocated fake hook page (1024-byte Vec<u8> initialised to zeros) asserts: (1) after 3 seals ["a", "bb", "ccc"], bytes are `"a\0bb\0ccc\0\0"`; (2) after unseal "bb", bytes are `"a\0ccc\0\0"`; (3) unseal nonexistent name returns Ok(false) and leaves bytes unchanged

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [ ] **Optimality** — Why tracer-side length vs. hook-readable length in the page? Because the hook body uses sentinel-only traversal per spec §Task 1 strcmp-loop design — simpler, no atomic required on the length. Notes: ___________________________
- [ ] **Completeness** — Atomic-append invariant respected: (a) entry bytes → (b) new sentinel → (c) length. Partial-write loop around `process_vm_writev`? Compaction preserves order for remaining entries? Notes: ___________________________
- [ ] **Correctness** — Edge cases: (1) seal name that's already sealed (current behavior: append duplicate — document or reject?); (2) unseal on empty list; (3) unseal removes last entry, sentinel stays at offset 0; (4) name with 0-length; (5) name > remaining lock-list capacity (return error rather than overflow into hook body): ___________________________

### Task 5: `PropSystem::seal` / `unseal` / `seals` API + tier_b_child_smoke integration test

- [ ] Implementation: `crates/resetprop/src/lib.rs` adds `hook_handle: OnceLock<Mutex<Option<HookHandle>>>` field on `PropSystem`; `pub fn seal(&self, name: &str, value: &str) -> Result<SealRecord>` at lib.rs:~500 (adjacent to `set_stealth_persist` at 497) does (1) reject with `Error::InvalidKey` if `PropertyContext::resolve(name)` returns the `properties_serial` arena filename — guard runs BEFORE any ptrace work, matching P02 `seal_arena`; (2) bind `let arena_path = self.context.as_ref().ok_or(Error::NotFound)?.resolve(name).ok_or(Error::NotFound)?.to_string();` from `PropertyContext::resolve` (`context.rs:367-376`); (3) `self.set_stealth(name, value)?`; (4) lazy-init via `self.hook_handle.get_or_init(|| Mutex::new(None))`, lock the Mutex, if inner is None call `seal::hook::install_init_hook(1)?` and store; (5) call `seal::hook::seal_prop(handle, name)?`; (6) push `SealRecord { name: name.to_string(), arena_path, tier: SealTier::Prop, sealed_at: SystemTime::now() }` onto the shared registry (defined by P01 in `seal/mod.rs`); (7) return the record. `pub fn unseal(&self, name: &str) -> Result<bool>` calls `seal::hook::unseal_prop(handle, name)` then removes the matching `tier == Prop` record. `pub fn seals(&self) -> Result<Vec<SealRecord>>` clones the registry. Integration test file at `crates/resetprop/tests/tier_b_child_smoke.rs` per `test-harness-patterns.md §5`: `#[no_mangle] pub extern "C" fn __system_property_update`, two `PinnedPi` ("locked.prop", "free.prop"), fork+loop pattern, parent installs hook, seals "locked.prop", asserts via `process_vm_readv`.
- [ ] Test: `cargo build -p resetprop` compiles with no warnings; `cargo test -p resetprop --test tier_b_child_smoke -- --ignored --test-threads=1` passes both assertions: `locked.prop` bytes unchanged AND `free.prop` bytes differ pre→post hook install

#### Self-Audit Gate 5 (MANDATORY before Phase End)

- [ ] **Optimality** — `OnceLock<Mutex<Option<HookHandle>>>` vs plain `Mutex<Option<HookHandle>>`? OnceLock avoids unconditional lock-init cost on read-only `seals()` call. Notes: ___________________________
- [ ] **Completeness** — All three public methods present? Registry reused from P02 (not a second registry)? Test file has `#[ignore]` + doc-comment with exact invocation? `.cargo/config.toml` `--export-dynamic` rustflag confirmed per test-harness-patterns.md §5? Notes: ___________________________
- [ ] **Correctness** — Edge cases: (1) `seal()` called when `install_init_hook` returns Err — hook_handle stays None for retry; (2) concurrent `seal()` calls serialized by the Mutex; (3) `unseal()` on a never-sealed name returns Ok(false), registry unchanged; (4) `seals()` returns empty Vec before any seal; (5) test fails if `--export-dynamic` missing — document in test file comment: ___________________________

## Functional Requirements (subsystem-level)

### A64 Encoder (per `arm64-a64-encoding.md` §Instruction Table)

- [ ] FR-01: `NOP` const equals `0xd503201f` (per arm64-a64-encoding.md table row `nop`) — file:line after verification
- [ ] FR-02: `RET_X30` const equals `0xd65f03c0` (per arm64-a64-encoding.md table row `ret x30`) — file:line after verification
- [ ] FR-03: `ISB_SY` const equals `0xd5033fdf` (per arm64-a64-encoding.md table row `isb (SY)`) — file:line after verification
- [ ] FR-04: `LDR_X16_PC8` const equals `0x58000050` (per arm64-a64-encoding.md §Absolute-target trampoline) — file:line after verification
- [ ] FR-05: `BR_X16` const equals `0xd61f0200` (per arm64-a64-encoding.md §Absolute-target trampoline) — file:line after verification
- [ ] FR-06: Every encoder helper asserts its immediate range (e.g., `add_imm64` rejects imm12 ≥ 4096) (per spec §Tasks T1 "bit-field assert! on immediate ranges")

### Hook Body (per `arm64-a64-encoding.md` §Hook body sketch)

- [ ] FR-07: `build_hook_body_bytes` emits a null-guard `cbz x0, .fallthrough` as the first word (per arm64-a64-encoding.md §Hook body sketch word 0) — file:line after verification
- [ ] FR-07a: `build_hook_body_bytes` is a pure function returning `Vec<u8>` with no ptrace or `process_vm_writev` dependency — verified by running `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_roundtrip` without any test harness (per spec §Tasks T2)
- [ ] FR-08: `build_hook_body_bytes` loads `&pi->name` via `add x9, x0, #96`, using `PROP_INFO_NAME_OFFSET = 96` (per aosp-property-system.md §1 `static_assert(sizeof(prop_info) == 96)`) — file:line after verification
- [ ] FR-09: On name match the hook returns `mov w0, #0; ret` (per aosp-property-system.md §3 `Update` returns 0 on success)
- [ ] FR-10: On fallthrough the hook restores 4 saved prologue words then `ldr x16, =RESTORE_TARGET; br x16` to `target_fn + 16` (per arm64-a64-encoding.md §Hook body sketch install-time patching rules)
- [ ] FR-11: The `RESTORE_TARGET` literal at words 19..=20 holds `target_fn + 16` as little-endian u64 (per arm64-a64-encoding.md §Hook body sketch)
- [ ] FR-12: The `LOCK_LIST` literal at words 21..=22 holds `hook_page + LOCK_LIST_OFFSET` as little-endian u64 (per arm64-a64-encoding.md §Hook body sketch)

### Trampoline Installation (per `arm64-a64-encoding.md` §Absolute-target trampoline + `linux-arm64-abi.md` §10)

- [ ] FR-13: `install_trampoline` obtains the hook body from `build_hook_body_bytes(...)` and writes the 92-byte result at `hook_page + HOOK_BODY_OFFSET` BEFORE writing the 16-byte trampoline at `target_fn` (write-order invariant — body ready before init is re-entered via the trampoline)
- [ ] FR-14: `install_trampoline` writes all bytes of each region via `process_vm_writev`, looping on partial returns (per linux-arm64-abi.md §10 partial-transfer semantics)
- [ ] FR-15: i-cache sync primary path issues remote `membarrier(0x80, 0, 0)` via `__NR_membarrier = 283` (per linux-arm64-abi.md §1)
- [ ] FR-16: i-cache sync fallback executes `ISB` in the tracee via register flip when `membarrier` returns `EINVAL`/`EPERM` (per spec §Tasks T3)
- [ ] FR-17: Any `process_vm_writev` failure is converted to `Error::SealHookError` (per resetprop-rs-integration.md §4 seal error variants)

### Lock-List Mechanics (per spec §Tasks T4)

- [ ] FR-18: `seal_prop` writes entry bytes (name + NUL), then trailing sentinel NUL, then advances tracer-side length counter (in that exact order) — atomic-append invariant guarantees hook iterator never observes half-written entries
- [ ] FR-19: `unseal_prop` returns `Ok(true)` and compacts remaining entries left on match; returns `Ok(false)` without modifying the page if name absent
- [ ] FR-20: `seal_prop` rejects names containing interior NUL (invalid C-string sentinel) with a typed error
- [ ] FR-21: Lock list has a single trailing empty-string sentinel NUL at all times (append and compact both preserve this)

### PropSystem API (per `resetprop-rs-integration.md` §3 + spec §Tasks T5)

- [ ] FR-22: `PropSystem::seal(name, value)` calls `self.set_stealth(name, value)` first, THEN installs/reuses hook, THEN appends SealRecord (stealth write never skipped — per plan §Internal flow step 1)
- [ ] FR-22a: `PropSystem::seal` rejects any name whose `PropertyContext::resolve` returns the `properties_serial` arena filename with `Error::InvalidKey` BEFORE any ptrace work occurs — same guard as `PropSystem::seal_arena` in P02 (per REGISTRY §1 "Arenas NOT to touch"; `aosp-property-system.md §11`; system_properties.cpp:325-333) — verified at crates/resetprop/src/lib.rs:___
- [ ] FR-23: `PropSystem::seal` lazily installs the init hook on first call via `OnceLock`; subsequent calls reuse the same `HookHandle` (per spec §Tasks T5)
- [ ] FR-24: `PropSystem::seal` pushes `SealRecord { tier: SealTier::Prop, ... }` onto the same shared in-memory registry P02 uses for `SealTier::Arena` (per spec §Approach item 5)
- [ ] FR-25: `PropSystem::unseal(name)` calls `seal::hook::unseal_prop` and removes only records where `tier == Prop`; arena seals are untouched
- [ ] FR-26: `PropSystem::seals()` returns a clone (not a reference) of the combined registry; repeated calls never share mutable state

### Integration Test (per `test-harness-patterns.md` §5)

- [ ] FR-27: Test binary defines `#[no_mangle] pub extern "C" fn __system_property_update(pi: *mut u8, value: *const u8, len: u32) -> libc::c_int` (per test-harness-patterns.md §5)
- [ ] FR-28: Test constructs two `PinnedPi` with names "locked.prop" and "free.prop" using 96-byte header + name bytes layout (per test-harness-patterns.md §6)
- [ ] FR-29: Parent reads pi->value bytes via `process_vm_readv` both pre-seal and post-seal (per test-harness-patterns.md §5 `read_remote_value`)
- [ ] FR-30: Test asserts `locked_before == locked_after` (hook blocked update) and `free_before != free_after` (pass-through worked) (per test-harness-patterns.md §11 Assertions)
- [ ] FR-31: Test file has `#[ignore]` attribute and doc-comment line specifying `cargo test --test tier_b_child_smoke -- --ignored --test-threads=1` (per test-harness-patterns.md §12)

## Test Criteria

- [ ] TC-01: `cargo test -p resetprop --lib seal::hook` passes 0 failures (per spec §Validation) — annotate with test function names after run
- [ ] TC-02: `cargo test -p resetprop --test tier_b_child_smoke -- --ignored --test-threads=1` passes 0 failures (per spec §Validation) — must run on Linux host with `/proc/sys/kernel/yama/ptrace_scope <= 1` or CAP_SYS_PTRACE (per linux-arm64-abi.md §11)
- [ ] TC-03: `cargo test -p resetprop` (full regression) passes 0 failures — no regression in P01/P02/P03 modules (per spec §Validation)
- [ ] TC-04: `cargo build -p resetprop --release` produces no new warnings (per REGISTRY §2 build target)
- [ ] TC-05: Disassembling the output of `build_hook_body_bytes(0, 0, 0)` in the encoder unit test reproduces the expected `cbz x0, .fallthrough; add x9, x0, #96; ...` sequence (per spec §Tasks T2 verification)
- [ ] TC-05a: `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_roundtrip` exits 0 without invoking ptrace or any forked-child harness (per spec §Tasks T2 — pure helper)
- [ ] TC-06: The encoder unit test constructs the trampoline via helpers and compares byte-for-byte to `0x5800_0050, 0xd61f_0200, <target LE>` (per arm64-a64-encoding.md §Absolute-target trampoline example)

## Integration Verification

- [ ] IV-01: Consumes `HookHandle`, `install_init_hook`, `seal::elf::resolve_symbol`, hook-page allocation from P03 (per spec §Preconditions)
- [ ] IV-02: Consumes `SealRecord`, `SealTier::{Arena, Prop}`, and the shared in-memory registry defined by P01 in `seal/mod.rs` — P04 is on a parallel track with P02 per REGISTRY §5 (per spec §Approach item 5)
- [ ] IV-03: Consumes `PropSystem::set_stealth` at `crates/resetprop/src/lib.rs:458` (per resetprop-rs-integration.md §3)
- [ ] IV-04: Consumes `process_vm_writev`/`process_vm_readv` + remote syscall injector from P01's `seal/ptrace.rs` (per spec §Preconditions)
- [ ] IV-05: Downstream exposes `PropSystem::seal`, `PropSystem::unseal`, `PropSystem::seals` — consumed by P05 CLI (per spec §Objective and plan §New CLI surface)
- [ ] IV-06: Placement neighbors preserved — new methods sit at `lib.rs:~500`, directly adjacent to `set_stealth_persist` at lib.rs:497 (per resetprop-rs-integration.md §3 and spec §Scope)

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `PROP_INFO_NAME_OFFSET` | 96 (REGISTRY §1 "prop_info layout — name at offset 96"; aosp-property-system.md §1 `static_assert(sizeof(prop_info) == 96)` at prop_info.h:89) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `HOOK_BODY_OFFSET` (inside hook_page) | 4 (P04 spec §Approach item 4 — byte 0 is empty-list sentinel NUL, bytes 1..=3 zero-pad, hook body starts at byte 4) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `LOCK_LIST_OFFSET` (inside hook_page) | 0 (P04 spec §Approach item 4) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` | `0x80` (arm64-a64-encoding.md §i-cache invalidation options; linux/membarrier.h cmd enum value) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `__NR_membarrier` | 283 (linux-arm64-abi.md §1 citations table: `asm-generic/unistd.h:683`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| Trampoline size | 16 bytes (REGISTRY §1 "Trampoline — 16 bytes at symbol entry"; arm64-a64-encoding.md §Absolute-target trampoline "4 words (16 bytes)") | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `ISB` opcode | `0xd5033fdf` (arm64-a64-encoding.md §Instruction Table row `isb (SY)`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `RET` opcode | `0xd65f03c0` (arm64-a64-encoding.md §Instruction Table row `ret (x30)`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `LDR x16,[pc,#8]` opcode | `0x58000050` (arm64-a64-encoding.md §Absolute-target trampoline, `TRAMPOLINE_LDR_X16`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `BR x16` opcode | `0xd61f0200` (arm64-a64-encoding.md §Absolute-target trampoline, `TRAMPOLINE_BR_X16`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `NOP` opcode | `0xd503201f` (arm64-a64-encoding.md §Instruction Table row `nop`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `SVC #0` opcode | `0xd4000001` (arm64-a64-encoding.md §Instruction Table row `svc #0`; linux-arm64-abi.md §2 `ARM64_SVC_0`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `BRK #0` opcode | `0xd4200000` (arm64-a64-encoding.md §Instruction Table row `brk #0`; linux-arm64-abi.md §2 `ARM64_BRK_0`) | `crates/resetprop/src/seal/hook.rs:<line>` after verification |
| `properties_serial` rejection path | `/dev/__properties__/properties_serial` returned by `PropertyContext::resolve` → `PropSystem::seal` returns `Error::InvalidKey` BEFORE any ptrace work (REGISTRY §1 row "Arenas NOT to touch"; `aosp-property-system.md §11`) | `crates/resetprop/src/lib.rs:<line>` inside `PropSystem::seal` guard |

## Anti-Scope (explicitly excluded)

- AS-01: No CLI flag wiring for `-sl`, `--seal`, `--unseal`, `--seals` (P05 scope) (per P04 spec §Anti-Scope)
- AS-02: No on-disk persistence of `SealRecord` (deferred per plan §Decisions locked) (per P04 spec §Anti-Scope)
- AS-03: No arena remap logic — `seal_arena`/`unseal_arena` is P02 scope, already complete (per P04 spec §Anti-Scope)
- AS-04: No ELF parsing, symbol resolution, hook page allocation, or `install_init_hook` stage-A+B — P03 scope (per P04 spec §Anti-Scope)
- AS-05: No propdetect heuristic updates (deferred per plan §Decisions locked; plan §Touchpoints for propdetect) (per P04 spec §Anti-Scope)
- AS-06: No README.md edits (P05 scope) (per P04 spec §Anti-Scope)
- AS-07: No `tests/device-stress-test.sh` modifications (P05 scope — Tests 21/22) (per P04 spec §Anti-Scope)

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment (Task 5) completes. NOT after each task.

- [ ] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template) with: phase spec path `phases/seal/P04-tier-b-part2.md`, checklist path `phases/seal/checklists/P04-checklist.md`, REGISTRY path `phases/seal/REGISTRY-P.md`, code file paths (`crates/resetprop/src/seal/hook.rs`, `crates/resetprop/src/lib.rs`, `crates/resetprop/tests/tier_b_child_smoke.rs`), branch name `feat/P04-tier-b-part2`, External API Verification flag = YES and sources (aosp-property-system.md, arm64-a64-encoding.md, linux-arm64-abi.md, bionic/libc/system_properties/system_properties.cpp:270-336, bionic/libc/system_properties/include/system_properties/prop_info.h:89)
- [ ] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block
- [ ] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block
- [ ] Both agents dispatched IN PARALLEL (single message, two Agent tool calls)
- [ ] Because `External API Verification: YES`, both agents grep'd/read the listed sources and quoted real signatures (AOSP `Update` prototype at system_properties.cpp:270, `prop_info.h:89` static_assert, libc `__system_property_update` ABI)
- [ ] code-reviewer report saved at `phases/seal/audits/P04-audit.md` — verdict: PASS | NEEDS_FIX
- [ ] critic report saved at `phases/seal/audits/P04-audit.md` — verdict: PASS | NEEDS_FIX
- [ ] All CRITICAL findings resolved
- [ ] All MAJOR findings resolved
- [ ] MINOR findings logged (not blocking)
- [ ] Re-ran both agents after fixes; both emitted `VERDICT: PASS`

## Acceptance Gate

- [ ] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes on Optimality, Completeness, Correctness)
- [ ] All 31 FR items verified with code-location annotations
- [ ] All 6 TC items executed; all exit 0
- [ ] All 6 IV items verified; upstream consumes confirmed, downstream exposes confirmed
- [ ] No regressions in prerequisite phases — `cargo test -p resetprop` (full suite) and `cargo test -p resetprop --test tier_a_child_smoke -- --ignored --test-threads=1` (P02 regression) both pass
- [ ] Branch `feat/P04-tier-b-part2` commits clean; all conventional commits with `feat(seal):`, `fix(seal):`, or `test(seal):` prefix
- [ ] All 13 canonical values verified against cited authorities
- [ ] Gate 2 reports PASS from BOTH `code-reviewer` AND `critic` agents
- [ ] REGISTRY §4 row for P04 updated: `Status = COMPLETE`, branch, sessions, notes
- [ ] REGISTRY §7 session log appended with session date, phase P04, outcome, artifacts (audit report path)
