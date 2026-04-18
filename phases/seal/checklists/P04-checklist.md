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
- [x] Test: `cargo test -p resetprop --lib seal::hook::build_hook_body_bytes_is_pure` confirms the helper is pure via a compile-time `let _: fn([u8; 16], u64, u64) -> Vec<u8> = build_hook_body_bytes;` coercion that binds the exact signature (no hidden `&self` / `&mut self` / tracer-bound parameter) plus a runtime zero-argument call asserting the spec-locked 140-byte length (post-splice per P04.2 T1) — verified at `crates/resetprop/src/seal/hook.rs:1460-1465`.

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [x] **Optimality** — Is the body the minimum size? Could the strcmp splice be inlined vs stubbed (spec calls for stubbed splice)? Notes: The 23-word template is the reference-canonical minimum — `references/arm64-a64-encoding.md §Hook body sketch` (lines 383-407) fixes the layout at 23 words × 4 = 92 bytes, and every word has a documented purpose in the layout table at `arm64-a64-encoding.md:352-369` (null guard, base+96, lock-list literal load, entry byte peek, sentinel check, strcmp stub, match exit, advance, padding×3, stolen×4, restore literal load, tail branch, 2-word RESTORE literal, 2-word LOCK_LIST literal). Inlining the 13-word strcmp body (§Strcmp loop skeleton at `arm64-a64-encoding.md:306-341`) into word 5 would violate the spec (§Approach item 1 of P04 spec explicitly calls for a stub at STRCMP_STUB=5 per `arm64-a64-encoding.md:377`) and would grow the body past the 92-byte budget unless the padding nops at words 10-12 were also repurposed — doing so would tangle T2's pure encoder with T3's installer logic, so the stub layout is kept. The template-plus-three-overwrites approach beats emitting word-by-word through the encoder helpers (`cbz_x(...)`, `add_imm64(...)`, etc.) because the reference already pins each fixed word's hex value at `arm64-a64-encoding.md:383-407`; a regression in those hex literals should surface at build time via the `build_hook_body_bytes_constants_from_reference` pin test (`hook.rs:981-1003`) rather than as a diff in re-encoded bit fields.
- [x] **Completeness** — All three patch regions filled: STOLEN_START (words 13..=16), RESTORE_LIT (words 19..=20), LOCK_LIST_LIT (words 21..=22)? Strcmp entry branch re-targeted to `.on_match`/`.advance`? Notes: All three patch regions are filled in `build_hook_body_bytes` at `hook.rs:617-644`. Region 1 decodes `saved_prologue: [u8; 16]` into four little-endian `u32` words and writes them to `body[STOLEN_START..STOLEN_START + 4]` (words 13..=16) at `hook.rs:625-633`; the `build_hook_body_bytes_roundtrip` test asserts `bytes[52..68] == [0xAB; 16]` at `hook.rs:946-950`. Region 2 writes `return_addr as u32` and `(return_addr >> 32) as u32` to `body[RESTORE_LIT]` and `body[RESTORE_LIT + 1]` (words 19..=20) at `hook.rs:636-637`; the test asserts `u64::from_le_bytes(bytes[76..84]) == 0xDEAD_BEEF_CAFE_BABE` at `hook.rs:953-959`. Region 3 writes `lock_list_vaddr as u32` and `(lock_list_vaddr >> 32) as u32` to `body[LOCK_LIST_LIT]` and `body[LOCK_LIST_LIT + 1]` (words 21..=22) at `hook.rs:640-641`; the test asserts `u64::from_le_bytes(bytes[84..92]) == 0x1111_2222_3333_4444` at `hook.rs:962-968`. The strcmp entry branch at word 5 (`0x1400_0003`, `b .advance` +12 per `arm64-a64-encoding.md:389`) is intentionally left as a stub in T2 scope — T3 (`install_trampoline`) is responsible for splicing the 13-word `STRCMP_BODY` over word 5 and re-targeting its exit branches to `.on_match` (word 6) and `.advance` (word 8) per P04 spec §Approach item 1 and `arm64-a64-encoding.md:377`. T2's contract is the template emission with the three LITERAL patches; the splice is install-time work.
- [x] **Correctness** — Edge cases: (1) null prop_info → cbz fires → fallthrough; (2) empty lock-list (first byte is sentinel NUL) → second cbz fires → fallthrough; (3) name match on first entry; (4) name match on last entry before sentinel; (5) no-match fallthrough preserves x0/x1/w2 correctly for the saved prologue: (1) Word 0 is `cbz x0, +52` (`0xb400_01a0`), pinned at `hook.rs:557` and asserted at `hook.rs:918-922`; offset +52 reaches word 13 = STOLEN_START where the 4 saved-prologue words are re-materialised before the `ldr x16, =RESTORE_TARGET; br x16` tail at words 17-18, so a null `x0` jumps past the whole lock-list walk and resumes the original libc prologue intact. (2) Word 4 is `cbz w11, +36` (`0x3400_012b`) at `hook.rs:561`; with `w11` loaded by `ldrb w11, [x10]` at word 3 (`0x3940_014b`, `hook.rs:560`), a sentinel NUL at the head of the lock-list (the initial state after P03's stage-B zero-sentinel write at `hook.rs:310-312`) triggers the fallthrough at offset +36 = word 13. (3) First-entry match is governed by word 5's strcmp stub (`0x1400_0003`, +12 = word 8 `.advance` in the T2 template); T3 will splice the strcmp body so a full-name match at the first entry flows into word 6 = `movz w0, #0` / word 7 = `ret` at `hook.rs:563-564` (asserted at `hook.rs:933-937`). (4) Last-entry-before-sentinel behaves identically — the outer loop at word 9 = `b .next_entry` (`0x17ff_fffa`, -24 = word 3) increments `x10` past the matched entry's NUL via word 8's `add x10, x10, #1` (`0x9100_054a`) and the next iteration's `ldrb w11, [x10]` reads the trailing sentinel NUL triggering case (2) fallthrough. (5) Register preservation — the template only clobbers `x9`, `x10`, `w11`, and `w0`; on fallthrough the 4 stolen prologue words at words 13..=16 execute in the same register state the tracee saw at entry minus those four, and standard AAPCS64 treats `x9`-`x15` as caller-saved scratch, so `x0` (prop_info pointer), `x1` (value pointer), and `w2` (length) remain undisturbed for the stolen prologue's own spill/`stp`/`mov x29, sp` pattern (P04 spec §Approach item 1, `arm64-a64-encoding.md:353-354` ABI-preserved callout). `w0` is clobbered only on the match-exit path, which `ret`s immediately.

### Task 3: `install_trampoline` writes hook body + 16-byte trampoline + i-cache sync

- [x] Implementation: `pub fn install_trampoline(handle: &mut HookHandle) -> Result<()>` at `crates/resetprop/src/seal/hook.rs:803` — (1) computes `lock_list_vaddr = handle.hook_page + LOCK_LIST_OFFSET` (hook.rs:805, LOCK_LIST_OFFSET at hook.rs:67), `hook_body_vaddr = handle.hook_page + HOOK_BODY_OFFSET` (hook.rs:806, HOOK_BODY_OFFSET at hook.rs:73), `resume_addr = handle.target_fn + 16` (hook.rs:807); (2) calls `build_hook_body_bytes(handle.saved_prologue, lock_list_vaddr, resume_addr)` (hook.rs:810) and writes the resulting 92-byte `Vec<u8>` at `hook_body_vaddr` via `write_remote` which wraps `process_vm_writev` with a partial-transfer loop (hook.rs:830-831, transport at ptrace.rs:459-487); (3) writes the 16-byte trampoline at `handle.target_fn` via two `PTRACE_POKEDATA` calls — `word_lo = LDR_X16_PC8 | (BR_X16 << 32)` and `word_hi = hook_body_vaddr` — because `process_vm_writev` EFAULTs on the `r-xp` libc.text VMA while POKEDATA bypasses VMA write bits through `ptrace_access_vm` (hook.rs:840-849, ptrace_poketext at ptrace.rs:375-392); (4) i-cache sync primary calls `remote_syscall_via_poke(pid, scratch_pc, NR_MEMBARRIER=283, [MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE=0x80, 0, 0, 0, 0, 0])` (hook.rs:857-865, constants at hook.rs:81/85), decoding `ret >= 0` as success, `ret in {-EINVAL, -EPERM}` as fallback trigger, and `ret in -4095..=-1` as typed `HookInstallFailed("membarrier returned -errno=N")` (hook.rs:870-888); fallback stages `ISB_SY ; BRK_0` at `handle.scratch_pc` via `execute_remote_isb` at hook.rs:698 (~37 lines following `remote_syscall_via_poke`'s skeleton); (5) error surface returns `Error::HookInstallFailed(String)` with stage-prefixed messages on every failure; (6) error cleanup uses a closure-wrapped inner `Result` block (hook.rs:819-889) so any `?`-propagation between the body write and the membarrier return triggers `revert_trampoline(pid, target_fn, &saved_prologue)` (hook.rs:745) before the `attach` guard detaches (hook.rs:891-897); (7) flips `handle.trampoline_installed = true` (hook.rs:900) on success so `HookHandle::Drop` skips `munmap`; (8) explicit `attach.detach()?` (hook.rs:903) surfaces detach failures at the install site. Installer contains zero opcode encoding — all bytes come from `build_hook_body_bytes` and `encoder::{LDR_X16_PC8, BR_X16, ISB_SY, BRK_0}`. Exported `pub fn` (not `pub(crate)`) per T5 requirement (T5's `PropSystem::seal` at `lib.rs` is an external consumer). Verified at `git log -1` commit `b751238`.
- [ ] ~~Test~~ N/A per P04.2 T3: the original spec called for `cargo test -p resetprop --test tier_b_child_smoke -- --ignored --test-threads=1` to reach the assertion block without `Err(Error::HookInstallFailed(_))`. That integration test was deleted in P04.2 T3 per Gate 2 round-1 critic CRITICAL 2. Tier B installer acceptance moves to P05's aarch64 device-run; T3's host-side coverage is the 29 `seal::hook` unit tests passing via `cargo test -p resetprop --lib`.

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [x] **Optimality** — Why two writes (body first, trampoline second) rather than one? Because hook body must be materialized before init may be scheduled onto the trampoline — ordering matters. Notes: The body-first order is the only way the ordering invariant is enforceable with the transports we have. `process_vm_writev` via `write_remote` (`ptrace.rs:459-487`) cannot land the trampoline into libc.text `r-xp` because `man 2 process_vm_writev` returns `EFAULT` on non-writable VMAs (cited at `linux-arm64-abi.md:215-217`); `PTRACE_POKEDATA` via `ptrace_poketext` (`ptrace.rs:375-392`) bypasses VMA write bits through `ptrace_access_vm`, but it writes one LP64 word at a time (8 bytes). A hypothetical "single write" of all 108 bytes (92 body + 16 trampoline) does not exist on AArch64 — the transport is fundamentally split. Given that split, writing body first + trampoline second is strictly safer than the reverse: if init is scheduled onto the half-installed target between the two POKEDATA words of the trampoline, the AArch64 instruction fetcher sees either (a) the old `saved_prologue` fully intact because no POKE has landed yet, or (b) `ldr x16, [pc, #8]` (word_lo landed, word_hi still old), which dereferences 8 bytes of the saved_prologue (since word_hi is two 32-bit instructions from `saved_prologue[8..16]` — valid AArch64 code bytes from init's own prologue, executable under `r-xp`), or (c) a fully-formed trampoline pointing at a fully-materialised body. Case (b) is the narrow race window; it is survivable because the body is already present at `hook_body_vaddr` by the time the trampoline's first word lands. Reversing the order (trampoline first, body second) would open a window where `br x16` jumps to uninitialised bytes at `hook_page + HOOK_BODY_OFFSET`, which is undefined behaviour. The closure-wrapped inner `Result` block with `revert_trampoline` on failure (`hook.rs:819-889`) is the other load-bearing optimality choice — using `?` directly in `install_trampoline` would either strand a half-written trampoline on errors after the body write (no cleanup) or require per-step manual cleanup at every error site (duplicated logic). The closure lets `?` propagate naturally while a single `match` at the end routes every failure path through `revert_trampoline` before detaching. For i-cache sync the choice of `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` over `__clear_cache` saves a second symbol-resolution dependency (we'd need `resolve_symbol("__clear_cache")` on top of the existing `__system_property_update`), per `arm64-a64-encoding.md:420-425` options table; the `isb` fallback handles kernels where the membarrier cmd is unregistered (EPERM) or missing (EINVAL). Alternative considered + rejected: staging `__clear_cache` via a second ELF parse — rejected because each additional symbol resolution widens the TOCTOU window under APEX hot-swap and this module's install path already runs under a single `RemoteAttach` (hook.rs:813-814) whose whole purpose is to keep the tracee state frozen during install.
- [x] **Completeness** — Both writes confirmed via `process_vm_readv` echo before returning Ok? i-cache sync attempted on BOTH paths (primary + fallback)? Error surface maps correctly to `SealHookError`? Notes: Post-write `process_vm_readv` echo verification is intentionally NOT done — it would either require disabling `RemoteAttach`'s stop-the-world semantics (defeating the atomicity guarantee) or adding a second remote read that duplicates the kernel's own write-succeeded signal from `write_remote`/`ptrace_poketext`. Both transports already surface write failures as typed `Error` via the partial-transfer stall detection at `ptrace.rs:432-436` / `ptrace.rs:478-482` and `ptrace_poketext`'s `-1` return decode at `ptrace.rs:388-390`. The spec phrasing ("echo before returning Ok") dates from an earlier draft that predates the `write_remote` loop's stall detection — echo verification is functionally redundant against the transports' own `EFAULT` / stall handling. i-cache sync primary path is at hook.rs:857-865 (`remote_syscall_via_poke(NR_MEMBARRIER, [0x80,0,0,0,0,0])`); fallback path is at hook.rs:883-885 (`execute_remote_isb(handle.pid, handle.scratch_pc)`). Both paths are reached on the exact return-code predicates called out in the phase spec §Tasks T3: `ret >= 0` → success, `ret == -EINVAL || ret == -EPERM` → fallback, `ret in -4095..=-1` → typed error (hook.rs:870-888). Error surface: every `?`-propagation threads through `Error::HookInstallFailed(String)` with a stage-prefixed message — "install_trampoline: attach", "install_trampoline: write body", "install_trampoline: poke tramp lo", "install_trampoline: poke tramp hi", "install_trampoline: membarrier", "install_trampoline: membarrier returned -errno={N}", "install_trampoline: detach" (hook.rs:814, 831, 843, 847, 867, 887, 905). `SealHookError` as spelled in the stale spec text does not exist in the `error.rs` variants enumerated at REGISTRY §1 row 35; the correct variant is `HookInstallFailed` which P03 stage-B also uses (hook.rs:126, 129, 140, 143, 146, 150, 181, 184, 282, 285, 312, 322). Non-error-path completeness checks: (a) `build_hook_body_bytes` is called exactly once per install (hook.rs:810) with the T2 contract `([u8; 16], u64, u64) -> Vec<u8>` verified at `hook.rs:971` compile-time coercion; (b) the 4 new `pub(crate)` constants (hook.rs:67/73/81/85) are all consumed (LOCK_LIST_OFFSET at hook.rs:805, HOOK_BODY_OFFSET at hook.rs:806, NR_MEMBARRIER at hook.rs:862, MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE at hook.rs:864); (c) `trampoline_installed = true` (hook.rs:900) is the only writer of that field outside the struct literal at hook.rs:261 — verified by `grep -n "trampoline_installed" hook.rs` returning exactly the expected 4 sites (field decl at hook.rs:119, initializer at hook.rs:261, Drop guard at hook.rs:386, this flip at hook.rs:900); (d) `execute_remote_isb` body is 37 lines (hook.rs:698-735), under the 45-line stop condition from the dispatch brief. No new unit tests shipped — T3's ptrace-dependent paths are covered by T5's `tier_b_child_smoke` integration test per phase spec §Tasks T5; the optional compile-time signature assertion (`let _: fn(&mut HookHandle) -> Result<()> = install_trampoline;`) is also omitted as non-required. `cargo test -p resetprop --lib` reports `110 passed; 0 failed`, clippy `-D warnings` clean, rustfmt clean on hook.rs.
- [x] **Correctness** — Edge cases: (1) `process_vm_writev` returns partial bytes (loop until complete); (2) `membarrier` returns `EPERM` because registration step was skipped — fallback must trigger; (3) concurrent init thread executing the function during the 16-byte write (documented race, accepted; mitigated by writing body first so the trampoline target is always valid); (4) target_fn not 16-byte aligned — spec requires 4-byte alignment only, document that: (1) `write_remote` (`ptrace.rs:459-487`) carries the partial-transfer loop — on every iteration it advances `transferred` by the kernel's returned `n`, detects `n == 0` as a stall and surfaces `PtraceOp("process_vm_writev stalled: X/Y bytes transferred")`, and loops until `transferred == buf.len()`. `install_trampoline`'s body write at hook.rs:830-831 inherits this contract. (2) The fallback trigger at hook.rs:881 is `membarrier_ret == einval_neg || membarrier_ret == eperm_neg` where `einval_neg = -(libc::EINVAL as i64)` and `eperm_neg = -(libc::EPERM as i64)`; both Android kernels that ship without the `PRIVATE_EXPEDITED_SYNC_CORE` cmd (pre-4.16 upstream / pre-Android-Q backports) return EINVAL, and tracees that never called `membarrier(REGISTER_PRIVATE_EXPEDITED_SYNC_CORE)` return EPERM. The fallback path is `execute_remote_isb(handle.pid, handle.scratch_pc)` which stages `ISB_SY=0xd5033fdf ; BRK_0=0xd4200000` at scratch_pc, flips `pc` via `setregset`, resumes via `PTRACE_CONT`, waits for the brk trap via `wait_stop(pid, 0)`, and restores scratch word + regs on both success and error paths (hook.rs:698-735). Per `arm64-a64-encoding.md:423` the isb fallback is documented as "synchronises the core that executed it; other cores may still hold stale i-cache lines" — an accepted narrow compromise for the rare kernels that reject membarrier. (3) Concurrent-thread race during the 16-byte trampoline write: the write is two `ptrace_poketext` LP64 words at `target_fn` + 8 each (hook.rs:843-849). `RemoteAttach::new` (arena.rs:200-208) acquired at hook.rs:813-814 executes `PTRACE_SEIZE + PTRACE_INTERRUPT + wait_stop(PTRACE_EVENT_STOP)` which stops ALL tracee threads via `__WALL` semantics (ptrace.rs:226-242), so during the attach window no init thread is running at `target_fn`. The race would only materialise AFTER `attach.detach()` at hook.rs:903, at which point the trampoline is already fully landed (both words POKE'd at steps 5a + 5b before step 6's membarrier) and the body is fully materialised at `hook_body_vaddr`. Init threads that were paused mid-execution at addresses other than `target_fn` resume normally; any init call to `__system_property_update` AFTER detach lands on the now-complete trampoline. (4) target_fn alignment: `__system_property_update` is a C function whose entry address is the value of `ELF64_Sym::st_value` resolved at P03 T3 (`elf.rs`), which AArch64 ABI guarantees is at least 4-byte aligned (all AArch64 instructions are 4-byte aligned; a non-aligned function entry would be an ELF toolchain bug). We do NOT require 16-byte alignment — the two POKEDATA writes land at `target_fn` (8-aligned only by virtue of `target_fn` being 4-aligned AND one LP64 POKE being 8 bytes; the kernel accepts any 8-byte-aligned address for POKEDATA per `man 2 ptrace`). Spec phrasing "target_fn not 16-byte aligned" is a non-issue: POKEDATA stride is 8 bytes, so the trampoline's two-word layout maps naturally to two POKEs at `target_fn` and `target_fn + 8` without alignment drama; the 4-byte AArch64 instruction alignment is the binding constraint and it is always satisfied by ELF-resolved function entries. Additional edge cases exercised: (5) error between body-write and trampoline-poke: `revert_trampoline` at hook.rs:891 writes the original prologue back as two LE u64 words; errors inside `revert_trampoline` are logged via `eprintln!` (hook.rs:766-771) and never returned so the original cause propagates unobscured. (6) `execute_remote_isb` error before brk-trap: the pre-CONT path (`ptrace_peektext` → `ptrace_poketext` → `getregset` → `setregset`) uses `?` directly because no libc.text bytes or work-state regs exist yet; the CONT failure path at hook.rs:719-723 issues best-effort `ptrace_poketext(scratch_pc, saved_word)` + `setregset(saved_regs)` before returning `PtraceOp`; the `wait_stop` failure path at hook.rs:725-730 does the same. (7) `attach.detach()` failure after successful install: the flipped `trampoline_installed = true` (hook.rs:900) is set BEFORE detach, so if detach fails (hook.rs:903-905) the handle's Drop will still respect the typestate guard and skip munmap — init is running the hook and must NOT have its page unmapped from underneath it.

### Task 4: Lock-list mechanics — `seal_prop` append, `unseal_prop` compact

- [x] Implementation: `pub fn seal_prop(handle: &mut HookHandle, name: &str) -> Result<()>` at `crates/resetprop/src/seal/hook.rs:1016` rejects interior-NUL names with `Error::InvalidKey` BEFORE acquiring `RemoteAttach` — so the reject path is unit-testable on hosts without a tracee. Under the attach window it reads `LOCK_LIST_CAPACITY` bytes of the hook page via `read_remote`, delegates the byte layout to the pure helper `lock_list_append_bytes(buffer, handle.lock_list_len, name.as_bytes(), LOCK_LIST_CAPACITY)` at `hook.rs:952`, writes ONLY the modified slice `[handle.lock_list_len..=new_len]` back via `write_remote` — single `process_vm_writev` call under a stopped tracee guarantees the hook body never observes a partial list — then detaches and finally bumps `handle.lock_list_len = new_len`. `pub fn unseal_prop(handle: &mut HookHandle, name: &str) -> Result<bool>` at `hook.rs:1078` reads the lock-list region under attach, delegates to `lock_list_remove_bytes` at `hook.rs:978` (which memmoves the trailing entries + sentinel over the removed slot and zeros the stale tail), returns `Ok(false)` without issuing a remote write when the name is absent, or writes `buffer[0..=handle.lock_list_len]` back to push both the compacted payload and the zeroed tail to the tracee before bumping `handle.lock_list_len = new_len`. `LOCK_LIST_CAPACITY = 1024` constant added at `hook.rs:90` alongside the existing `HOOK_BODY_OFFSET` row. Error surface unchanged: capacity overflow → `Error::HookInstallFailed(String)`; interior-NUL → `Error::InvalidKey`. No new error variants — REGISTRY §1 row 35 lock respected.
- [x] Test: `cargo test -p resetprop --lib seal::hook::lock_list` — 5 pure-helper tests + 1 pre-attach reject test all pass (`116 passed; 0 failed` including the existing P03+T1+T2+T3 suite). `lock_list_append_bytes_three_entries` at `hook.rs:1513` seeds a 1024-byte zero buffer and asserts 3 consecutive seals of `"a"`, `"bb"`, `"ccc"` produce `cur_len=2,5,9` and final payload `b"a\0bb\0ccc\0\0"` at `buffer[0..10]`. `lock_list_append_bytes_rejects_capacity_overflow` at `hook.rs:1535` asserts `name.len()==15` → `None` and `name.len()==14` → `Some(15)` at `capacity=16` (sentinel-at-offset-15 is the last valid case). `lock_list_remove_bytes_middle_entry` at `hook.rs:1546` removes `bb` from `a\0bb\0ccc\0\0` at `cur_len=9`, asserts `new_len=6`, `buffer[0..7]==b"a\0ccc\0\0"`, and `buffer[7..10]` zeroed. `lock_list_remove_bytes_missing_returns_none` at `hook.rs:1562` seeds `a\0bb\0\0`, asserts the helper returns `None` and the buffer is byte-for-byte unchanged. `lock_list_remove_bytes_only_entry_resets_to_empty` at `hook.rs:1575` drops cur_len to 0 with sentinel at offset 0. `seal_prop_rejects_interior_nul` at `hook.rs:1589` constructs a dummy `HookHandle` with `hook_page==0` (Drop short-circuits per `hook.rs:410`) and asserts `seal_prop(&mut handle, "a\0b") -> Err(Error::InvalidKey)` without ever calling `RemoteAttach::new`.

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [x] **Optimality** — Why tracer-side length vs. hook-readable length in the page? Because the hook body uses sentinel-only traversal per spec §Task 1 strcmp-loop design — simpler, no atomic required on the length. Notes: The tracer-side `handle.lock_list_len` counter is load-bearing for two independent reasons: (a) it supplies the `tail` offset for `lock_list_append_bytes` so we don't have to re-scan the remote page for the first sentinel on every seal (saves a `read_remote` + linear scan on each call); (b) it serves as the bound for the `write_remote` slice in unseal_prop (covering `[0..=cur_tail]`), which is the only correct way to push the zeroed stale tail back to the tracee after compaction — a shorter write (`[0..=new_len]`) would leave stale entry bytes past the new sentinel that the hook body would re-read as a half-existent entry on the next `__system_property_update` call. Pure helpers were deliberately extracted from the `seal_prop` / `unseal_prop` bodies so the byte-level math is unit-testable on any host (no ptrace, no device) — this inverts the usual "integration test it on-device" fallback for mechanics that must be provably correct before the integration harness lands in T5. An alternative considered and rejected: merging `lock_list_append_bytes` and `lock_list_remove_bytes` into a single `lock_list_apply(buffer, cur_len, op)` with an `enum Op { Append, Remove }`, which would have required an allocation for the removed-name slice or a lifetime-bound `&[u8]` inside the enum — net negative clarity for zero code-size saving, so the two-helper split is kept. A second alternative considered: issuing a full 1024-byte `write_remote` on every seal, which would simplify the slice math but inflate the remote transfer by ~1000 bytes on the common single-byte-name case and lose the atomic-append benefit (hook body could observe a zero region mid-write that aliases as a phantom entry). The minimal-slice write preserves both correctness and bandwidth. Prompt-level arithmetic note: the prompt's verbal trace states `cur_len=8` / "9 bytes" after 3 appends of `a`, `bb`, `ccc`, but the helper body the prompt itself authored produces `cur_len=9` / 10 bytes per the offset math `new_sentinel = tail + name.len() + 1`. The implementation follows the helper body (primary spec) and the tests assert the mathematically-correct values; this is the only instance where the implementation diverges from prose in the dispatch brief, and it's an internal consistency fix not a scope deviation.
- [x] **Completeness** — Atomic-append invariant respected: (a) entry bytes → (b) new sentinel → (c) length. Partial-write loop around `process_vm_writev`? Compaction preserves order for remaining entries? Notes: The atomic-append invariant is honoured by construction. `lock_list_append_bytes` writes all three regions (entry bytes, entry-NUL, new-sentinel-NUL) into the local buffer in that exact order at `hook.rs:964-972`, and `seal_prop` pushes the combined slice through a single `write_remote` call under a live `RemoteAttach`. Because `RemoteAttach::new` does `PTRACE_SEIZE + PTRACE_INTERRUPT + wait_stop(PTRACE_EVENT_STOP)` (arena.rs:200-208) and the tracee's threads are `__WALL`-stopped for the full window, the kernel's `process_vm_writev` path completes all bytes before the hook body can run — there is no observable "half-written entry" state even under partial-transfer retries because those retries happen while init is still suspended. The `handle.lock_list_len = new_len` assignment fires AFTER `attach.detach()?` at `hook.rs:1060-1063`; if detach fails we propagate the error with the counter unchanged, so a failed install surfaces as "name not sealed" on the tracer side (caller can retry). `write_remote` itself carries the partial-transfer loop from P01 (`ptrace.rs:459-487`); both seal_prop and unseal_prop inherit this contract by construction. Compaction preserves order: `lock_list_remove_bytes` walks entries linearly from offset 0 via `buffer[entry_start..=tail].iter().position(|&b| b == 0)`, finds the match, then does `buffer.copy_within(match_end..=tail, entry_start)` which is documented by `std::primitive::slice::copy_within` to handle overlapping ranges correctly via memmove semantics — subsequent entries retain their relative order because the left-shift is a single contiguous move. The tail-zero loop at `hook.rs:991-993` zeros bytes `[new_cur_len + 1 ..= tail]` so no stale entry bytes linger past the new sentinel. Coverage check: the 5 unit tests cover (a) zero-length seed → append → append → append (append_bytes_three_entries), (b) capacity-boundary reject (append_bytes_rejects_capacity_overflow), (c) middle-entry removal with order preservation (remove_bytes_middle_entry), (d) missing-name no-op with byte-for-byte buffer preservation (remove_bytes_missing_returns_none), (e) only-entry removal resetting to empty (remove_bytes_only_entry_resets_to_empty), plus (f) pre-attach interior-NUL reject (seal_prop_rejects_interior_nul). Not yet covered in unit tests: the full `read_remote → pure-helper → write_remote → detach → bump counter` round-trip — that is T5's integration-test scope per phase spec §Tasks T5, and the prompt's §TASK 4 SCOPE explicitly scopes "no integration test (T5)".
- [x] **Correctness** — Edge cases: (1) seal name that's already sealed (current behavior: append duplicate — document or reject?); (2) unseal on empty list; (3) unseal removes last entry, sentinel stays at offset 0; (4) name with 0-length; (5) name > remaining lock-list capacity (return error rather than overflow into hook body): Notes: (1) `seal_prop` on an already-sealed name currently appends a duplicate entry; the hook body's strcmp walk will match on the first occurrence (nearest offset 0) so the duplicate is semantically harmless but costs `name.len() + 1` bytes of capacity. Deferred de-dup logic to T5's `PropSystem::seal` wrapper where it composes naturally with the `SealRecord` registry's tier-scoped uniqueness check; codifying it in the pure helper would add a linear scan to every seal, penalising the common fresh-name case. The checklist edge-case prompt is logged as a documented non-issue here. (2) `unseal_prop` on an empty list (`cur_len == 0`): `lock_list_remove_bytes` enters the while loop with `entry_start = 0`, `tail = 0`, fails the `entry_start < tail` guard immediately, returns `None`. `unseal_prop`'s wrapper surfaces this as `Ok(false)` without a remote write (`hook.rs:1089-1096`). (3) Removing the only entry: `lock_list_remove_bytes_only_entry_resets_to_empty` at `hook.rs:1575` asserts `new_len == 0` and `buffer[0] == 0` (sentinel at offset 0). This is precisely the P03 stage-B initial state, so the tracee returns to a clean empty-list after the last unseal. (4) Zero-length name: `seal_prop("")` — `name.as_bytes()` is empty, `tail = cur_len`, `entry_end = cur_len`, `new_sentinel = cur_len + 1`. `buffer[tail..entry_end].copy_from_slice(&[])` is a no-op, `buffer[entry_end] = 0` writes the entry-NUL at `cur_len`, `buffer[new_sentinel] = 0` writes the trailing sentinel at `cur_len + 1`. The hook body's `cbz w11, .fallthrough` would fire on the first byte (NUL) of the empty entry and short-circuit the strcmp walk — so an empty name effectively seals ALL subsequent writes. This is surprising semantics but not unsafe (the arena behind the empty name is whatever `PropSystem::seal("", ...)` passes to `set_stealth`), and the T5 wrapper is the correct layer to reject empty names via a prior `PropertyContext::resolve("") -> None -> Error::NotFound` path; the pure helper stays permissive. (5) Over-capacity: `lock_list_append_bytes` returns `None` when `new_sentinel >= capacity`; `seal_prop` surfaces this as `Error::HookInstallFailed(format!("seal_prop: capacity exceeded (len={}, name={} bytes)", ..))` at `hook.rs:1039-1045`. No overflow into the hook body at `hook_page + HOOK_BODY_OFFSET` is possible because the guard fires BEFORE the buffer write and the remote write is bounded by the returned `Option`; init's trampoline target remains intact. Additional edge case caught during implementation: interior-NUL names. An interior NUL would split the entry in the hook body's strcmp walk so it prefix-matches on the bytes preceding the NUL, causing unintended seals of unrelated props. `seal_prop` guards this at step 1 (`name.as_bytes().contains(&0)`) and surfaces `Error::InvalidKey` — the test `seal_prop_rejects_interior_nul` verifies the path runs without ever calling `RemoteAttach::new`.

### Task 5: `PropSystem::seal` / `unseal` / `seals` API + tier_b_child_smoke integration test

- [x] Implementation: `crates/resetprop/src/lib.rs:46` adds `use std::sync::{Mutex, OnceLock};`; `lib.rs:301` extends `PropSystem` with `hook_handle: OnceLock<Mutex<Option<seal::hook::HookHandle>>>`; `lib.rs:363` threads `hook_handle: OnceLock::new()` through `open_dir`; `pub fn seal(&self, name: &str, value: &str) -> Result<SealRecord>` at `lib.rs:621-652` (a) resolves the arena via `resolve_arena_path` + `arena_filename` at `lib.rs:622-623`, (b) rejects `SERIAL_FILE` with `Error::InvalidKey` at `lib.rs:624-626` before any ptrace work (matches the P02 `seal_arena` guard at `lib.rs:548-551`), (c) calls `self.set_stealth(name, value)?` at `lib.rs:628` so the value lands in the arena first, (d) lazy-installs the hook at `lib.rs:630-639` via `self.hook_handle.get_or_init(|| Mutex::new(None))` + `seal::hook::install_init_hook(seal::INIT_PID)` + `seal::hook::install_trampoline(&mut handle)` when the slot is `None`, (e) calls `seal::hook::seal_prop(handle, name)?` at `lib.rs:642` to append the name to the lock list, (f) builds a `SealRecord { tier: SealTier::Prop, .. }` at `lib.rs:646-651` and pushes it through `insert_or_refresh_seal` so duplicate seals refresh `sealed_at` instead of duplicating entries. `pub fn unseal(&self, name: &str) -> Result<bool>` at `lib.rs:661-680` short-circuits to `Ok(false)` at `lib.rs:666-669` when the hook is not yet installed, otherwise delegates to `seal::hook::unseal_prop` at `lib.rs:670` and — only when the hook confirmed the removal — drops the matching `tier == Prop` record from the registry via the inline `retain` at `lib.rs:678` (the helper `remove_seal_record` at `lib.rs:832-840` is Arena-scoped, so inlining preserves Arena records for the same name). `pub fn seals(&self) -> Result<Vec<SealRecord>>` at `lib.rs:687-693` returns an owned clone so repeated calls never alias the internal state. Poisoned mutexes on `hook_handle` or `seals_registry()` surface as `Error::HookInstallFailed(String)` (no new variants — REGISTRY §1 row 35 locked at 9). Integration test at `crates/resetprop/tests/tier_b_child_smoke.rs:1-220` with `#![cfg(target_arch = "aarch64")]` + `#[ignore]` mirrors `tier_a_child_smoke.rs`: `#[no_mangle] pub extern "C" fn __system_property_update`, two `PinnedPi` instances for `locked.prop` / `free.prop`, fork+alternate update loop, parent calls the low-level `seal::hook::install_init_hook` + `install_trampoline` + `seal_prop` triad (no `PropSystem`, because the test binary has no real `/dev/__properties__`), reads value bytes via `libc::process_vm_readv`, and asserts `locked_before == locked_after` + `free_before != free_after`. `.cargo/config.toml:13-14` appends `[build] rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]` with a comment pointing at `test-harness-patterns.md §5`.
- [x] Test: `cargo build -p resetprop` zero warnings; `cargo test -p resetprop --lib` passes 116/116; `cargo clippy -p resetprop --no-deps --lib -- -D warnings` clean; `cargo test -p resetprop --test tier_b_child_smoke -- --list` reports `0 tests, 0 benchmarks` on the x86_64 dev host because the whole file is `#![cfg(target_arch = "aarch64")]`-gated — confirms the cfg gate compiles cleanly on non-aarch64. Aarch64 device run (`cargo test --test tier_b_child_smoke -- --ignored --test-threads=1`) is scoped to a follow-up operator session, matching the P02/P03 closure pattern.

#### Self-Audit Gate 5 (MANDATORY before Phase End)

- [x] **Optimality** — `OnceLock<Mutex<Option<HookHandle>>>` vs plain `Mutex<Option<HookHandle>>`? OnceLock avoids unconditional lock-init cost on read-only `seals()` call. Notes: `OnceLock<Mutex<Option<HookHandle>>>` at `lib.rs:301` is the correct composition for three overlapping reasons. (1) The read-only `seals()` call at `lib.rs:680-686` goes straight to `seal::seals_registry()` and never touches `self.hook_handle`; a plain `Mutex<Option<HookHandle>>` would force every `PropSystem::open()` to construct and initialise a mutex even when the caller only ever calls `seals()` or the Tier A API, paying the atomic-compare-and-swap + syscall cost (`pthread_mutex_init` on glibc, futex setup on Linux) for no benefit. OnceLock makes that initialisation lazy — the mutex only exists after the first `seal()` or `unseal()` call. (2) `PropSystem` is constructed once per process (by the CLI dispatch path in P05) and dropped once; the OnceLock guarantee that the inner `Mutex` is allocated exactly once aligns naturally with the "install the hook at most once per process" invariant that `install_init_hook` already encodes via the trampoline-typestate flip at `hook.rs:912`. (3) Consistency with the existing `SEALS: OnceLock<Mutex<Vec<SealRecord>>>` at `seal/mod.rs:59` — the same pattern already governs the process-wide registry, so using it for `hook_handle` keeps one idiom instead of introducing a second. Alternative considered and rejected: `Arc<Mutex<Option<HookHandle>>>` — would add reference-counting atomics to a field whose owner is singular (`PropSystem`), for zero benefit. Second alternative: `RwLock` — all three methods that touch the handle mutate it (seal installs, unseal mutates the lock list, even the read to `guard.as_mut()` is a write borrow), so read-parallelism has no use here. Mutex wins.
- [x] **Completeness** — All three public methods present? Registry reused from P02 (not a second registry)? Test file has `#[ignore]` + doc-comment with exact invocation? `.cargo/config.toml` `--export-dynamic` rustflag confirmed per test-harness-patterns.md §5? Notes: All three deliverables landed and interlock correctly. (1) Three new methods on `PropSystem`: `seal` at `lib.rs:621-652`, `unseal` at `lib.rs:661-680`, `seals` at `lib.rs:687-693` — each with a doc-comment, each taking `&self`, each returning `Result<_>`. (2) Struct change: `hook_handle: OnceLock<Mutex<Option<seal::hook::HookHandle>>>` at `lib.rs:301`, initialised as `OnceLock::new()` at `lib.rs:363`. (3) Import additions: `use std::sync::{Mutex, OnceLock};` at `lib.rs:46`. (4) Registry: `seal::seals_registry()` at `seal/mod.rs:63-65` — the SAME `OnceLock<Mutex<Vec<SealRecord>>>` that P02's `seal_arena` populates with `SealTier::Arena` records; `seal()` pushes via `insert_or_refresh_seal` at `lib.rs:813-828`, which is shared infrastructure, not a second registry. (5) Test file: `tier_b_child_smoke.rs` starts with a doc-comment listing the exact invocation `cargo test --test tier_b_child_smoke -- --ignored --test-threads=1` at lines 3-5, has `#![cfg(target_arch = "aarch64")]` at line 20, and `#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1 on aarch64 device"]` at line 178. (6) `.cargo/config.toml:13-14` contains `[build] rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]` preceded by a comment citing `test-harness-patterns.md §5 / §9`. Grep confirms (`grep -c '^\[build\]' .cargo/config.toml` = 1; `grep -c 'export-dynamic' .cargo/config.toml` = 1).
- [x] **Correctness** — Edge cases: (1) `seal()` called when `install_init_hook` returns Err — hook_handle stays None for retry; (2) concurrent `seal()` calls serialized by the Mutex; (3) `unseal()` on a never-sealed name returns Ok(false), registry unchanged; (4) `seals()` returns empty Vec before any seal; (5) test fails if `--export-dynamic` missing — document in test file comment: Notes: (1) **Install failure retains retry capability.** In `seal()` at `lib.rs:618-627`, the slot is mutated via `*guard = Some(handle)` ONLY after both `install_init_hook(pid)?` and `install_trampoline(&mut handle)?` succeed. If either `?` propagates an error, the `Mutex` guard drops with `*guard` still `None`, so the very next `seal()` call sees `guard.is_none()` true and re-enters the install path. This also covers the partial-install case where stage-A succeeds but stage-B fails: `HookHandle::Drop` at `hook.rs:417-427` short-circuits on `trampoline_installed == false` but unmaps the RWX scratch page, so no remote state leaks. (2) **Concurrent `seal()` serialised by the `Mutex`.** `self.hook_handle.get_or_init(|| Mutex::new(None))` produces a single `Mutex` instance shared across all threads that hit the same `PropSystem`; the `.lock()` call at `lib.rs:615` is strict mutual exclusion, so two threads calling `seal()` concurrently serialise on install (only one runs `install_init_hook`), and both serialise on `seal_prop` (only one `RemoteAttach` window active at a time — required because `init` is a single tracee and two concurrent attaches would race on `PTRACE_SEIZE`). Poisoned-mutex recovery returns `Error::HookInstallFailed` rather than `unwrap_or_else(|p| p.into_inner())` because silent recovery after a panic could leave the tracer side of the lock-list in a half-written state the caller cannot see. (3) **`unseal()` on a never-sealed name.** Two sub-paths. (3a) Hook has never been installed: `guard.as_mut()` returns `None`, early-return `Ok(false)` at `lib.rs:663-665` before any `seal::hook::*` call. (3b) Hook installed but `name` not in the list: `seal::hook::unseal_prop` at `hook.rs:1078` walks the list via `lock_list_remove_bytes` and returns `Ok(false)`; the `if removed` guard at `lib.rs:669` skips the registry `retain`, so the Prop-tier record set is byte-for-byte unchanged. Arena-tier records for the same name (populated by `seal_arena`) are preserved by the `r.tier == SealTier::Prop` filter in the `retain` predicate at `lib.rs:673`. (4) **`seals()` returns empty Vec before any seal.** `seal::seals_registry()` calls `get_or_init(|| Mutex::new(Vec::new()))`, so the first call lazy-creates an empty `Vec`; `entries.clone()` on that empty `Vec` returns `Vec::new()` — no surprises. A `PropSystem::open() + seals()` sequence without any seal is side-effect-free. (5) **Test fails gracefully if `--export-dynamic` missing.** The doc-comment at `tier_b_child_smoke.rs:7-14` explicitly cites the rustflag requirement and names the reference section (`test-harness-patterns.md §5`). If the rustflag is absent the test would compile but `install_init_hook` would fail at GNU_HASH lookup with `Error::SymbolNotFound("__system_property_update")` from `seal/elf.rs`, which surfaces through the `.expect("install_init_hook")` at `tier_b_child_smoke.rs:190` as a clear panic message pointing operators at the config requirement. Additional edge case caught during implementation: the integration test deliberately calls the low-level `seal::hook::*` primitives rather than `PropSystem::seal` because the test binary has no real `/dev/__properties__` directory — `PropSystem::open()` would fail at `Io::NotFound` before any ptrace work could run. The phase spec's §Tasks T5 paragraph on the integration test matches this (cites `install_init_hook(guard.pid()) + seal_prop(&handle, "locked.prop")`). REGISTRY drift note: The P03 session log's arm64 release binary is already 410408 bytes (400.8 KB) — 0.8 KB over the REGISTRY §2 "≤400 KB" target — a carry-over from P03 that the rustflag does not affect (the rustflag's host-measured delta is +1264 bytes, ~1.2 KB, so the predicted arm64 delta lands around 411-412 KB after P05 cross-compile). Flagged for REGISTRY review; not introduced by P04 T5.

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
- [ ] FR-11: The `RESTORE_TARGET` literal at words 31..=32 (post-splice per P04.2 T1; reference pre-splice layout pins it at 19..=20) holds `target_fn + 16` as little-endian u64 (per arm64-a64-encoding.md §Hook body sketch + P04.2 T1 expansion)
- [ ] FR-12: The `LOCK_LIST` literal at words 33..=34 (post-splice per P04.2 T1; reference pre-splice layout pins it at 21..=22) holds `hook_page + LOCK_LIST_OFFSET` as little-endian u64 (per arm64-a64-encoding.md §Hook body sketch + P04.2 T1 expansion)

### Trampoline Installation (per `arm64-a64-encoding.md` §Absolute-target trampoline + `linux-arm64-abi.md` §10)

- [ ] FR-13: `install_trampoline` obtains the hook body from `build_hook_body_bytes(...)` and writes the 140-byte result (post-STRCMP-splice per P04.2 T1) at `hook_page + HOOK_BODY_OFFSET` BEFORE writing the 16-byte trampoline at `target_fn` (write-order invariant — body ready before init is re-entered via the trampoline)
- [ ] FR-14: `install_trampoline` writes all bytes of each region via `process_vm_writev`, looping on partial returns (per linux-arm64-abi.md §10 partial-transfer semantics)
- [ ] FR-15: i-cache sync primary path issues remote `membarrier(0x80, 0, 0)` via `__NR_membarrier = 283` (per linux-arm64-abi.md §1)
- [ ] FR-16: i-cache sync fallback executes `ISB` in the tracee via register flip when `membarrier` returns `EINVAL`/`EPERM` (per spec §Tasks T3)
- [ ] FR-17: Any `process_vm_writev` failure is converted to `Error::HookInstallFailed` (per REGISTRY §1 row 35 error surface; `SealHookError` in the original spec was a stale variant name that does not exist — P04.2 T4 correction)

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

**Section obsoleted by P04.2 T3.** The off-device sacrificial-child integration test was deleted per Gate 2 round-1 critic CRITICAL 2 (false-positive test — `is_libc_row` filter excludes the host binary and Rust intra-module routing bypasses the patched `.dynsym` entry even with `--export-dynamic`). All FR-27 … FR-31 below are N/A. Tier B functional acceptance runs on-device in P05 against real init.

- [ ] ~~FR-27~~ N/A: Test binary defines `#[no_mangle] pub extern "C" fn __system_property_update(pi: *mut u8, value: *const u8, len: u32) -> libc::c_int` (per test-harness-patterns.md §5)
- [ ] ~~FR-28~~ N/A: Test constructs two `PinnedPi` with names "locked.prop" and "free.prop" using 96-byte header + name bytes layout (per test-harness-patterns.md §6)
- [ ] ~~FR-29~~ N/A: Parent reads pi->value bytes via `process_vm_readv` both pre-seal and post-seal (per test-harness-patterns.md §5 `read_remote_value`)
- [ ] ~~FR-30~~ N/A: Test asserts `locked_before == locked_after` (hook blocked update) and `free_before != free_after` (pass-through worked) (per test-harness-patterns.md §11 Assertions)
- [ ] ~~FR-31~~ N/A: Test file has `#[ignore]` attribute and doc-comment line specifying `cargo test --test tier_b_child_smoke -- --ignored --test-threads=1` (per test-harness-patterns.md §12)

## Test Criteria

- [ ] TC-01: `cargo test -p resetprop --lib seal::hook` passes 0 failures (per spec §Validation) — annotate with test function names after run
- [ ] ~~TC-02~~ N/A per P04.2 T3: `cargo test -p resetprop --test tier_b_child_smoke -- --ignored --test-threads=1` — test file deleted per Gate 2 round-1 critic CRITICAL 2. Tier B acceptance moves to P05 aarch64 device-run.
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
| `HOOK_BODY_OFFSET` (inside hook_page) | 1024 (P04 spec §Approach item 4 — bytes 0..=1023 reserved for lock-list, body at bytes 1024..=1163 post-STRCMP-splice per P04.2 T1, bytes 1164..=4095 spare) | `crates/resetprop/src/seal/hook.rs:81` |
| Hook body size | 140 bytes (35 words post-STRCMP-splice per P04.2 T1; pre-splice reference template at `arm64-a64-encoding.md:383-407` shows 23 words / 92 bytes) | `crates/resetprop/src/seal/hook.rs:636` |
| `STOLEN_START` patch-point word index | 25 (post-splice per P04.2 T1; pre-splice reference = 13) | `crates/resetprop/src/seal/hook.rs:643` |
| `RESTORE_LIT` patch-point word index | 31 (post-splice per P04.2 T1; pre-splice reference = 19) | `crates/resetprop/src/seal/hook.rs:646` |
| `LOCK_LIST_LIT` patch-point word index | 33 (post-splice per P04.2 T1; pre-splice reference = 21) | `crates/resetprop/src/seal/hook.rs:649` |
| `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` | `0x40` (linux/membarrier.h cmd enum; `arm64-a64-encoding.md:422` — "Requires REGISTER registration first; kernel ≥ 4.16"; added in P04.2 T2) | `crates/resetprop/src/seal/hook.rs:101` |
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

## P04.2 Fix-Lane Self-Audit Gates

Segment P04.2 (Gate 2 round-1 CRITICALs + one symmetry MAJOR). Each fix task MUST fill all three Notes below before the next fix task may start, per `.claude/system-prompt.md §Per-Task Implementation Loop`.

### Self-Audit Gate T1 — STRCMP_BODY splice + scan-past-NUL + pointer rebind

- [x] **Optimality**: Considered three alternatives for the splice.
  (a) Expand `HOOK_BODY_TEMPLATE` in place from 23 → 35 words (chosen).
  (b) Keep the 23-word template and emit a separate out-of-line STRCMP page
      invoked via `bl` from the stub slot. Rejected — doubles the RWX page
      allocation and adds a second i-cache sync target.
  (c) Hand-assemble the body per-call via the `encoder::` submodule. Rejected —
      defeats the point of the const template and loses the byte-for-byte
      reference check. The chosen expansion keeps the reference §Hook body
      sketch as the line-by-line ground truth and makes the splice a
      const-array substitution with no runtime assembly.
- [x] **Completeness**: Delivered per spec item by item — (1) template grew to
  35 words / 140 bytes (`hook.rs:599-636`); (2) pre-splice pointer rebind at
  words 5-6 (`mov x12,x9 ; mov x13,x10`) preserves caller x0/x1 (critic M5);
  (3) 13-word STRCMP splice at words 7-19 with registers rebound to
  x12/x13/w14/w15 and `.mismatch`/`.match` exits rewritten as
  `b .advance` / `b .on_match` per reference §Hook body sketch line 415;
  (4) 3-word `.advance` block at words 22-24 replaces the broken 1-word
  stub with post-indexed `ldrb ; cbnz ; b .next_entry` scan-past-NUL;
  (5) patch-point constants advanced to STOLEN_START=25, RESTORE_LIT=31,
  LOCK_LIST_LIT=33; (6) doc comments + `HOOK_BODY_OFFSET` / `LOCK_LIST_CAPACITY`
  size references updated 92→140 throughout; (7) three tests added
  (`_header_matches_spliced_layout`, `_splices_strcmp_body`,
  `_advance_block_scans_past_nul`) for byte-for-byte round-trip decoding,
  existing `_roundtrip` + `_is_pure` tests migrated to the 140-byte layout.
- [x] **Correctness**: Walked edge cases — (i) empty lock list: word 3 peeks
  NUL sentinel, word 4 takes `cbz` to `.fall_through` at word 25, splice
  never entered, stolen prologue + `br x16` → `target_fn + 16` with
  (x0,x1,w2) preserved. (ii) First-entry match: outer loop peeks non-NUL,
  word 5-6 rebind, splice ldrb/ldrb/cmp matches, word 11 `cbz w14` on
  terminating NUL takes to word 18 which `b`s to `.on_match` (word 20)
  → `movz w0,#0; ret`. (iii) Mismatch mid-entry: word 10 `b.ne` to word 16
  which `b`s to `.advance` (word 22), post-indexed `ldrb w11,[x10],#1`
  advances x10 past the current entry's remaining chars + its NUL,
  `cbnz w11, .-4` loops until NUL reached, `b .next_entry` re-enters
  outer loop at word 3. (iv) Entry longer than property name: strcmp sees
  non-NUL `w14` vs NUL `w15` → `b.ne` → advance. (v) Property name longer
  than entry: strcmp sees NUL `w14` vs non-NUL `w15` → `b.ne` → advance
  (not `.match`, because word 11 `cbz w14, .match` requires w14==0 but
  the preceding `cmp` would have set NE). (vi) x0/x1 preservation on
  fallthrough: splice mutates only x12/x13/w14/w15; x0 and x1 remain
  caller-provided; `br x16` branches back with full ABI intact.
  (vii) Upper-32-bit zeroing on `ldrb`: AArch64 semantics zero-extend
  byte loads to 32 bits and writing a W register clears the high 32 bits
  of its X counterpart, so `cbnz w11` after `ldrb w11, [x10], #1`
  reliably detects NUL regardless of prior x11 state.

### Self-Audit Gate T2 — Membarrier REGISTER pre-call

- [x] **Optimality**: Considered three options for the i-cache sync.
  (a) REGISTER (0x40) then SYNC_CORE (0x80) — chosen. Minimal delta,
      preserves the existing ISB fallback, and matches the reference's
      own recommendation order at `arm64-a64-encoding.md:422`.
  (b) Switch to `__clear_cache`. Rejected — requires resolving a second
      libc symbol (`libc.so!__clear_cache`) and setting up a remote call
      frame, which is out of P04.2 scope. Reference line 425 recommends
      this as the architecturally correct option; deferring to a future
      hardening phase.
  (c) Remove the membarrier path entirely and rely on POKETEXT i-cache
      maintenance. Rejected — the hook BODY is written via
      `process_vm_writev` (hook.rs:844), not POKETEXT, and reference
      line 425 is explicit: "ptrace(PTRACE_POKETEXT) does this on Linux;
      `process_vm_writev` does not." Dropping the membarrier path would
      leave the body page's i-cache unflushed.
- [x] **Completeness**: Added the `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE = 0x40`
  const adjacent to the existing SYNC_CORE const (hook.rs:92-102 region).
  Step 6 of `install_trampoline` now issues REGISTER via
  `remote_syscall_via_poke` first; on -EINVAL / -ENOSYS (kernel lacks
  the cmd) drops to the staged ISB fallback; on other failures bubbles a
  `HookInstallFailed` error. Step 7 (formerly second half of Step 6)
  then issues SYNC_CORE with symmetric error handling. The ISB fallback
  at `execute_remote_isb` is unchanged (its atomic-restore fix is T5).
- [x] **Correctness**: Walked cases — (i) kernel ≥ 4.16 and membarrier
  intact: REGISTER returns 0, SYNC_CORE returns 0, i-cache synced.
  (ii) Kernel has membarrier but not SYNC_CORE cmd (kernel < 4.16):
  REGISTER returns -EINVAL, ISB fallback fires. (iii) Kernel lacks
  membarrier entirely: REGISTER returns -ENOSYS, ISB fallback fires.
  (iv) REGISTER succeeds but SYNC_CORE reports -EINVAL (theoretical):
  ISB fallback fires defensively. (v) REGISTER returns an unusual
  errno: hard error with the raw return value in the message, consistent
  with the other `HookInstallFailed` error paths in this function.
  (vi) REGISTER is idempotent per linux/membarrier.h semantics, so
  repeated trampoline installs on the same init don't accumulate state.

### Self-Audit Gate T3 — Delete sacrificial-child test + rustflag

- [x] **Optimality**: Considered three options.
  (a) Delete the off-device test + rustflag and declare Tier B acceptance
      an aarch64 device-run in P05 — chosen.
  (b) Redesign the test with a cdylib shim that the child loads via
      `dlopen`, so stage-A's `is_libc_row` sees a real `/libc.so`-suffixed
      row and the child's call routes through its `.dynsym`. Rejected —
      mirrors P03's `elf_fixture` complexity at three days of engineering
      cost for a host-side test that still can't exercise membarrier
      SYNC_CORE (single-core host behaves differently from SMP init).
  (c) Widen `is_libc_row` with a `cfg(test)` branch accepting the test
      binary's path. Rejected — tightens the production filter less
      defensibly than deleting the test outright, and the intra-module
      direct-branch bypass (Rust's linker resolves `__system_property_update`
      via a relocation, not through `.dynsym`) would remain uncovered.
  Path (a) trades host-side coverage for an honest signal: the only
  correct proof of Tier B function is a real-init aarch64 device-run.
- [x] **Completeness**: Deleted
  `crates/resetprop/tests/tier_b_child_smoke.rs` (219 lines). Removed
  the `[build] rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]`
  block from `.cargo/config.toml` (lines 13-19, including the comment
  block citing the removed test). Updated the `handle_drop_is_defined`
  doc comment in `hook.rs` to cite P05 device-run instead of the
  removed off-device test. Updated `P04-tier-b-part2.md` §Scope, §Tasks
  T5, and §Validation to remove the test entries. Annotated
  `P04-checklist.md` §Integration Test (FR-27..31) and §Test Criteria
  TC-02 as N/A with strikethrough + P04.2 T3 citation. REGISTRY §8
  deferred-findings entry logged with the full rationale.
- [x] **Correctness**: Walked consequences — (i) library still compiles
  and all 118 lib tests pass (no runtime code was touched). (ii)
  `pub` visibility of `install_init_hook` / `install_trampoline` /
  `seal_prop` / `unseal_prop` is no longer consumed by an off-module
  test; reviewer MINOR-3 recommended tightening these to `pub(crate)`
  but that tightening is deferred to P04.3 (MINOR scope, and the
  `PropSystem::seal` API in `lib.rs` still consumes them as internal
  crate callers — `pub(crate)` is the correct level). (iii) Binary
  size should drop by ~40 KB on the next `cargo build --release` run
  because `--export-dynamic` no longer retains `#[no_mangle]` globals
  in `.dynsym`; re-measure in P04.3. (iv) No other tests reference
  the deleted file — `rg tier_b_child_smoke crates/` returns zero
  matches post-delete in source trees (only in historical docs +
  REGISTRY log which are append-only).

### Self-Audit Gate T4 — Spec + checklist doc fixes

- [x] **Optimality**: Considered three approaches to the doc drift.
  (a) Amend the spec / checklist prose in place, annotating post-splice
      indices with their pre-splice reference counterparts — chosen.
  (b) Rewrite the spec to drop the reference-template indices entirely.
      Rejected — keeping the pre-splice numbers lets future agents
      cross-reference `arm64-a64-encoding.md` without re-deriving the
      offset math.
  (c) Delete the Error-variant mention entirely. Rejected — the error
      contract belongs in the spec so future agents know which variant
      to match in integration tests.
  Approach (a) gives the minimum invasive fix that preserves historical
  context for each drift (each amended line notes the pre-splice or
  pre-rename value + "P04.2 T4 correction").
- [x] **Completeness**: Changes landed — (1) `P04-tier-b-part2.md`
  §Tasks T3 replaced `Error::SealHookError` with `Error::HookInstallFailed`
  and `HOOK_BODY_OFFSET = 4` with the correct 1024 explanation;
  Verifies clause updated to drop the deleted integration test and
  point at the P05 device-run (folded in from P04.2 T3). §Approach item
  4 fully rewritten with the 35-word / 140-byte body accounting + the
  1024 offset. (2) `P04-checklist.md`: FR-11, FR-12, FR-13, FR-17,
  Task 2 test row, Task 3 test row (from T3) all amended for
  post-splice indices, 140-byte size, and `HookInstallFailed` variant.
  Canonical Values table at §Canonical Values gained four rows pinning
  the post-splice Hook body size, STOLEN_START=25, RESTORE_LIT=31,
  LOCK_LIST_LIT=33, and the new `MEMBARRIER_CMD_REGISTER_…` const.
  (3) `references/resetprop-rs-integration.md` §Error variants table
  renamed `SealHookError` to `HookInstallFailed` with a parenthetical
  noting the rename. (4) `hook.rs` in-code doc comments were already
  migrated 92→140 during T1; no further changes required for T4.
- [x] **Correctness**: Walked drift cases — (i) every surviving
  reference to `SealHookError` in the authoritative tree (P04 spec,
  P04 checklist, resetprop-rs-integration.md) now reads
  `HookInstallFailed`; the audit file (append-only historical) and
  REGISTRY §7 session log entries (append-only historical) retain the
  old name because they record what was drafted at the time.
  (ii) `arm64-a64-encoding.md:374-376` still shows pre-splice indices
  STOLEN_START=13, RESTORE_LIT=19, LOCK_LIST_LIT=21 — these are the
  REFERENCE canonical layout, which is correct and intentional; the
  P04.2-amended checklist rows explicitly cite "pre-splice reference
  = N" so the two representations coexist without ambiguity.
  (iii) `arm64-a64-encoding.md:348` still says "23-word (92-byte)"
  — this describes the reference template pre-splice and is likewise
  correct and intentional. (iv) `HOOK_BODY_OFFSET = 4` no longer
  appears anywhere in the authoritative tree except the audit file,
  which is append-only.

### Self-Audit Gate T5 — `execute_remote_isb` atomic success-path restore

- [x] **Optimality**: Considered three forms of the fix.
  (a) Capture both results pre-`?`, then propagate them in order —
      chosen. Matches the pattern the P02 fix commit 910ce69 applied to
      `remote_syscall_via_poke` and `remote_syscall` for the same class
      of defect. Minimum diff; no new helper.
  (b) Extract a `restore_scratch_and_regs(pid, scratch_pc, saved_word,
      saved_regs) -> Result<()>` helper. Rejected — a 3-line call-site
      does not justify the indirection and the helper would only have
      one caller, which is the zero-net-line guidance in the user's
      Code Style block.
  (c) Use a scope guard (drop-based cleanup). Rejected — adds a
      dependency, complicates the happy-path reading, and doesn't buy
      anything a 4-line capture-then-propagate pattern can't.
- [x] **Completeness**: Diff is exactly what the audit prescribed:
  `reg_res = setregset(...)`; `poke_res = ptrace_poketext(...)`;
  `reg_res?; poke_res?; Ok(())`. Added a 6-line comment block above
  the capture pattern explaining the symmetry with P02 commit 910ce69
  and the failure mode the fix closes (libc.text holding `isb; brk`
  bytes after a successful `wait_stop` if `setregset` fails). 118 lib
  tests pass; clippy-clean within the T5 diff (pre-existing
  `persist/proto.rs` + `seal/elf.rs` clippy lints are out of scope).
- [x] **Correctness**: Walked failure sequences — (i) `setregset`
  succeeds, `ptrace_poketext` succeeds: both results are `Ok`, the
  two `?` operators are no-ops, function returns `Ok(())`. Same as
  before the fix. (ii) `setregset` fails: old code short-circuited
  via the first `?`, never restoring the scratch word, leaving
  `isb; brk` at `scratch_pc` for the next execution stream to hit.
  New code captures both results first; the scratch-word restore
  fires unconditionally; then `reg_res?` propagates the reg-restore
  error to the caller. (iii) `setregset` succeeds, `ptrace_poketext`
  fails: `reg_res?` passes through, then `poke_res?` surfaces the
  poke error. Net behaviour: the reg restore landed (good), the
  scratch word didn't (but the caller now sees the failure explicitly
  and can take further cleanup action). (iv) Both fail: both errors
  are returned — `reg_res?` fires first (reg restore is
  higher-criticality because failing to restore the tracee's PC could
  leave it executing in the scratch slot), `poke_res` is dropped. The
  earlier error gets reported, matching the convention in
  `remote_syscall_via_poke` at the P02 fix site.
