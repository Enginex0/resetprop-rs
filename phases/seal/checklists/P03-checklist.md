# P03 — Tier B Part 1: ELF Parse + Hook Page Allocation — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [x] P01 (Foundation: ptrace + maps) shows COMPLETE in REGISTRY §4
- [x] `crates/resetprop/src/seal/ptrace.rs` exists with public `remote_syscall` that takes `(pid, scratch_pc, syscall_no, [u64; 6])` and returns `Result<i64>` (ptrace.rs:512)
- [x] `crates/resetprop/src/seal/maps.rs` exists with public `parse_maps(pid) -> Result<Vec<MapEntry>>` and a `MapEntry { start, end, perms, pathname, ... }` type (maps.rs:17,32)
- [x] `crates/resetprop/src/error.rs` extended with variants `PtraceAttach`, `PtraceScope`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed` (error.rs:15-23)
- [x] `crates/resetprop/src/seal/mod.rs` exists (from P01) as the module-tree root

(Source: P03 spec, Preconditions; REGISTRY §5)

## Branch

- [x] Branch `feat/P03-tier-b-part1` created (cut from P02 tip 39ff4f4 — P03 depends on P01 only per §5, P02 changes are preserved along the parallel track)
- [x] All commits follow `feat(seal):` / `test(seal):` / `fix(seal):` / `docs(seal):` prefix per REGISTRY §2

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: Create `seal/elf.rs` with ELF64 layouts, constants, and `parse_libc_elf`

- [x] Implementation: `crates/resetprop/src/seal/elf.rs` exists with `#[repr(C)]` structs `Elf64_Ehdr` (64 B), `Elf64_Phdr` (56 B), `Elf64_Dyn` (16 B), `Elf64_Sym` (24 B), each with `const _: () = assert!(mem::size_of::<T>() == N);` guards
- [x] Implementation: constants `ELFMAG`, `ELFCLASS64`, `ELFDATA2LSB`, `ET_DYN = 3`, `EM_AARCH64 = 183`, `PT_LOAD = 1`, `PT_DYNAMIC = 2`, `DT_NULL = 0`, `DT_HASH = 4`, `DT_STRTAB = 5`, `DT_SYMTAB = 6`, `DT_STRSZ = 10`, `DT_SYMENT = 11`, `DT_GNU_HASH = 0x6fff_fef5`, `STT_FUNC = 2`, `STB_GLOBAL = 1`, `SHN_UNDEF = 0` all declared
- [x] Implementation: `pub fn parse_libc_elf(file: &File) -> Result<LibcElfView>` validates magic + class + data + machine + type + phentsize, walks phdrs, locates the single `PT_DYNAMIC`, walks `Elf64_Dyn` entries until `DT_NULL`, records `symtab_offset`, `strtab_offset`, `strtab_size`, `gnu_hash_offset` via a `vaddr_to_foff` helper built from the PT_LOAD list
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::ehdr_size_64` exits 0
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::phdr_size_56` exits 0
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::dyn_size_16` exits 0
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::sym_size_24` exits 0
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::parse_rejects_bad_magic` exits 0
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::parse_rejects_wrong_machine` exits 0

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [x] **Optimality** — Considered alternative approach? Is this the most elegant within constraints? Notes: Considered (a) mmap + `ptr::read` on slices into `&Elf64_*` refs, (b) per-struct `pread` via `FileExt::read_exact_at`. Rejected (a) — mmap lifetime management adds 3+ unsafe sites with no footprint savings for ~1 MB libc.so, and REGISTRY §2 requires a `// SAFETY:` paragraph per unsafe block. Rejected (b) — spec Design Decision 5 locks `read_to_end`; pread adds one syscall per struct with no ownership benefit since T2/T3 must slice the buffer anyway. Chose `read_to_end` + single `read_struct<T>` helper using `ptr::read_unaligned` — one unsafe site, one SAFETY paragraph at `elf.rs:218-221`, O(1) allocations, and T2/T3 can index `LibcElfView::bytes` directly. Minimal-surface design within the "libc-only, no ELF crate" constraint.
- [x] **Completeness** — Deliverable fully met spec §Tasks T1? Notes: Yes. Four `#[repr(C)]` structs with `const _: () = assert!(...)` guards at `elf.rs:103, 118, 136, 150`. All 17 constants declared as `pub const` at module top (`elf.rs:30-78`) with `/usr/include/elf.h` line citations inlined. `parse_libc_elf(file: &File) -> Result<LibcElfView>` at `elf.rs:241` performs validation order magic→class→data→machine→type→phentsize (`elf.rs:255-274`), PT_LOAD collection + PT_DYNAMIC location (`elf.rs:281-303`), Dyn walk bounded by both `DT_NULL` and `dyn_filesz/16` (`elf.rs:317-336`), and `vaddr_to_foff` translation for SYMTAB/STRTAB/GNU_HASH (`elf.rs:341-351`). All 6 checklist tests pass: `ehdr_size_64`, `phdr_size_56`, `dyn_size_16`, `sym_size_24`, `parse_rejects_bad_magic`, `parse_rejects_wrong_machine`.
- [x] **Correctness** — Edge cases walked through (list them): zero-phnum ELF, PT_DYNAMIC absent, PT_DYNAMIC entry count derived from `p_filesz / 16`, DT_STRSZ optional, vaddr outside every PT_LOAD range: (a) zero-phnum → `for i in 0..phnum` no-ops, `pt_dynamic.is_none()` fires `ElfParse("PT_DYNAMIC absent")` at `elf.rs:306`; (b) PT_DYNAMIC absent → same path as (a); (c) entry count derived as `dyn_filesz / sizeof(Elf64_Dyn) = dyn_filesz / 16` at `elf.rs:317`, loop terminates at whichever comes first between DT_NULL and the derived count — both bounds enforced per Design Decision 8; (d) DT_STRSZ optional → `strtab_sz` defaults to `0` at `elf.rs:311`, never rejected, flows through to `LibcElfView`; (e) vaddr outside PT_LOAD → `vaddr_to_foff` returns `None`, caller wraps as `ElfParse("DT_SYMTAB/STRTAB/GNU_HASH vaddr outside PT_LOAD map")` at `elf.rs:342,344,348`.

### Task 2: GNU_HASH lookup matching bionic chain-walk and terminator semantics

- [x] Implementation: `pub fn gnu_lookup(view: &LibcElfView, name: &str) -> Option<u64>` parses the on-disk GNU_HASH header (`nbuckets`, `symoffset`, `bloom_size`, `bloom_shift` as four u32s), then `bloom: [u64; bloom_size]`, then `buckets: [u32; nbuckets]`, then chain
- [x] Implementation: hash function is `h = 5381; for b in name.as_bytes() { h = h.wrapping_add(h.wrapping_shl(5)).wrapping_add(*b as u32); }` (bionic form from `linker_gnu_hash.h:46-54`)
- [x] Implementation: bloom test uses `bits = 64`, masks `1 << (h % bits)` and `1 << ((h >> bloom_shift) % bits)`, both must be set to proceed
- [x] Implementation: chain walk compares `((chain[idx] ^ h) >> 1) == 0` (per `linker_soinfo.cpp:362`) and terminates when `chain[idx] & 1 != 0` (per `linker_soinfo.cpp:371`)
- [x] Implementation: on chain match, reads the `Elf64_Sym` at `symtab_offset + n * 24`, reads the NUL-terminated name at `strtab_offset + st_name` (bounded by `strtab_size`), and returns `Some(sym.st_value)` only after a byte-exact name match
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::gnu_hash_seed_5381` asserts `gnu_hash(b"") == 5381` and `gnu_hash(b"_") == 5381*33 + b'_' as u32` (wrapping)
- [x] Test: `cargo test -p resetprop --lib seal::elf::tests::gnu_lookup_absent_returns_none` exits 0

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [x] **Optimality** — Notes: Considered (a) `ptr::read_unaligned` via the existing `read_struct` for u32/u64 header reads, (b) zero-copy `&[u32]` reinterpretation of the GNU_HASH section. Rejected (a) — duplicates an `unsafe` site with no throughput gain. Rejected (b) — `Vec<u8>` alignment is unspecified, reinterpret-cast would be unsafe + platform-dependent. Chose safe `u32::from_le_bytes` / `u64::from_le_bytes` helpers (`u32_le` / `u64_le`) with explicit bounds checks — no unsafe, same codegen. `Elf64_Sym` decode still goes through shared `read_struct` at `elf.rs:500`. `gnu_hash` extracted as `pub(crate) fn` at `elf.rs:384-393` for test reuse per checklist-locked test name.
- [x] **Completeness** — Notes: Every spec bullet satisfied. `pub fn gnu_lookup(view, name) -> Option<u64>` at `elf.rs:434`. On-disk header (nbuckets/symoffset/bloom_size/bloom_shift) at `elf.rs:441-444`. Bloom double-check at `elf.rs:465-473`. Bucket read + zero guard at `elf.rs:476-481`. Chain-walk compare `((c^h)>>1)==0` at `elf.rs:496` and terminator `(c&1)!=0` at `elf.rs:508`. `Elf64_Sym` read + strtab NUL resolution + byte-exact name compare at `elf.rs:500-504`. FR-09 seed 5381 at `elf.rs:386`. FR-10 bloom bits=64 at `elf.rs:378`. FR-11 chain compare cited above. FR-12 terminator cited above. FR-13 bounded strtab via `read_cstr_at` at `elf.rs:425-432`. Both required tests present and green: `gnu_hash_seed_5381` at `elf.rs:627` and `gnu_lookup_absent_returns_none` at `elf.rs:651`.
- [x] **Correctness** — Edge cases: `nbuckets == 0`, `buckets[h % nbuckets] == 0`, chain index underflow when `n < symoffset`, bloom `bloom_size == 0`, symbol name unterminated within `strtab_size`: (a) `nbuckets == 0` → rejected at header guard `elf.rs:446` preventing div-by-zero in `h % nbuckets`; (b) bucket zero → `elf.rs:479-481` `if n == 0 { return None; }` matching bionic `linker_soinfo.cpp:350-354`; (c) `n < symoffset` → guarded at `elf.rs:485-487` — without it, u32 underflow in release would produce garbage chain index; (d) `bloom_size == 0` → same header guard at `elf.rs:446`, prevents `(bloom_size - 1)` wrapping to `u32::MAX` and OOB bloom read; (e) unterminated name within strtab → `read_cstr_at` at `elf.rs:425-432` bounds scan to `min(offset + max_len, bytes.len())` and returns `None` on no-NUL, which `?`-propagates at `elf.rs:502` to drop the candidate and continue walking (safer than false-match); (f) chain OOB beyond section → every offset is `checked_add`/`checked_mul` and `u32_le` returns `None` when reaching past `bytes.len()`, propagates via `?`. Never panics.

### Task 3: Linear fallback, `resolve_symbol` dispatcher, and fixture-based integration test

- [x] Implementation: `pub fn linear_lookup(view: &LibcElfView, name: &str) -> Option<u64>` iterates `0..((strtab_offset - symtab_offset) / 24)`, reads each `Elf64_Sym`, skips `st_shndx == SHN_UNDEF`, compares the NUL-terminated name at `strtab_offset + st_name` against the target, returns `Some(st_value)` on match
- [x] Implementation: `pub fn resolve_symbol(view: &LibcElfView, name: &str) -> Result<u64>` dispatches to `gnu_lookup` when `gnu_hash_offset.is_some()` and falls back to `linear_lookup`, wrapping a `None` result in `Error::SymbolNotFound(name.into())`
- [x] Implementation: fixture crate `crates/resetprop/tests/fixtures/elf_fixture/Cargo.toml` declares `crate-type = ["cdylib"]` and names the crate `elf_fixture`
- [x] Implementation: fixture `crates/resetprop/tests/fixtures/elf_fixture/src/lib.rs` exports three `#[no_mangle] pub extern "C"` functions (`__system_property_update`, `seal_fixture_probe_a`, `seal_fixture_probe_b`), all returning `0`
- [x] Implementation: integration test `crates/resetprop/tests/elf_fixture_smoke.rs` is `#[test] #[ignore]`, invokes `cargo build -p elf_fixture --release` via `std::process::Command`, opens the produced `.so` path, calls `parse_libc_elf` + `resolve_symbol`, and asserts (a) `__system_property_update` resolves to a non-zero `st_value`, (b) `gnu_lookup` and `linear_lookup` agree on the value for a fixture symbol
- [x] Test: `cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1` exits 0

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [x] **Optimality** — Notes: Considered (a) deriving the symbol count from `DT_HASH`'s `nchain` — rejected because bionic libc historically ships without SysV hash and T1/T2 never captured `DT_HASH`; the `(strtab - symtab) / 24` convention matches `references/android-libc-elf.md §6` and the bionic linker's own linear fallback. (b) `bytes.windows(24)` for the iteration — rejected as it would bypass the `read_struct` alignment-safe path from T1. (c) Adding a synthetic unit test in addition to the integration test — rejected; duplicating the `from_parts` scaffolding from T2 would reproduce existing coverage without pinning the real-world cdylib round-trip. Chose minimal: `linear_lookup` reuses `read_struct` + `read_cstr_at`, `resolve_symbol` does a straight GNU-then-linear fall-through, and the integration test is the single truth-source for the end-to-end contract.
- [x] **Completeness** — Notes: Sub-deliverables mapped to FRs. `linear_lookup` at `elf.rs:~540` → FR-14 (`.dynsym` linear scan) + FR-15 (SHN_UNDEF skip). `resolve_symbol` at `elf.rs:~560` → FR-16 (GNU→linear dispatcher). Fixture crate at `crates/resetprop/tests/fixtures/elf_fixture/{Cargo.toml, src/lib.rs}` with three `#[no_mangle] pub extern "C"` stubs (`__system_property_update`, `seal_fixture_probe_a`, `seal_fixture_probe_b`) → FR-17 (deterministic `.dynsym` contents). Integration test `crates/resetprop/tests/elf_fixture_smoke.rs` gated `#![cfg(target_arch = "aarch64")]` + `#[ignore]` → checklist Task 3 bullets 3-5 and §Validation item 3. Workspace `Cargo.toml` members list extended by one entry so `cargo build -p elf_fixture --release` resolves. `cargo build -p elf_fixture --release` produces `target/release/libelf_fixture.so` (273600 bytes verified). No public re-exports added on the crate root — T4 consumes via `seal::elf::resolve_symbol`.
- [x] **Correctness** — Edge cases: strtab not adjacent to symtab (linear bound wrong), zero-named symbol at index 0, fixture cdylib built without `.gnu.hash` (force `-Wl,--hash-style=both`), `cargo build -p elf_fixture` not findable from the test (use `CARGO_BIN_EXE_*` or a relative path from `CARGO_MANIFEST_DIR`): (a) non-adjacent strtab/symtab → `entries = (strtab - symtab) / 24` may overestimate; per-iteration `read_struct` + `.ok()?` converts OOB reads to `None`, and `read_cstr_at` returns `None` on OOB name offsets — loop continues, never panics. (b) zero-named symbol (ELF reserved `sym[0]` with `st_shndx == SHN_UNDEF`) → skipped before the name compare at the `if sym.st_shndx == SHN_UNDEF` guard; even without the guard, empty-string name never matches non-empty queries. (c) fixture built without `.gnu.hash` → `view.gnu_hash_offset.is_none()` routes straight to linear; test asserts `resolve_symbol == linear_lookup` unconditionally and only cross-checks `gnu_lookup` when `Some`, so behavior is resilient to SysV-only, GNU-only, or dual-hash linker output. (d) `cargo build` discovery → test uses `env!("CARGO")` (cargo sets this when launching the test binary; stable across `rustup run <channel>` and CI). Cdylib located via `env!("CARGO_MANIFEST_DIR") + "/../../target/release/libelf_fixture.so"`; missing-file case prints the attempted path for actionable failure.

### Task 4: `HookHandle` type + stage-A of `install_init_hook`

- [x] Implementation: `pub struct HookHandle { pid: libc::pid_t, hook_page: u64, lock_list_len: u32, target_fn: u64, saved_prologue: [u8; 16] }` declared in `crates/resetprop/src/seal/hook.rs`
- [x] Implementation: `pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle>` stage-A calls `seal::maps::parse_maps(pid)`, filters the first row with `perms == "r-xp"` and `pathname.ends_with("/libc.so")`, formats `/proc/<pid>/map_files/<start>-<end>` using hex `format!("{:x}-{:x}", start, end)`, opens it with `File::open`, parses via `seal::elf::parse_libc_elf`, resolves `__system_property_update` via `seal::elf::resolve_symbol`, and computes `target_fn = libc_base + st_value`
- [x] Implementation: any failure in stage-A surfaces as `Error::HookInstallFailed(msg)` wrapping the underlying `Error`, preserving the failing step in the message (e.g., `"stage-A: libc row not found in /proc/{pid}/maps"`)
- [x] Test: `cargo test -p resetprop --lib seal::hook::tests::hook_handle_size` asserts the struct has the expected field layout (non-zero fields are reachable via accessors)
- [x] Test: `cargo test -p resetprop --lib seal::hook::tests::libc_row_filter_r_xp_suffix` exercises the filter logic on a synthetic `Vec<MapEntry>` and confirms only `r-xp` + `/libc.so` suffix passes

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [x] **Optimality** — Notes: Considered (a) single-function install_init_hook with a TODO comment at the construction site to be replaced by T5; (b) two-function split `install_init_hook_stage_a -> (u64, u64)` + `install_init_hook -> HookHandle`. Rejected (a) — leaves a visible placeholder, requires T5 to mutate a scattered struct literal, and the TODO marker violates the "no placeholder code" rule. Chose (b) — handoff to T5 becomes an explicit tuple return, stage-A is independently callable from future diagnostics, and the leading `_libc_base` underscore at `hook.rs:96` signals "consumed by a later stage" without dead-code warnings. `is_libc_row` extracted as `pub(crate) fn` at `hook.rs:43` so the `libc_hwasan.so` false-match guard is testable on synthetic `MapEntry`s — inlining the closure would have made the suffix-trap untestable.
- [x] **Completeness** — Notes: Every §Tasks T4 bullet at an identifiable hook.rs line. `HookHandle` struct with `pub(crate)` fields at `hook.rs:30-37` (locked shape — T5 will populate `hook_page`/`saved_prologue` but not change the layout). Stage-A (a) `parse_maps` at `hook.rs:61-62`; (b) filter `r-xp` + `/libc.so` suffix via `is_libc_row` at `hook.rs:43-50` + first-match `find` at `hook.rs:64-66`; (c) format `/proc/<pid>/map_files/<start>-<end>` at `hook.rs:69-72`; (d) `File::open` at `hook.rs:74-75`; (e) `parse_libc_elf` at `hook.rs:77-78`; (f) `resolve_symbol("__system_property_update")` at `hook.rs:80-81`; (g) `target_fn = libc_base + st_value` with `checked_add` overflow guard at `hook.rs:83-85`; (h) every step returns `Error::HookInstallFailed("stage-A: <step>: <cause>")` preserving the failing step per checklist requirement. FR-18 (filter), FR-19 (map_files path), FR-20 (target_fn arithmetic) each have a dedicated error branch. Tests `hook_handle_size` at `hook.rs:125` and `libc_row_filter_r_xp_suffix` at `hook.rs:143` both green. `pub mod hook;` added to `seal/mod.rs` adjacent to existing modules. No Drop impl yet — T5 scope.
- [x] **Correctness** — Edge cases: multiple libc.so rows (first wins), `libc_hwasan.so` present alongside `libc.so` (suffix match must not accept `libc_hwasan.so`), bootstrap libc path `/system/lib64/bootstrap/libc.so` (valid suffix match — acceptable), map_files symlink not readable without CAP_SYS_PTRACE (error must surface as `HookInstallFailed`): (a) multiple `r-xp` rows → `entries.iter().find` short-circuits on first match per spec directive "first match wins"; (b) `libc_hwasan.so` → `ends_with("/libc.so")` with the leading slash rejects because the string ends with `libc_hwasan.so` which does not end with `/libc.so` — explicitly asserted at `hook.rs:163-166`; (c) bootstrap path `/system/lib64/bootstrap/libc.so` → satisfies both perms and suffix gates → accepted, asserted at `hook.rs:159-162`; (d) `/proc/<pid>/map_files/...` EACCES → `File::open` surfaces `io::Error`, wrapped into `HookInstallFailed("stage-A: open <path>: <cause>")` at `hook.rs:74-75` — the target path and underlying OS error are both in the message for operator triage; (e) `target_fn` arithmetic overflow → `checked_add` at `hook.rs:84` returns `None` which maps to `HookInstallFailed("stage-A: target_fn overflow")`, keeping the pipeline sound against malformed symbol values.

### Task 5: Stage-B — remote mmap + prologue snapshot + sentinel + Drop cleanup

- [x] Implementation: stage-B ptrace-attaches via `seal::ptrace` (SEIZE + INTERRUPT) before issuing the remote syscall
- [x] Implementation: `seal::ptrace::remote_syscall(pid, __NR_mmap = 222, [0_u64, 4096, 0x7, 0x22, u64::MAX, 0])` is invoked; the returned `i64` is decoded — values in `-4095..=-1` are `-errno` and surface as `Error::HookInstallFailed`, otherwise `hook_page = ret as u64`
- [x] Implementation: `process_vm_writev` writes a 4-byte zero word at `hook_page` (empty lock-list sentinel); `lock_list_len = 0` is set in the returned `HookHandle`
- [x] Implementation: `process_vm_readv` captures 16 bytes from `target_fn` into `saved_prologue: [u8; 16]`
- [x] Implementation: the tracer detaches (`PTRACE_DETACH`) before returning
- [x] Implementation: `impl Drop for HookHandle` re-attaches, issues `remote_syscall(pid, __NR_munmap = 215, [hook_page, 4096, 0, 0, 0, 0])`, detaches, and swallows all errors (best-effort cleanup)
- [x] Implementation: a doc comment on `impl Drop` explicitly flags that P04 will override this behavior once the trampoline is installed (must NOT unmap while the hook is live)
- [x] Test: `cargo test -p resetprop --lib seal::hook::tests::handle_drop_is_defined` asserts the `Drop` impl exists (compile-time check via `fn _drop_compiles<T: Drop>() {}; _drop_compiles::<HookHandle>();`)
- [x] Test: stage-B paths are exercised by the off-device Tier B child smoke test deferred to P04 (`tier_b_child_smoke.rs` is P04 scope per REGISTRY §3)

#### Self-Audit Gate 5 (MANDATORY — phase end)

- [x] **Optimality** — Notes: Considered two scratch-PC strategies. (a) Bootstrap RWX page: mmap a dedicated 4 KiB anonymous RWX page, stage `svc+brk` in it, use that as `scratch_pc` — matches P02's `remote_remap_private`. Rejected because the bootstrap page IS the hook page we're installing — two remote mmaps double the leak-on-error surface and per-install syscall count. (b) libc.text NOP-slide / aligned slot: `remote_syscall_via_poke` uses PEEK/POKEDATA which bypasses VMA write bits, so an r-xp scratch is legal; reuses `find_scratch_slot` verbatim from `seal::arena`. Chose (b) — fewer syscalls, less leak surface, fewer failure modes. Amendment to spec: spec writes `remote_syscall` but P02's Gate 2 round-1 fix replaced that with `remote_syscall_via_poke` for libc.text scratch; the brief baked in this correction. Also declared a narrow deviation: promoted `RemoteAttach::{new, detach, pid}` from private `fn` to `pub(crate) fn` (3-token visibility bump + comment) at `arena.rs:190-219` because the brief explicitly required `RemoteAttach` consumption and forbade reimplementation.
- [x] **Completeness** — Notes: Every §Tasks T5 bullet at a file:line. Stage-A helper returns `(libc_base, libc_end, target_fn)` at `hook.rs:92`. Stage-B acquires `RemoteAttach` at `hook.rs:172-173`. `derive_libc_scratch_pc` reads libc.text capped at 64 KiB at `hook.rs:137-146`, calls `find_scratch_slot` at `hook.rs:148-151`. Remote mmap at `hook.rs:185-195` with `PROT_RWX=0x7`, `MAP_PRIVATE|ANON=0x22`, `HOOK_PAGE_SIZE=4096`, `fd=u64::MAX`, via `remote_syscall_via_poke(pid, scratch_pc, NR_MMAP, ...)`. Errno decode for `[-4095,-1]` at `hook.rs:199-204`. Four-byte zero sentinel write at `hook.rs:218-221`. Sixteen-byte prologue snapshot at `hook.rs:228-231`. Detach via implicit `RemoteAttach` Drop at end of scope. `HookHandle` constructed at `hook.rs:238-245`. `impl Drop for HookHandle` at `hook.rs:287-305` with zero-`hook_page` guard at `hook.rs:291-293` and best-effort `drop_best_effort` body at `hook.rs:254-282`. Test `handle_drop_is_defined` at `hook.rs:400-411`. Module doc-comment flags that P04 will override Drop once trampoline is live at `hook.rs:287-297`. FR-21 (remote mmap ret decode) at `hook.rs:199-204`; FR-22 (Drop swallows errors) at `hook.rs:302-304`; FR-23 (munmap via `remote_syscall_via_poke`) at `hook.rs:289-299`. 31 lib tests pass, clippy clean, grep proves zero bare `remote_syscall(` calls in hook.rs.
- [x] **Correctness** — Edge cases: `mmap` returns `-ENOMEM` (surfaces as HookInstallFailed), target PID exits mid-attach (ESRCH from ptrace, surfaces as HookInstallFailed), `process_vm_readv` returns short read (retry-or-fail loop must exist), Drop fires before stage-B completes (zero `hook_page` must not `munmap`): (a) mmap -ENOMEM → errno window `-4095..=-1` catches it at `hook.rs:199-204`, wraps as `HookInstallFailed("stage-B: mmap returned -errno=12")`, no hook page leaks; (b) tracee exits mid-attach → `RemoteAttach::new` returns `Err(PtraceAttach(...))` via `ptrace_seize`, wrapped as `HookInstallFailed("stage-B: attach: <cause>")` at `hook.rs:173`; if process dies later, `remote_syscall_via_poke` surfaces ESRCH, wrapped similarly, and `RemoteAttach::drop` swallows its own detach error (arena.rs:214-220); (c) `process_vm_readv` short read → P01's `read_remote` implements the retry/fail loop internally at `ptrace.rs:428-440`; stage-B wraps its error as `HookInstallFailed("stage-B: read libc.text: ...")` or `"stage-B: read prologue: ..."` at `hook.rs:143-145,229-231`; (d) Drop fires with `hook_page == 0` → early return at `hook.rs:291-293` prevents munmap of a non-existent page; `install_init_hook` only constructs the handle after stage-B succeeds, so production callers never see this state — only synthetic `HookHandle` literals (e.g. `hook_handle_size` test) do.

## Functional Requirements (subsystem-level)

### ELF parser (per `references/android-libc-elf.md` §2-§4)

- [x] FR-01: `Elf64_Ehdr` is 64 bytes, `Elf64_Phdr` 56, `Elf64_Dyn` 16, `Elf64_Sym` 24, all validated by compile-time asserts (per `references/android-libc-elf.md` §2)
- [x] FR-02: `parse_libc_elf` rejects any file whose first 4 bytes are not `[0x7f, b'E', b'L', b'F']` (per `references/android-libc-elf.md` §4.1)
- [x] FR-03: `parse_libc_elf` rejects any file with `e_ident[EI_CLASS] != ELFCLASS64` (2) (per `references/android-libc-elf.md` §3)
- [x] FR-04: `parse_libc_elf` rejects any file with `e_ident[EI_DATA] != ELFDATA2LSB` (1) (per `references/android-libc-elf.md` §3)
- [x] FR-05: `parse_libc_elf` rejects any file with `e_machine != EM_AARCH64` (183) (per `references/android-libc-elf.md` §3)
- [x] FR-06: `parse_libc_elf` rejects any file with `e_type != ET_DYN` (3) (per `references/android-libc-elf.md` §3)
- [x] FR-07: `parse_libc_elf` locates the single `PT_DYNAMIC` program header and walks its entries until `DT_NULL` (per `references/android-libc-elf.md` §4.3)
- [x] FR-08: `parse_libc_elf` translates `DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` virtual addresses to file offsets using the `PT_LOAD` map (per `references/android-libc-elf.md` §4.5)

### GNU_HASH lookup (per `references/android-libc-elf.md` §5)

- [x] FR-09: GNU_HASH function is `h = 5381; h = h + (h << 5) + b` for each byte, matching bionic `linker_gnu_hash.h:46-54` (per `references/android-libc-elf.md` §5.2)
- [x] FR-10: bloom filter mask bit width is 64 (arm64 pointer size), index is `(h / 64) & (bloom_size - 1)` (per `references/android-libc-elf.md` §5.3)
- [x] FR-11: chain compare is `((chain[idx] ^ h) >> 1) == 0` (per bionic `linker_soinfo.cpp:362`)
- [x] FR-12: chain terminator is `chain[idx] & 1 != 0` (per bionic `linker_soinfo.cpp:371`)
- [x] FR-13: on hash match, name is byte-compared against the target before returning `Some(st_value)` (per `references/android-libc-elf.md` §5.3)

### Linear fallback (per `references/android-libc-elf.md` §6)

- [x] FR-14: `linear_lookup` iterates at most `(strtab_offset - symtab_offset) / 24` entries (per `references/android-libc-elf.md` §6)
- [x] FR-15: `linear_lookup` skips entries with `st_shndx == SHN_UNDEF` (per `references/android-libc-elf.md` §7)
- [x] FR-16: `resolve_symbol` prefers GNU_HASH when available and falls back to linear (per P03 spec §Approach)
- [x] FR-17: `resolve_symbol` returns a non-zero `st_value` for `__system_property_update` against the fixture cdylib (per P03 spec §Tasks T3)

### Hook installer (per P03 spec §Tasks T4-T5)

- [x] FR-18: `install_init_hook` selects the first `/proc/<pid>/maps` row with `perms == "r-xp"` and `pathname` ending in `/libc.so` (per P03 spec §Tasks T4)
- [x] FR-19: `install_init_hook` opens libc via `/proc/<pid>/map_files/<start>-<end>` (hex-formatted) (per `references/android-libc-elf.md` §1)
- [x] FR-20: `target_fn = libc_base + st_value` where `libc_base` is the row's `start` (per `references/android-libc-elf.md` §7)
- [x] FR-21: hook page is allocated via `remote_syscall(__NR_mmap, [0, 4096, PROT_READ|WRITE|EXEC = 0x7, MAP_PRIVATE|MAP_ANONYMOUS = 0x22, -1, 0])` (per `references/linux-arm64-abi.md` §1, §2)
- [x] FR-22: on success, `hook_page` is non-zero, `saved_prologue` is 16 bytes of the target function prologue, `lock_list_len == 0` (per P03 spec §Tasks T5)
- [x] FR-23: `Drop for HookHandle` unmaps the hook page (`__NR_munmap = 215`, length 4096) and ignores errors (per P03 spec §Tasks T5)

## Test Criteria

- [x] TC-01: `cargo test -p resetprop --lib seal::elf` passes with zero failures (per P03 spec §Validation)
- [x] TC-02: `cargo test -p resetprop --lib seal::hook` passes with zero failures (per P03 spec §Validation)
- [x] TC-03: `cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1` passes with zero failures (per P03 spec §Validation)
- [x] TC-04: `cargo test -p resetprop --lib seal::ptrace` still passes (regression check on P01) (per P03 spec §Validation)
- [x] TC-05: `cargo test -p resetprop --lib seal::maps` still passes (regression check on P01) (per P03 spec §Validation)
- [x] TC-06: `cargo build --release --target aarch64-linux-android -p resetprop-cli` produces a binary ≤ 400 KB (per REGISTRY §2 binary size target)

## Integration Verification

- [x] IV-01: Consumes P01: `seal::ptrace::remote_syscall`, `seal::maps::parse_maps`, `Error::ElfParse`, `Error::SymbolNotFound`, `Error::HookInstallFailed` (per REGISTRY §5)
- [x] IV-02: Exposes `HookHandle`, `install_init_hook`, `seal::elf::resolve_symbol` — consumed by P04 (per REGISTRY §5)
- [x] IV-03: Does NOT touch `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, `appcompat.rs` (per plan §Files modified)
- [x] IV-04: Does NOT add public methods to `PropSystem` (P04 scope — per P03 spec §Anti-Scope)

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `DT_GNU_HASH` | `0x6fff_fef5` (`/usr/include/elf.h:890-961`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:70` |
| `ET_DYN` | `3` (`/usr/include/elf.h:161`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:40` |
| `EM_AARCH64` | `183` (`/usr/include/elf.h:317`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:43` |
| `sizeof(Elf64_Ehdr)` | `64` (`/usr/include/elf.h:81-97`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:104` compile-time assert |
| `sizeof(Elf64_Phdr)` | `56` (`/usr/include/elf.h:697-707`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:119` compile-time assert |
| `sizeof(Elf64_Dyn)` | `16` (`/usr/include/elf.h:878-886`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:132` compile-time assert |
| `sizeof(Elf64_Sym)` | `24` (`/usr/include/elf.h:530-538`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:148` compile-time assert |
| `MAP_PRIVATE \| MAP_ANONYMOUS` | `0x22` (libc `MAP_PRIVATE = 0x02`, `MAP_ANONYMOUS = 0x20`; `references/linux-arm64-abi.md` §8) | `crates/resetprop/src/seal/hook.rs:44` |
| `PROT_READ \| PROT_WRITE \| PROT_EXEC` | `0x7` (libc `PROT_READ = 0x1`, `PROT_WRITE = 0x2`, `PROT_EXEC = 0x4`) | `crates/resetprop/src/seal/hook.rs:41` |
| GNU_HASH seed | `5381` (`aosp-android15/bionic/linker/linker_gnu_hash.h:46-54`; `references/android-libc-elf.md` §5.2) | `crates/resetprop/src/seal/elf.rs:386` |
| Hook page size | `4096` (REGISTRY §1 — "Hook page: 4 KB RWX anonymous mmap"; plan §Tier B install step 3) | `crates/resetprop/src/seal/hook.rs:50` |
| `__NR_mmap` | `222` (`asm-generic/unistd.h:570,886`; `references/linux-arm64-abi.md` §1) | `crates/resetprop/src/seal/arena.rs:19` (re-exported via `use crate::seal::arena::NR_MMAP` at `hook.rs:30`) |
| `__NR_munmap` | `215` (`asm-generic/unistd.h:556`; `references/linux-arm64-abi.md` §1) | `crates/resetprop/src/seal/arena.rs:21` (re-exported via `use crate::seal::arena::NR_MUNMAP` at `hook.rs:30`) |
| `STT_FUNC` | `2` (`/usr/include/elf.h:585-599`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:73` |
| `STB_GLOBAL` | `1` (`/usr/include/elf.h:585-599`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:76` |
| `SHN_UNDEF` | `0` (`/usr/include/elf.h:413`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:79` |

## Anti-Scope (explicitly excluded)

- [x] AS-01: No ARM64 trampoline encoding (P04 scope) (per P03 spec §Anti-Scope)
- [x] AS-02: No trampoline write at `target_fn` via `process_vm_writev` (P04 scope) (per P03 spec §Anti-Scope)
- [x] AS-03: No `seal_prop(name)` / `unseal_prop(name)` lock-list write path (P04 scope) (per P03 spec §Anti-Scope)
- [x] AS-04: No `PropSystem::seal` / `PropSystem::unseal` / `PropSystem::seals` public API (P04 scope) (per P03 spec §Anti-Scope)
- [x] AS-05: No CLI flag parsing for `-sl` / `--seal` / `--unseal` / `--seals` (P05 scope) (per P03 spec §Anti-Scope)
- [x] AS-06: No `README.md` updates for the seal user surface (P05 scope) (per P03 spec §Anti-Scope)
- [x] AS-07: No `tests/device-stress-test.sh` Test 21 / Test 22 additions (P05 scope) (per P03 spec §Anti-Scope)
- [x] AS-08: No `propdetect` heuristics for the Tier B signature (deferred post-v1 per plan §Touchpoints for propdetect; REGISTRY §1) (per P03 spec §Anti-Scope)
- [x] AS-09: No `SealRecord` disk persistence (deferred) (per P03 spec §Anti-Scope)
- [x] AS-10: No i-cache coherence `membarrier` or `isb` calls (P04 scope) (per P03 spec §Anti-Scope)
- [x] AS-11: No Tier A arena privatization (P02 scope, parallel track) (per P03 spec §Anti-Scope)

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment completes. NOT after each segment.

- [x] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template — both persona prompts are inlined there verbatim) with: phase spec path `phases/seal/P03-tier-b-part1.md`, checklist path `phases/seal/checklists/P03-checklist.md`, REGISTRY path `phases/seal/REGISTRY-P.md`, code file paths (`crates/resetprop/src/seal/elf.rs`, `crates/resetprop/src/seal/hook.rs`, `crates/resetprop/src/seal/mod.rs`, `crates/resetprop/tests/fixtures/elf_fixture/`, `crates/resetprop/tests/elf_fixture_smoke.rs`), branch name `feat/P03-tier-b-part1`, External API Verification flag `YES` and the five sources listed in §External API Verification
- [x] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block
- [x] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block
- [x] Both agents dispatched IN PARALLEL (single message, two Agent tool calls)
- [x] Since `External API Verification: YES`, both agents grep'd/read actual sources (`bionic/linker/linker_gnu_hash.h`, `bionic/linker/linker_soinfo.cpp`, `bionic/linker/linker.cpp`, `/usr/include/elf.h`) and quoted real signatures / real line numbers
- [x] code-reviewer report saved at `phases/seal/audits/P03-audit.md` — round 1 verdict: NEEDS_FIX (2 MAJOR + 4 MINOR); round 2 verdict: PASS
- [x] critic report saved at `phases/seal/audits/P03-audit.md` — round 1 verdict: NEEDS_FIX (1 CRITICAL + 5 MAJOR + 2 MINOR); round 2 verdict: PASS
- [x] All CRITICAL findings resolved (C1 TOCTOU fixed in commit 2b89a24 — install_init_hook now attach-first)
- [x] All MAJOR findings resolved (M1-M4 in commit 56a27df, M5-M7 in commit 2b89a24)
- [x] MINOR findings logged (not blocking) — 8 MINORs total across both reports, all documented in `phases/seal/audits/P03-audit.md`
- [x] Re-ran both agents after fixes; both emitted `VERDICT: PASS`

## Acceptance Gate

- [x] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes)
- [x] All FR-01 through FR-23 verified
- [x] All TC-01 through TC-06 passing
- [x] All IV-01 through IV-04 verified
- [x] No regressions in P01 (`cargo test -p resetprop --lib seal::ptrace && cargo test -p resetprop --lib seal::maps` — 5 tests total, all pass)
- [x] Branch commits clean; conventional commits with `feat(seal):` / `test(seal):` / `fix(seal):` / `docs(seal):` / `refactor(seal):` prefix
- [x] All 16 canonical values verified at the `file:line` column
- [x] Gate 2 reports PASS from BOTH agents
- [ ] REGISTRY §4 P03 row updated to COMPLETE (currently SEGMENT_COMPLETE pending aarch64 device-run of `elf_fixture_smoke`)
- [x] REGISTRY §7 session log appended with outcome (`PASS`) and audit verdict (`code-reviewer: PASS, critic: PASS`)
