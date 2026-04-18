# P03 — Tier B Part 1: ELF Parse + Hook Page Allocation — Completion Checklist

> **Gate rule**: Every box must be checked. No partial credit. If ANY item is unchecked, the segment/phase is NOT complete.
> **Self-audit rule** (Hard Rule 2): Each task has a self-audit gate. Empty Notes = audit not done = next task BLOCKED.
> **Adversarial gate** (Hard Rule 3): After the FINAL segment, deploy code-reviewer (Sonnet) + critic (Opus) IN PARALLEL. Phase NOT COMPLETE until both PASS.

## Prerequisites

- [ ] P01 (Foundation: ptrace + maps) shows COMPLETE in REGISTRY §4
- [ ] `crates/resetprop/src/seal/ptrace.rs` exists with public `remote_syscall` that takes `(pid, scratch_pc, syscall_no, [u64; 6])` and returns `Result<i64>`
- [ ] `crates/resetprop/src/seal/maps.rs` exists with public `parse_maps(pid) -> Result<Vec<MapEntry>>` and a `MapEntry { start, end, perms, pathname, ... }` type
- [ ] `crates/resetprop/src/error.rs` extended with variants `PtraceAttach`, `PtraceScope`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`
- [ ] `crates/resetprop/src/seal/mod.rs` exists (from P01) as the module-tree root

(Source: P03 spec, Preconditions; REGISTRY §5)

## Branch

- [ ] Branch `feat/P03-tier-b-part1` created (or resumed) from latest main
- [ ] All commits follow `feat(seal):` / `test(seal):` / `fix(seal):` / `docs(seal):` prefix per REGISTRY §2

## Implementation Tasks (with mandatory self-audit gates)

### Task 1: Create `seal/elf.rs` with ELF64 layouts, constants, and `parse_libc_elf`

- [ ] Implementation: `crates/resetprop/src/seal/elf.rs` exists with `#[repr(C)]` structs `Elf64_Ehdr` (64 B), `Elf64_Phdr` (56 B), `Elf64_Dyn` (16 B), `Elf64_Sym` (24 B), each with `const _: () = assert!(mem::size_of::<T>() == N);` guards
- [ ] Implementation: constants `ELFMAG`, `ELFCLASS64`, `ELFDATA2LSB`, `ET_DYN = 3`, `EM_AARCH64 = 183`, `PT_LOAD = 1`, `PT_DYNAMIC = 2`, `DT_NULL = 0`, `DT_HASH = 4`, `DT_STRTAB = 5`, `DT_SYMTAB = 6`, `DT_STRSZ = 10`, `DT_SYMENT = 11`, `DT_GNU_HASH = 0x6fff_fef5`, `STT_FUNC = 2`, `STB_GLOBAL = 1`, `SHN_UNDEF = 0` all declared
- [ ] Implementation: `pub fn parse_libc_elf(file: &File) -> Result<LibcElfView>` validates magic + class + data + machine + type + phentsize, walks phdrs, locates the single `PT_DYNAMIC`, walks `Elf64_Dyn` entries until `DT_NULL`, records `symtab_offset`, `strtab_offset`, `strtab_size`, `gnu_hash_offset` via a `vaddr_to_foff` helper built from the PT_LOAD list
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::ehdr_size_64` exits 0
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::phdr_size_56` exits 0
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::dyn_size_16` exits 0
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::sym_size_24` exits 0
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::parse_rejects_bad_magic` exits 0
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::parse_rejects_wrong_machine` exits 0

#### Self-Audit Gate 1 (MANDATORY before Task 2)

- [x] **Optimality** — Considered alternative approach? Is this the most elegant within constraints? Notes: Considered (a) mmap + `ptr::read` on slices into `&Elf64_*` refs, (b) per-struct `pread` via `FileExt::read_exact_at`. Rejected (a) — mmap lifetime management adds 3+ unsafe sites with no footprint savings for ~1 MB libc.so, and REGISTRY §2 requires a `// SAFETY:` paragraph per unsafe block. Rejected (b) — spec Design Decision 5 locks `read_to_end`; pread adds one syscall per struct with no ownership benefit since T2/T3 must slice the buffer anyway. Chose `read_to_end` + single `read_struct<T>` helper using `ptr::read_unaligned` — one unsafe site, one SAFETY paragraph at `elf.rs:218-221`, O(1) allocations, and T2/T3 can index `LibcElfView::bytes` directly. Minimal-surface design within the "libc-only, no ELF crate" constraint.
- [x] **Completeness** — Deliverable fully met spec §Tasks T1? Notes: Yes. Four `#[repr(C)]` structs with `const _: () = assert!(...)` guards at `elf.rs:103, 118, 136, 150`. All 17 constants declared as `pub const` at module top (`elf.rs:30-78`) with `/usr/include/elf.h` line citations inlined. `parse_libc_elf(file: &File) -> Result<LibcElfView>` at `elf.rs:241` performs validation order magic→class→data→machine→type→phentsize (`elf.rs:255-274`), PT_LOAD collection + PT_DYNAMIC location (`elf.rs:281-303`), Dyn walk bounded by both `DT_NULL` and `dyn_filesz/16` (`elf.rs:317-336`), and `vaddr_to_foff` translation for SYMTAB/STRTAB/GNU_HASH (`elf.rs:341-351`). All 6 checklist tests pass: `ehdr_size_64`, `phdr_size_56`, `dyn_size_16`, `sym_size_24`, `parse_rejects_bad_magic`, `parse_rejects_wrong_machine`.
- [x] **Correctness** — Edge cases walked through (list them): zero-phnum ELF, PT_DYNAMIC absent, PT_DYNAMIC entry count derived from `p_filesz / 16`, DT_STRSZ optional, vaddr outside every PT_LOAD range: (a) zero-phnum → `for i in 0..phnum` no-ops, `pt_dynamic.is_none()` fires `ElfParse("PT_DYNAMIC absent")` at `elf.rs:306`; (b) PT_DYNAMIC absent → same path as (a); (c) entry count derived as `dyn_filesz / sizeof(Elf64_Dyn) = dyn_filesz / 16` at `elf.rs:317`, loop terminates at whichever comes first between DT_NULL and the derived count — both bounds enforced per Design Decision 8; (d) DT_STRSZ optional → `strtab_sz` defaults to `0` at `elf.rs:311`, never rejected, flows through to `LibcElfView`; (e) vaddr outside PT_LOAD → `vaddr_to_foff` returns `None`, caller wraps as `ElfParse("DT_SYMTAB/STRTAB/GNU_HASH vaddr outside PT_LOAD map")` at `elf.rs:342,344,348`.

### Task 2: GNU_HASH lookup matching bionic chain-walk and terminator semantics

- [ ] Implementation: `pub fn gnu_lookup(view: &LibcElfView, name: &str) -> Option<u64>` parses the on-disk GNU_HASH header (`nbuckets`, `symoffset`, `bloom_size`, `bloom_shift` as four u32s), then `bloom: [u64; bloom_size]`, then `buckets: [u32; nbuckets]`, then chain
- [ ] Implementation: hash function is `h = 5381; for b in name.as_bytes() { h = h.wrapping_add(h.wrapping_shl(5)).wrapping_add(*b as u32); }` (bionic form from `linker_gnu_hash.h:46-54`)
- [ ] Implementation: bloom test uses `bits = 64`, masks `1 << (h % bits)` and `1 << ((h >> bloom_shift) % bits)`, both must be set to proceed
- [ ] Implementation: chain walk compares `((chain[idx] ^ h) >> 1) == 0` (per `linker_soinfo.cpp:362`) and terminates when `chain[idx] & 1 != 0` (per `linker_soinfo.cpp:371`)
- [ ] Implementation: on chain match, reads the `Elf64_Sym` at `symtab_offset + n * 24`, reads the NUL-terminated name at `strtab_offset + st_name` (bounded by `strtab_size`), and returns `Some(sym.st_value)` only after a byte-exact name match
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::gnu_hash_seed_5381` asserts `gnu_hash(b"") == 5381` and `gnu_hash(b"_") == 5381*33 + b'_' as u32` (wrapping)
- [ ] Test: `cargo test -p resetprop --lib seal::elf::tests::gnu_lookup_absent_returns_none` exits 0

#### Self-Audit Gate 2 (MANDATORY before Task 3)

- [x] **Optimality** — Notes: Considered (a) `ptr::read_unaligned` via the existing `read_struct` for u32/u64 header reads, (b) zero-copy `&[u32]` reinterpretation of the GNU_HASH section. Rejected (a) — duplicates an `unsafe` site with no throughput gain. Rejected (b) — `Vec<u8>` alignment is unspecified, reinterpret-cast would be unsafe + platform-dependent. Chose safe `u32::from_le_bytes` / `u64::from_le_bytes` helpers (`u32_le` / `u64_le`) with explicit bounds checks — no unsafe, same codegen. `Elf64_Sym` decode still goes through shared `read_struct` at `elf.rs:500`. `gnu_hash` extracted as `pub(crate) fn` at `elf.rs:384-393` for test reuse per checklist-locked test name.
- [x] **Completeness** — Notes: Every spec bullet satisfied. `pub fn gnu_lookup(view, name) -> Option<u64>` at `elf.rs:434`. On-disk header (nbuckets/symoffset/bloom_size/bloom_shift) at `elf.rs:441-444`. Bloom double-check at `elf.rs:465-473`. Bucket read + zero guard at `elf.rs:476-481`. Chain-walk compare `((c^h)>>1)==0` at `elf.rs:496` and terminator `(c&1)!=0` at `elf.rs:508`. `Elf64_Sym` read + strtab NUL resolution + byte-exact name compare at `elf.rs:500-504`. FR-09 seed 5381 at `elf.rs:386`. FR-10 bloom bits=64 at `elf.rs:378`. FR-11 chain compare cited above. FR-12 terminator cited above. FR-13 bounded strtab via `read_cstr_at` at `elf.rs:425-432`. Both required tests present and green: `gnu_hash_seed_5381` at `elf.rs:627` and `gnu_lookup_absent_returns_none` at `elf.rs:651`.
- [x] **Correctness** — Edge cases: `nbuckets == 0`, `buckets[h % nbuckets] == 0`, chain index underflow when `n < symoffset`, bloom `bloom_size == 0`, symbol name unterminated within `strtab_size`: (a) `nbuckets == 0` → rejected at header guard `elf.rs:446` preventing div-by-zero in `h % nbuckets`; (b) bucket zero → `elf.rs:479-481` `if n == 0 { return None; }` matching bionic `linker_soinfo.cpp:350-354`; (c) `n < symoffset` → guarded at `elf.rs:485-487` — without it, u32 underflow in release would produce garbage chain index; (d) `bloom_size == 0` → same header guard at `elf.rs:446`, prevents `(bloom_size - 1)` wrapping to `u32::MAX` and OOB bloom read; (e) unterminated name within strtab → `read_cstr_at` at `elf.rs:425-432` bounds scan to `min(offset + max_len, bytes.len())` and returns `None` on no-NUL, which `?`-propagates at `elf.rs:502` to drop the candidate and continue walking (safer than false-match); (f) chain OOB beyond section → every offset is `checked_add`/`checked_mul` and `u32_le` returns `None` when reaching past `bytes.len()`, propagates via `?`. Never panics.

### Task 3: Linear fallback, `resolve_symbol` dispatcher, and fixture-based integration test

- [ ] Implementation: `pub fn linear_lookup(view: &LibcElfView, name: &str) -> Option<u64>` iterates `0..((strtab_offset - symtab_offset) / 24)`, reads each `Elf64_Sym`, skips `st_shndx == SHN_UNDEF`, compares the NUL-terminated name at `strtab_offset + st_name` against the target, returns `Some(st_value)` on match
- [ ] Implementation: `pub fn resolve_symbol(view: &LibcElfView, name: &str) -> Result<u64>` dispatches to `gnu_lookup` when `gnu_hash_offset.is_some()` and falls back to `linear_lookup`, wrapping a `None` result in `Error::SymbolNotFound(name.into())`
- [ ] Implementation: fixture crate `crates/resetprop/tests/fixtures/elf_fixture/Cargo.toml` declares `crate-type = ["cdylib"]` and names the crate `elf_fixture`
- [ ] Implementation: fixture `crates/resetprop/tests/fixtures/elf_fixture/src/lib.rs` exports three `#[no_mangle] pub extern "C"` functions (`__system_property_update`, `seal_fixture_probe_a`, `seal_fixture_probe_b`), all returning `0`
- [ ] Implementation: integration test `crates/resetprop/tests/elf_fixture_smoke.rs` is `#[test] #[ignore]`, invokes `cargo build -p elf_fixture --release` via `std::process::Command`, opens the produced `.so` path, calls `parse_libc_elf` + `resolve_symbol`, and asserts (a) `__system_property_update` resolves to a non-zero `st_value`, (b) `gnu_lookup` and `linear_lookup` agree on the value for a fixture symbol
- [ ] Test: `cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1` exits 0

#### Self-Audit Gate 3 (MANDATORY before Task 4)

- [x] **Optimality** — Notes: Considered (a) deriving the symbol count from `DT_HASH`'s `nchain` — rejected because bionic libc historically ships without SysV hash and T1/T2 never captured `DT_HASH`; the `(strtab - symtab) / 24` convention matches `references/android-libc-elf.md §6` and the bionic linker's own linear fallback. (b) `bytes.windows(24)` for the iteration — rejected as it would bypass the `read_struct` alignment-safe path from T1. (c) Adding a synthetic unit test in addition to the integration test — rejected; duplicating the `from_parts` scaffolding from T2 would reproduce existing coverage without pinning the real-world cdylib round-trip. Chose minimal: `linear_lookup` reuses `read_struct` + `read_cstr_at`, `resolve_symbol` does a straight GNU-then-linear fall-through, and the integration test is the single truth-source for the end-to-end contract.
- [x] **Completeness** — Notes: Sub-deliverables mapped to FRs. `linear_lookup` at `elf.rs:~540` → FR-14 (`.dynsym` linear scan) + FR-15 (SHN_UNDEF skip). `resolve_symbol` at `elf.rs:~560` → FR-16 (GNU→linear dispatcher). Fixture crate at `crates/resetprop/tests/fixtures/elf_fixture/{Cargo.toml, src/lib.rs}` with three `#[no_mangle] pub extern "C"` stubs (`__system_property_update`, `seal_fixture_probe_a`, `seal_fixture_probe_b`) → FR-17 (deterministic `.dynsym` contents). Integration test `crates/resetprop/tests/elf_fixture_smoke.rs` gated `#![cfg(target_arch = "aarch64")]` + `#[ignore]` → checklist Task 3 bullets 3-5 and §Validation item 3. Workspace `Cargo.toml` members list extended by one entry so `cargo build -p elf_fixture --release` resolves. `cargo build -p elf_fixture --release` produces `target/release/libelf_fixture.so` (273600 bytes verified). No public re-exports added on the crate root — T4 consumes via `seal::elf::resolve_symbol`.
- [x] **Correctness** — Edge cases: strtab not adjacent to symtab (linear bound wrong), zero-named symbol at index 0, fixture cdylib built without `.gnu.hash` (force `-Wl,--hash-style=both`), `cargo build -p elf_fixture` not findable from the test (use `CARGO_BIN_EXE_*` or a relative path from `CARGO_MANIFEST_DIR`): (a) non-adjacent strtab/symtab → `entries = (strtab - symtab) / 24` may overestimate; per-iteration `read_struct` + `.ok()?` converts OOB reads to `None`, and `read_cstr_at` returns `None` on OOB name offsets — loop continues, never panics. (b) zero-named symbol (ELF reserved `sym[0]` with `st_shndx == SHN_UNDEF`) → skipped before the name compare at the `if sym.st_shndx == SHN_UNDEF` guard; even without the guard, empty-string name never matches non-empty queries. (c) fixture built without `.gnu.hash` → `view.gnu_hash_offset.is_none()` routes straight to linear; test asserts `resolve_symbol == linear_lookup` unconditionally and only cross-checks `gnu_lookup` when `Some`, so behavior is resilient to SysV-only, GNU-only, or dual-hash linker output. (d) `cargo build` discovery → test uses `env!("CARGO")` (cargo sets this when launching the test binary; stable across `rustup run <channel>` and CI). Cdylib located via `env!("CARGO_MANIFEST_DIR") + "/../../target/release/libelf_fixture.so"`; missing-file case prints the attempted path for actionable failure.

### Task 4: `HookHandle` type + stage-A of `install_init_hook`

- [ ] Implementation: `pub struct HookHandle { pid: libc::pid_t, hook_page: u64, lock_list_len: u32, target_fn: u64, saved_prologue: [u8; 16] }` declared in `crates/resetprop/src/seal/hook.rs`
- [ ] Implementation: `pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle>` stage-A calls `seal::maps::parse_maps(pid)`, filters the first row with `perms == "r-xp"` and `pathname.ends_with("/libc.so")`, formats `/proc/<pid>/map_files/<start>-<end>` using hex `format!("{:x}-{:x}", start, end)`, opens it with `File::open`, parses via `seal::elf::parse_libc_elf`, resolves `__system_property_update` via `seal::elf::resolve_symbol`, and computes `target_fn = libc_base + st_value`
- [ ] Implementation: any failure in stage-A surfaces as `Error::HookInstallFailed(msg)` wrapping the underlying `Error`, preserving the failing step in the message (e.g., `"stage-A: libc row not found in /proc/{pid}/maps"`)
- [ ] Test: `cargo test -p resetprop --lib seal::hook::tests::hook_handle_size` asserts the struct has the expected field layout (non-zero fields are reachable via accessors)
- [ ] Test: `cargo test -p resetprop --lib seal::hook::tests::libc_row_filter_r_xp_suffix` exercises the filter logic on a synthetic `Vec<MapEntry>` and confirms only `r-xp` + `/libc.so` suffix passes

#### Self-Audit Gate 4 (MANDATORY before Task 5)

- [ ] **Optimality** — Notes: ___________________________
- [ ] **Completeness** — Notes: ___________________________
- [ ] **Correctness** — Edge cases: multiple libc.so rows (first wins), `libc_hwasan.so` present alongside `libc.so` (suffix match must not accept `libc_hwasan.so`), bootstrap libc path `/system/lib64/bootstrap/libc.so` (valid suffix match — acceptable), map_files symlink not readable without CAP_SYS_PTRACE (error must surface as `HookInstallFailed`): ___________________________

### Task 5: Stage-B — remote mmap + prologue snapshot + sentinel + Drop cleanup

- [ ] Implementation: stage-B ptrace-attaches via `seal::ptrace` (SEIZE + INTERRUPT) before issuing the remote syscall
- [ ] Implementation: `seal::ptrace::remote_syscall(pid, __NR_mmap = 222, [0_u64, 4096, 0x7, 0x22, u64::MAX, 0])` is invoked; the returned `i64` is decoded — values in `-4095..=-1` are `-errno` and surface as `Error::HookInstallFailed`, otherwise `hook_page = ret as u64`
- [ ] Implementation: `process_vm_writev` writes a 4-byte zero word at `hook_page` (empty lock-list sentinel); `lock_list_len = 0` is set in the returned `HookHandle`
- [ ] Implementation: `process_vm_readv` captures 16 bytes from `target_fn` into `saved_prologue: [u8; 16]`
- [ ] Implementation: the tracer detaches (`PTRACE_DETACH`) before returning
- [ ] Implementation: `impl Drop for HookHandle` re-attaches, issues `remote_syscall(pid, __NR_munmap = 215, [hook_page, 4096, 0, 0, 0, 0])`, detaches, and swallows all errors (best-effort cleanup)
- [ ] Implementation: a doc comment on `impl Drop` explicitly flags that P04 will override this behavior once the trampoline is installed (must NOT unmap while the hook is live)
- [ ] Test: `cargo test -p resetprop --lib seal::hook::tests::handle_drop_is_defined` asserts the `Drop` impl exists (compile-time check via `fn _drop_compiles<T: Drop>() {}; _drop_compiles::<HookHandle>();`)
- [ ] Test: stage-B paths are exercised by the off-device Tier B child smoke test deferred to P04 (`tier_b_child_smoke.rs` is P04 scope per REGISTRY §3)

#### Self-Audit Gate 5 (MANDATORY — phase end)

- [ ] **Optimality** — Notes: ___________________________
- [ ] **Completeness** — Notes: ___________________________
- [ ] **Correctness** — Edge cases: `mmap` returns `-ENOMEM` (surfaces as HookInstallFailed), target PID exits mid-attach (ESRCH from ptrace, surfaces as HookInstallFailed), `process_vm_readv` returns short read (retry-or-fail loop must exist), Drop fires before stage-B completes (zero `hook_page` must not `munmap`): ___________________________

## Functional Requirements (subsystem-level)

### ELF parser (per `references/android-libc-elf.md` §2-§4)

- [ ] FR-01: `Elf64_Ehdr` is 64 bytes, `Elf64_Phdr` 56, `Elf64_Dyn` 16, `Elf64_Sym` 24, all validated by compile-time asserts (per `references/android-libc-elf.md` §2)
- [ ] FR-02: `parse_libc_elf` rejects any file whose first 4 bytes are not `[0x7f, b'E', b'L', b'F']` (per `references/android-libc-elf.md` §4.1)
- [ ] FR-03: `parse_libc_elf` rejects any file with `e_ident[EI_CLASS] != ELFCLASS64` (2) (per `references/android-libc-elf.md` §3)
- [ ] FR-04: `parse_libc_elf` rejects any file with `e_ident[EI_DATA] != ELFDATA2LSB` (1) (per `references/android-libc-elf.md` §3)
- [ ] FR-05: `parse_libc_elf` rejects any file with `e_machine != EM_AARCH64` (183) (per `references/android-libc-elf.md` §3)
- [ ] FR-06: `parse_libc_elf` rejects any file with `e_type != ET_DYN` (3) (per `references/android-libc-elf.md` §3)
- [ ] FR-07: `parse_libc_elf` locates the single `PT_DYNAMIC` program header and walks its entries until `DT_NULL` (per `references/android-libc-elf.md` §4.3)
- [ ] FR-08: `parse_libc_elf` translates `DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` virtual addresses to file offsets using the `PT_LOAD` map (per `references/android-libc-elf.md` §4.5)

### GNU_HASH lookup (per `references/android-libc-elf.md` §5)

- [ ] FR-09: GNU_HASH function is `h = 5381; h = h + (h << 5) + b` for each byte, matching bionic `linker_gnu_hash.h:46-54` (per `references/android-libc-elf.md` §5.2)
- [ ] FR-10: bloom filter mask bit width is 64 (arm64 pointer size), index is `(h / 64) & (bloom_size - 1)` (per `references/android-libc-elf.md` §5.3)
- [ ] FR-11: chain compare is `((chain[idx] ^ h) >> 1) == 0` (per bionic `linker_soinfo.cpp:362`)
- [ ] FR-12: chain terminator is `chain[idx] & 1 != 0` (per bionic `linker_soinfo.cpp:371`)
- [ ] FR-13: on hash match, name is byte-compared against the target before returning `Some(st_value)` (per `references/android-libc-elf.md` §5.3)

### Linear fallback (per `references/android-libc-elf.md` §6)

- [ ] FR-14: `linear_lookup` iterates at most `(strtab_offset - symtab_offset) / 24` entries (per `references/android-libc-elf.md` §6)
- [ ] FR-15: `linear_lookup` skips entries with `st_shndx == SHN_UNDEF` (per `references/android-libc-elf.md` §7)
- [ ] FR-16: `resolve_symbol` prefers GNU_HASH when available and falls back to linear (per P03 spec §Approach)
- [ ] FR-17: `resolve_symbol` returns a non-zero `st_value` for `__system_property_update` against the fixture cdylib (per P03 spec §Tasks T3)

### Hook installer (per P03 spec §Tasks T4-T5)

- [ ] FR-18: `install_init_hook` selects the first `/proc/<pid>/maps` row with `perms == "r-xp"` and `pathname` ending in `/libc.so` (per P03 spec §Tasks T4)
- [ ] FR-19: `install_init_hook` opens libc via `/proc/<pid>/map_files/<start>-<end>` (hex-formatted) (per `references/android-libc-elf.md` §1)
- [ ] FR-20: `target_fn = libc_base + st_value` where `libc_base` is the row's `start` (per `references/android-libc-elf.md` §7)
- [ ] FR-21: hook page is allocated via `remote_syscall(__NR_mmap, [0, 4096, PROT_READ|WRITE|EXEC = 0x7, MAP_PRIVATE|MAP_ANONYMOUS = 0x22, -1, 0])` (per `references/linux-arm64-abi.md` §1, §2)
- [ ] FR-22: on success, `hook_page` is non-zero, `saved_prologue` is 16 bytes of the target function prologue, `lock_list_len == 0` (per P03 spec §Tasks T5)
- [ ] FR-23: `Drop for HookHandle` unmaps the hook page (`__NR_munmap = 215`, length 4096) and ignores errors (per P03 spec §Tasks T5)

## Test Criteria

- [ ] TC-01: `cargo test -p resetprop --lib seal::elf` passes with zero failures (per P03 spec §Validation)
- [ ] TC-02: `cargo test -p resetprop --lib seal::hook` passes with zero failures (per P03 spec §Validation)
- [ ] TC-03: `cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1` passes with zero failures (per P03 spec §Validation)
- [ ] TC-04: `cargo test -p resetprop --lib seal::ptrace` still passes (regression check on P01) (per P03 spec §Validation)
- [ ] TC-05: `cargo test -p resetprop --lib seal::maps` still passes (regression check on P01) (per P03 spec §Validation)
- [ ] TC-06: `cargo build --release --target aarch64-linux-android -p resetprop-cli` produces a binary ≤ 400 KB (per REGISTRY §2 binary size target)

## Integration Verification

- [ ] IV-01: Consumes P01: `seal::ptrace::remote_syscall`, `seal::maps::parse_maps`, `Error::ElfParse`, `Error::SymbolNotFound`, `Error::HookInstallFailed` (per REGISTRY §5)
- [ ] IV-02: Exposes `HookHandle`, `install_init_hook`, `seal::elf::resolve_symbol` — consumed by P04 (per REGISTRY §5)
- [ ] IV-03: Does NOT touch `info.rs`, `trie.rs`, `compact.rs`, `area.rs`, `persist/mod.rs`, `appcompat.rs` (per plan §Files modified)
- [ ] IV-04: Does NOT add public methods to `PropSystem` (P04 scope — per P03 spec §Anti-Scope)

## Canonical Values (REGISTRY-locked)

| Item | Required Value | Verified at |
|------|----------------|-------------|
| `DT_GNU_HASH` | `0x6fff_fef5` (`/usr/include/elf.h:890-961`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |
| `ET_DYN` | `3` (`/usr/include/elf.h:161`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |
| `EM_AARCH64` | `183` (`/usr/include/elf.h:317`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |
| `sizeof(Elf64_Ehdr)` | `64` (`/usr/include/elf.h:81-97`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:<line>` compile-time assert |
| `sizeof(Elf64_Phdr)` | `56` (`/usr/include/elf.h:697-707`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:<line>` compile-time assert |
| `sizeof(Elf64_Dyn)` | `16` (`/usr/include/elf.h:878-886`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:<line>` compile-time assert |
| `sizeof(Elf64_Sym)` | `24` (`/usr/include/elf.h:530-538`; `references/android-libc-elf.md` §2) | `crates/resetprop/src/seal/elf.rs:<line>` compile-time assert |
| `MAP_PRIVATE \| MAP_ANONYMOUS` | `0x22` (libc `MAP_PRIVATE = 0x02`, `MAP_ANONYMOUS = 0x20`; `references/linux-arm64-abi.md` §8) | `crates/resetprop/src/seal/hook.rs:<line>` |
| `PROT_READ \| PROT_WRITE \| PROT_EXEC` | `0x7` (libc `PROT_READ = 0x1`, `PROT_WRITE = 0x2`, `PROT_EXEC = 0x4`) | `crates/resetprop/src/seal/hook.rs:<line>` |
| GNU_HASH seed | `5381` (`aosp-android15/bionic/linker/linker_gnu_hash.h:46-54`; `references/android-libc-elf.md` §5.2) | `crates/resetprop/src/seal/elf.rs:<line>` |
| Hook page size | `4096` (REGISTRY §1 — "Hook page: 4 KB RWX anonymous mmap"; plan §Tier B install step 3) | `crates/resetprop/src/seal/hook.rs:<line>` |
| `__NR_mmap` | `222` (`asm-generic/unistd.h:570,886`; `references/linux-arm64-abi.md` §1) | `crates/resetprop/src/seal/hook.rs:<line>` |
| `__NR_munmap` | `215` (`asm-generic/unistd.h:556`; `references/linux-arm64-abi.md` §1) | `crates/resetprop/src/seal/hook.rs:<line>` |
| `STT_FUNC` | `2` (`/usr/include/elf.h:585-599`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |
| `STB_GLOBAL` | `1` (`/usr/include/elf.h:585-599`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |
| `SHN_UNDEF` | `0` (`/usr/include/elf.h:413`; `references/android-libc-elf.md` §3) | `crates/resetprop/src/seal/elf.rs:<line>` |

## Anti-Scope (explicitly excluded)

- AS-01: No ARM64 trampoline encoding (P04 scope) (per P03 spec §Anti-Scope)
- AS-02: No trampoline write at `target_fn` via `process_vm_writev` (P04 scope) (per P03 spec §Anti-Scope)
- AS-03: No `seal_prop(name)` / `unseal_prop(name)` lock-list write path (P04 scope) (per P03 spec §Anti-Scope)
- AS-04: No `PropSystem::seal` / `PropSystem::unseal` / `PropSystem::seals` public API (P04 scope) (per P03 spec §Anti-Scope)
- AS-05: No CLI flag parsing for `-sl` / `--seal` / `--unseal` / `--seals` (P05 scope) (per P03 spec §Anti-Scope)
- AS-06: No `README.md` updates for the seal user surface (P05 scope) (per P03 spec §Anti-Scope)
- AS-07: No `tests/device-stress-test.sh` Test 21 / Test 22 additions (P05 scope) (per P03 spec §Anti-Scope)
- AS-08: No `propdetect` heuristics for the Tier B signature (deferred post-v1 per plan §Touchpoints for propdetect; REGISTRY §1) (per P03 spec §Anti-Scope)
- AS-09: No `SealRecord` disk persistence (deferred) (per P03 spec §Anti-Scope)
- AS-10: No i-cache coherence `membarrier` or `isb` calls (P04 scope) (per P03 spec §Anti-Scope)
- AS-11: No Tier A arena privatization (P02 scope, parallel track) (per P03 spec §Anti-Scope)

## Phase-End Adversarial Audit (Gate 2)

This block runs ONCE per phase, after the FINAL segment completes. NOT after each segment.

- [ ] Built context-pointer block (per `.claude/system-prompt.md §Gate 2` template — both persona prompts are inlined there verbatim) with: phase spec path `phases/seal/P03-tier-b-part1.md`, checklist path `phases/seal/checklists/P03-checklist.md`, REGISTRY path `phases/seal/REGISTRY-P.md`, code file paths (`crates/resetprop/src/seal/elf.rs`, `crates/resetprop/src/seal/hook.rs`, `crates/resetprop/src/seal/mod.rs`, `crates/resetprop/tests/fixtures/elf_fixture/`, `crates/resetprop/tests/elf_fixture_smoke.rs`), branch name `feat/P03-tier-b-part1`, External API Verification flag `YES` and the five sources listed in §External API Verification
- [ ] Deployed `oh-my-claudecode:code-reviewer` (Sonnet) with Persona A prompt + context-pointer block
- [ ] Deployed `oh-my-claudecode:critic` (Opus) with Persona B prompt + context-pointer block
- [ ] Both agents dispatched IN PARALLEL (single message, two Agent tool calls)
- [ ] Since `External API Verification: YES`, both agents grep'd/read actual sources (`bionic/linker/linker_gnu_hash.h`, `bionic/linker/linker_soinfo.cpp`, `bionic/linker/linker.cpp`, `/usr/include/elf.h`) and quoted real signatures / real line numbers
- [ ] code-reviewer report saved at `phases/seal/audits/P03-audit.md` — verdict: {{PASS | NEEDS_FIX}}
- [ ] critic report saved at `phases/seal/audits/P03-audit.md` — verdict: {{PASS | NEEDS_FIX}}
- [ ] All CRITICAL findings resolved
- [ ] All MAJOR findings resolved
- [ ] MINOR findings logged (not blocking)
- [ ] Re-ran both agents after fixes; both emitted `VERDICT: PASS`

## Acceptance Gate

- [ ] All 5 implementation tasks COMPLETE with self-audit gates filled (non-empty Notes)
- [ ] All FR-01 through FR-23 verified
- [ ] All TC-01 through TC-06 passing
- [ ] All IV-01 through IV-04 verified
- [ ] No regressions in P01 (`cargo test -p resetprop --lib seal::ptrace && cargo test -p resetprop --lib seal::maps`)
- [ ] Branch commits clean; conventional commits with `feat(seal):` / `test(seal):` / `fix(seal):` / `docs(seal):` prefix
- [ ] All 16 canonical values verified at the `file:line` column
- [ ] Gate 2 reports PASS from BOTH agents
- [ ] REGISTRY §4 P03 row updated to COMPLETE
- [ ] REGISTRY §7 session log appended with outcome (`PASS`) and audit verdict (`code-reviewer: PASS, critic: PASS`)
