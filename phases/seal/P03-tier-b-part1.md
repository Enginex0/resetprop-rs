# P03: Tier B Part 1 — ELF Parse + Hook Page Allocation

## Objective

Create a hand-rolled ELF64 walker that resolves `__system_property_update` inside init's mapped libc.so, and build the Tier B hook install entry point that parses `/proc/1/maps`, resolves the target function address, and allocates a 4 KB RWX anonymous hook page inside init via `remote_syscall(mmap, ...)`. Deliver `HookHandle` with target address, prologue snapshot, and empty lock-list sentinel — ready for P04 to add the ARM64 trampoline encoder and lock-list write path.

## Preconditions

- [ ] P01 (Foundation: ptrace + maps) shows COMPLETE in REGISTRY §4
- [ ] Files that must exist: `crates/resetprop/src/seal/ptrace.rs` (exposes `remote_syscall`), `crates/resetprop/src/seal/maps.rs` (exposes `parse_maps`), `crates/resetprop/src/error.rs` (extended with `PtraceAttach`, `PtraceScope`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`)

## Scope

### Files to CREATE

| File | Purpose |
|------|---------|
| `crates/resetprop/src/seal/elf.rs` | Hand-rolled ELF64 parser: Ehdr / Phdr / Dyn / Sym layouts; PT_LOAD → vaddr-to-foff map; PT_DYNAMIC walk to SYMTAB/STRTAB/GNU_HASH; `gnu_lookup` (bionic-exact) + `linear_lookup` + public `resolve_symbol` dispatcher |
| `crates/resetprop/src/seal/hook.rs` | Tier B skeleton (P03 scope): `HookHandle { pid, hook_page, lock_list_len, target_fn, saved_prologue }`; `install_init_hook(pid)` parses `/proc/<pid>/maps`, opens libc via `/proc/<pid>/map_files/<start>-<end>`, resolves `__system_property_update`, remote-mmaps the 4 KB RWX hook page, writes the 4-byte empty-list sentinel, snapshots the 16-byte function prologue; `Drop` cleanup `munmap`s the hook page |
| `crates/resetprop/tests/fixtures/elf_fixture/Cargo.toml` | `[lib] crate-type = ["cdylib"]` fixture with `#[no_mangle] pub extern "C"` stubs named `__system_property_update`, `seal_fixture_probe_a`, `seal_fixture_probe_b` so GNU_HASH tests have deterministic symbols to resolve |
| `crates/resetprop/tests/fixtures/elf_fixture/src/lib.rs` | Three `extern "C"` function stubs (bodies return 0) to populate `.dynsym` in the built `.so` |
| `crates/resetprop/tests/elf_fixture_smoke.rs` | `#[ignore]`-gated integration test: builds the cdylib via `cargo build -p elf_fixture --release`, loads the produced `.so` with `File::open`, calls `parse_libc_elf` + `resolve_symbol("__system_property_update")`, asserts the returned `st_value` is non-zero and matches what GNU_HASH returns from a separate linear scan over the same file |

### Files to MODIFY

| File | Changes |
|------|---------|
| `crates/resetprop/src/seal/mod.rs` | Add `pub mod elf;` and `pub mod hook;` declarations. No other changes (no `PropSystem::seal` glue yet — that is P04 scope). |

## Reference Material

Read ONLY these at session start:

| File | Sections | Est. Tokens | Why |
|------|----------|-------------|-----|
| `phases/seal/references/android-libc-elf.md` | §1 (APEX + `/proc/1/map_files`), §2 (ELF64 structs), §3 (constants), §4 (Ehdr/Phdr/Dyn walk), §5 (GNU_HASH), §6 (linear fallback), §7 (runtime address math), §8 (edge cases) | ~5400 | Entire file is the spec for `seal/elf.rs`; canonical constants and the bionic-exact GNU_HASH algorithm live here |
| `phases/seal/references/linux-arm64-abi.md` | §1 (`__NR_mmap = 222`), §2 (ARM64 syscall ABI), §7 (staging `svc #0`), §11 (errno decoding), §12 (remote_syscall skeleton) | ~1800 | Stage-B of `install_init_hook` calls `remote_syscall(__NR_mmap, …)` with `MAP_PRIVATE\|MAP_ANONYMOUS = 0x22` and `PROT_READ\|WRITE\|EXEC = 0x7` |
| `phases/seal/references/resetprop-rs-integration.md` | §3 (lib.rs module block — where `pub mod seal;` goes), §4 (`error.rs` Display/From pattern), §14 (seal module compile order), §16 (copy-paste lines) | ~1200 | Confirms P03 adds no `PropSystem::seal` public API; no `info.rs` / `area.rs` coupling |
| `crates/resetprop/src/error.rs` | Full file | ~350 | Verify the 5 error variants this phase consumes (`PtraceAttach`, `PtraceScope`, `ElfParse`, `SymbolNotFound`, `HookInstallFailed`) land from P01 with the expected `Display` wording |
| `crates/resetprop/src/seal/ptrace.rs` | Public export of `remote_syscall` | ~300 | Stage-B of `install_init_hook` calls this; confirm signature before wiring |
| `crates/resetprop/src/seal/maps.rs` | Public export of `parse_maps` + `MapEntry` shape | ~200 | Stage-A of `install_init_hook` filters `r-xp` rows whose `pathname` ends with `/libc.so` |

## External API Verification

- **Required**: YES
- **Sources to verify against**:
  - `/home/president/aosp-android15/bionic/linker/linker_gnu_hash.h` — ground-truth GNU_HASH function (`h = 5381; h = h + (h<<5) + b`, lines 46–54)
  - `/home/president/aosp-android15/bionic/linker/linker_soinfo.cpp` — `gnu_lookup` chain-walk (`((chain[n] ^ h) >> 1) == 0` compare at line 362, `chain[n] & 1` terminator at line 371, `kBloomMaskBits = sizeof(ElfW(Addr)) * 8` at line 330)
  - `/home/president/aosp-android15/bionic/linker/linker.cpp` — GNU_HASH on-disk header layout (`nbuckets`, `symoffset`, `bloom_size`, `bloom_shift` u32s followed by bloom[bloom_size] u64s, lines 2893–2919)
  - `/usr/include/elf.h` — Ehdr layout (lines 81–97), Phdr layout (lines 697–707), Dyn layout (lines 878–886), Sym layout (lines 530–538), `ET_DYN=3` (line 161), `EM_AARCH64=183` (line 317), `DT_GNU_HASH=0x6ffffef5` (lines 890–961), `STT_FUNC=2` + `STB_GLOBAL=1` (lines 585–599), `SHN_UNDEF=0` (line 413)
  - `phases/seal/references/android-libc-elf.md` — consolidates all of the above with line-level citations

## Tasks (Max 5 Per Session)

1. **Task 1**: Create `seal/elf.rs` with hand-rolled ELF64 parser. Define `#[repr(C)] Elf64_Ehdr` (64 B), `Elf64_Phdr` (56 B), `Elf64_Dyn` (16 B), `Elf64_Sym` (24 B), each guarded by a `const _: () = assert!(mem::size_of::<T>() == N)` check. Declare constants `ELFMAG`, `ELFCLASS64=2`, `ELFDATA2LSB=1`, `ET_DYN=3`, `EM_AARCH64=183`, `PT_LOAD=1`, `PT_DYNAMIC=2`, `DT_NULL=0`, `DT_HASH=4`, `DT_STRTAB=5`, `DT_SYMTAB=6`, `DT_STRSZ=10`, `DT_SYMENT=11`, `DT_GNU_HASH=0x6ffffef5`, `STT_FUNC=2`, `STB_GLOBAL=1`, `SHN_UNDEF=0`. Implement `pub fn parse_libc_elf(file: &File) -> Result<LibcElfView>` that `pread`s Ehdr, validates magic + class + data + machine + type + phentsize, reads `e_phnum` program headers, collects PT_LOAD tuples `(p_vaddr, p_offset, p_filesz)`, locates the single PT_DYNAMIC, walks its `Elf64_Dyn` entries until `DT_NULL`, and records `symtab_offset`, `strtab_offset`, `strtab_size`, `gnu_hash_offset` (all file offsets via `vaddr_to_foff`). Return `LibcElfView { file_contents_ro_mmap: ..., symtab_offset, strtab_offset, strtab_size, gnu_hash_offset }` or a subset loaded into owned `Vec<u8>` buffers. — Files: `crates/resetprop/src/seal/elf.rs` — Verifies: `cargo test -p resetprop --lib seal::elf::tests::ehdr_size_64`, `cargo test -p resetprop --lib seal::elf::tests::phdr_size_56`, `cargo test -p resetprop --lib seal::elf::tests::dyn_size_16`, `cargo test -p resetprop --lib seal::elf::tests::sym_size_24`

2. **Task 2**: Implement GNU_HASH lookup `pub fn gnu_lookup(view: &LibcElfView, name: &str) -> Option<u64>` — on-disk layout: `nbuckets: u32`, `symoffset: u32`, `bloom_size: u32`, `bloom_shift: u32`, then `bloom: [u64; bloom_size]`, then `buckets: [u32; nbuckets]`, then `chain: [u32; ...]` indexed by `symtab_index - symoffset`. Hash (bionic form): `let mut h: u32 = 5381; for b in name.as_bytes() { h = h.wrapping_add(h.wrapping_shl(5)).wrapping_add(*b as u32); }`. Bloom test: `let w = bloom[((h/64) & (bloom_size-1)) as usize]; if (w & (1 << (h%64))) == 0 || (w & (1 << ((h >> bloom_shift) % 64))) == 0 { return None; }`. Bucket: `let mut n = buckets[(h % nbuckets) as usize]; if n == 0 { return None; }`. Chain walk: read `c = chain[(n - symoffset) as usize]`; if `((c ^ h) >> 1) == 0`, read `Elf64_Sym` at `symtab_offset + n*24`, NUL-read name at `strtab_offset + st_name`, strcmp against target; if `(c & 1) != 0` break; else `n += 1`. Return `Some(sym.st_value)` on match. — Files: `crates/resetprop/src/seal/elf.rs` — Verifies: `cargo test -p resetprop --lib seal::elf::tests::gnu_hash_seed_5381` (hashes `__system_property_update` and compares to a constant cross-computed in the test), `cargo test -p resetprop --lib seal::elf::tests::gnu_lookup_absent_returns_none`

3. **Task 3**: Implement linear fallback `pub fn linear_lookup(view: &LibcElfView, name: &str) -> Option<u64>` that iterates `i = 0..((strtab_offset - symtab_offset) / 24)`, reads one `Elf64_Sym` per index, skips `st_shndx == SHN_UNDEF`, reads the NUL-terminated name at `strtab_offset + st_name` (bounded by `strtab_size`), and returns `Some(st_value)` on `memcmp` match. Expose `pub fn resolve_symbol(view: &LibcElfView, name: &str) -> Result<u64>` that returns `gnu_lookup(view, name)` if `gnu_hash_offset` is present, else `linear_lookup(view, name)`, and wraps a `None` result in `Error::SymbolNotFound(name.into())`. Write the fixture crate `crates/resetprop/tests/fixtures/elf_fixture/` (crate-type `cdylib`, three `#[no_mangle] pub extern "C"` stubs including `__system_property_update`), and write the integration test `crates/resetprop/tests/elf_fixture_smoke.rs` (`#[test] #[ignore]`) that invokes `cargo build -p elf_fixture --release` as a subprocess, opens the produced `.so` path, calls `parse_libc_elf` + `resolve_symbol`, and asserts non-zero return plus equality between the GNU_HASH path and the linear scan path. — Files: `crates/resetprop/src/seal/elf.rs`, `crates/resetprop/tests/fixtures/elf_fixture/Cargo.toml`, `crates/resetprop/tests/fixtures/elf_fixture/src/lib.rs`, `crates/resetprop/tests/elf_fixture_smoke.rs` — Verifies: `cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1`

4. **Task 4**: Create `seal/hook.rs` with `pub struct HookHandle { pid: libc::pid_t, hook_page: u64, lock_list_len: u32, target_fn: u64, saved_prologue: [u8; 16] }` and stage-A of `pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle>`. Stage-A: (a) call `seal::maps::parse_maps(pid)`; (b) filter rows with `perms == "r-xp"` and `pathname.ends_with("/libc.so")` — first match wins; (c) format the `/proc/<pid>/map_files/<start>-<end>` path using the row's `start` and `end` addresses; (d) `File::open` it; (e) pass to `seal::elf::parse_libc_elf`; (f) call `seal::elf::resolve_symbol(&view, "__system_property_update")`; (g) compute `target_fn = libc_base + st_value` where `libc_base` is the row's `start`; (h) return an `Err(Error::HookInstallFailed(...))` if any step fails. Expose the intermediate values so stage-B (Task 5) can continue from them. — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: `cargo test -p resetprop --lib seal::hook::tests::hook_handle_size`, `cargo test -p resetprop --lib seal::hook::tests::libc_row_filter_r_xp_suffix`

5. **Task 5**: Stage-B of `install_init_hook` — remote mmap, prologue snapshot, sentinel write, Drop-guarded cleanup. (a) ptrace-SEIZE + INTERRUPT the target PID using `seal::ptrace`; (b) call `seal::ptrace::remote_syscall(pid, __NR_mmap=222, [NULL=0, 4096, PROT_READ\|WRITE\|EXEC=0x7, MAP_PRIVATE\|MAP_ANONYMOUS=0x22, !0_u64 (-1 as fd), 0])` — interpret the returned `i64`: values in `-4095..=-1` are `-errno`, anything else is the `hook_page` virtual address; (c) `process_vm_writev` a 4-byte zero word at `hook_page` (the empty-lock-list sentinel — matches the Tier B design in plan §"Lay out the hook page"); (d) `process_vm_readv` 16 bytes from `target_fn` into `saved_prologue`; (e) detach from the target; (f) construct `HookHandle { pid, hook_page, lock_list_len: 0, target_fn, saved_prologue }`. Implement `impl Drop for HookHandle` that re-attaches, issues `remote_syscall(pid, __NR_munmap=215, [hook_page, 4096, 0, 0, 0, 0])`, and detaches — swallowing all errors (Drop is best-effort). Add a module comment noting that P04 will adjust `Drop` to survive hook installation (the runtime must NOT unmap after the trampoline is live). Do NOT write the trampoline in this phase; do NOT expose `seal_prop` / `unseal_prop` — both are P04 scope. — Files: `crates/resetprop/src/seal/hook.rs` — Verifies: `cargo test -p resetprop --lib seal::hook::tests::handle_drop_is_defined`, manual review: `install_init_hook` returns a `HookHandle` whose `saved_prologue` is 16 bytes and whose `hook_page` is non-zero when stage-B succeeds

## Approach

1. **Hand-rolled ELF64 parser, no external crate.** REGISTRY §1 forbids `goblin` / `object`; `references/resetprop-rs-integration.md` §2 confirms `libc` is the only runtime dep. We own the four `#[repr(C)]` layouts and the PT_DYNAMIC walk. Compile-time `assert!(mem::size_of::<T>() == N)` checks catch any accidental padding drift.

2. **GNU_HASH primary / linear fallback.** Per `references/android-libc-elf.md` §4.6 and §6: APEX libc.so is always stripped but keeps `.dynsym` + `DT_GNU_HASH`, so GNU_HASH is the fast path. Linear scan of ~3000 exported symbols is a few microseconds — acceptable as a one-shot fallback when `DT_GNU_HASH` is absent (bootstrap libc, user-built libc, HWASan variants). `resolve_symbol` tries GNU_HASH first because it's O(1) in the common case; linear is the defensive net.

3. **`/proc/<pid>/map_files/<start>-<end>` for atomic fd access.** Per `references/android-libc-elf.md` §1: this symlink resolves to the exact inode init has mapped, bypassing any APEX `overlayfs` / bind-mount TOCTOU. Opening `/apex/com.android.runtime/lib64/bionic/libc.so` directly is unsafe because the file on disk may have been replaced after init boot.

4. **ET_DYN runtime address math.** Per `references/android-libc-elf.md` §7: APEX libc.so is position-independent `ET_DYN` with first-PT_LOAD `p_vaddr = 0`, so `load_bias = libc_base` and `target_fn = libc_base + sym.st_value`. No relocation fixup is required because bionic libc has no text relocations (no `DT_TEXTREL`).

5. **Hook page allocation in P03; trampoline write in P04.** This phase produces the `HookHandle` with a ready-to-use hook page and a prologue snapshot. P04 owns: the ARM64 encoder (`trampoline_to(target)` → 16 bytes of `ldr x16, [pc, #8]; br x16; <u64 target>`), the `process_vm_writev` of the trampoline at `target_fn`, the lock-list entry writes via `seal_prop` / `unseal_prop`, and the i-cache coherence flush (`membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)` primary / `isb` fallback). The P03 `Drop` impl unmaps the hook page; P04 will update it to only unmap when the trampoline has been reverted (otherwise init executes unmapped memory).

6. **Empty lock-list sentinel written in P03.** The first 4 bytes of the hook page are zero — the "end of list" marker in the Tier B layout from plan §Install sequence. Writing it here means P04 can begin appending entries without a zero-init step.

7. **Branch: `feat/P03-tier-b-part1`** (per REGISTRY §4 — one branch across the whole phase).

## Validation

```bash
# Unit tests — size asserts, GNU_HASH seed, hook handle invariants
cargo test -p resetprop --lib seal::elf
cargo test -p resetprop --lib seal::hook

# Integration test — real cdylib, real ELF parse, real GNU_HASH lookup
cargo test -p resetprop --test elf_fixture_smoke -- --ignored --test-threads=1

# Prerequisite regressions must stay green
cargo test -p resetprop --lib seal::ptrace
cargo test -p resetprop --lib seal::maps

# Release build still produces a ≤400 KB arm64 binary
cargo build --release --target aarch64-linux-android -p resetprop-cli
ls -la target/aarch64-linux-android/release/resetprop      # ≤ 400 KB
```

All commands must exit 0. The `#[ignore]` gate on `elf_fixture_smoke` preserves CI green on environments that cannot build the cdylib — the developer must run it manually before marking the segment complete.

## Anti-Scope

- No ARM64 trampoline encoding (P04 scope)
- No trampoline write at `target_fn` via `process_vm_writev` (P04 scope)
- No `seal_prop(name)` / `unseal_prop(name)` lock-list write path (P04 scope)
- No `PropSystem::seal` / `PropSystem::unseal` / `PropSystem::seals` public API (P04 scope — still gated on the full Tier B install succeeding)
- No CLI flag parsing for `-sl` / `--seal` / `--unseal` / `--seals` (P05 scope)
- No `README.md` updates for the seal user surface (P05 scope)
- No `tests/device-stress-test.sh` Test 21 / Test 22 additions (P05 scope)
- No `propdetect` heuristics for the Tier B signature (deferred post-v1 per plan §Touchpoints for propdetect; REGISTRY §1 propdetect integration row)
- No persistence of `SealRecord` to disk (plan §Decisions locked — deferred)
- No i-cache coherence `membarrier` or `isb` calls (P04 scope — needed only after the trampoline write)
- No Tier A arena privatization (P02 scope, parallel track)
