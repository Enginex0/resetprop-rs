# P03 — Tier B pt1 Adversarial Audit Reports

Phase: P03 — Tier B pt1 (ELF parse + hook page allocation)
Branch: `feat/P03-tier-b-part1`
Base: `39ff4f4` (P02 HEAD)
Session: S01 (2026-04-18)

Gate 2 persona prompts are in `.claude/system-prompt.md` §Gate 2.

## code-reviewer report

**Reviewer:** oh-my-claudecode:code-reviewer (claude-sonnet-4-6)
**Date:** 2026-04-18
**Branch:** `feat/P03-tier-b-part1`
**Diff base:** `39ff4f4` (P02 HEAD)
**Files reviewed:** 9
  - `crates/resetprop/src/seal/elf.rs` (new, 742 lines)
  - `crates/resetprop/src/seal/hook.rs` (new, 415 lines)
  - `crates/resetprop/src/seal/mod.rs` (+2 lines)
  - `crates/resetprop/src/seal/arena.rs` (+13 lines)
  - `crates/resetprop/tests/elf_fixture_smoke.rs` (new, 101 lines)
  - `crates/resetprop/tests/fixtures/elf_fixture/Cargo.toml` (new)
  - `crates/resetprop/tests/fixtures/elf_fixture/src/lib.rs` (new)
  - `Cargo.toml` (+1 workspace member)

---

### External API Verification (MANDATORY — verified against actual sources)

**`linker_gnu_hash.h:46-54` — hash function:**
```c
uint32_t h = 5381;
while (*name_bytes != 0) {
    h += (h << 5) + *name_bytes++;  // h*33 + c
}
```
Our `elf.rs:385-391`: seed=5381, `h.wrapping_add(h.wrapping_shl(5)).wrapping_add(u32::from(b))`. **MATCHES.**

**`linker_soinfo.cpp:330` — `kBloomMaskBits`:**
```cpp
constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
```
On arm64, `sizeof(ElfW(Addr)) = 8`, so `kBloomMaskBits = 64`. Our `elf.rs:378`: `const BLOOM_MASK_BITS: u32 = 64`. **MATCHES.**

**`linker_soinfo.cpp:331` — bloom word index:**
```cpp
const uint32_t word_num = (hash / kBloomMaskBits) & gnu_maskwords_;
```
Note: `gnu_maskwords_` is `bloom_size - 1` after the decrement at `linker.cpp:2917`. Our `elf.rs:467`: `((h / BLOOM_MASK_BITS) & (bloom_size - 1)) as usize`. **MATCHES** — the code applies the decrement inline rather than storing it, which is equivalent.

**`linker_soinfo.cpp:362` — chain compare:**
```cpp
if (((gnu_chain_[n] ^ hash) >> 1) == 0 && ...)
```
Our `elf.rs:496`: `if ((c ^ h) >> 1) == 0`. **MATCHES.**

**`linker_soinfo.cpp:371` — chain terminator:**
```cpp
} while ((gnu_chain_[n++] & 1) == 0);
```
Our `elf.rs:508`: `if (c & 1) != 0 { return None; }`. **MATCHES** — do-while with post-increment is semantically equivalent to our read-then-check loop.

**`linker.cpp:2900-2919` — GNU_HASH on-disk layout:**
```cpp
gnu_nbucket_ = header[0];
// skip symndx (header[1])
gnu_maskwords_ = header[2];  // then --gnu_maskwords_ at line 2917
gnu_shift2_ = header[3];
gnu_bloom_filter_ = ptr + 16;
gnu_bucket_ = gnu_bloom_filter_ + gnu_maskwords_;  // AFTER decrement
```
Our `elf.rs:451-462`: reads `nbuckets=header[0]`, `symoffset=header[1]`, `bloom_size=header[2]`, `bloom_shift=header[3]`, bloom base at offset 16. **MATCHES.**

**`linker_relocate.h:60-74` — `is_symbol_global_and_defined`:**
```cpp
inline bool is_symbol_global_and_defined(const soinfo* si, const ElfW(Sym)* s) {
  if (ELF_ST_BIND(s->st_info) == STB_GLOBAL || ELF_ST_BIND(s->st_info) == STB_WEAK) {
    return s->st_shndx != SHN_UNDEF;
  }
  return false;  // STB_LOCAL and unknown bindings return false
}
```
Bionic's `gnu_lookup` at `linker_soinfo.cpp:365` calls this after the hash match AND name match. Our `gnu_lookup` in `elf.rs` performs no such binding/section check after a successful name match. See MAJOR finding M1 below.

**`/usr/include/elf.h` constants — all verified:**
- `ET_DYN=3` (line 161) ✓ — `elf.rs:40`
- `EM_AARCH64=183` (line 317) ✓ — `elf.rs:43`
- `SHN_UNDEF=0` (line 413) ✓ — `elf.rs:79`
- `STB_GLOBAL=1` (line 586) ✓ — `elf.rs:76`
- `STT_FUNC=2` (line 599) ✓ — `elf.rs:73`
- `DT_GNU_HASH=0x6ffffef5` (line 961) ✓ — `elf.rs:70`
- `sizeof(Elf64_Ehdr)=64` (lines 81-97) ✓ — `elf.rs:104`
- `sizeof(Elf64_Phdr)=56` (lines 697-707) ✓ — `elf.rs:119`
- `sizeof(Elf64_Dyn)=16` (lines 878-886) ✓ — `elf.rs:132`
- `sizeof(Elf64_Sym)=24` (lines 530-538) ✓ — `elf.rs:148`

---

### Stage 1 — Spec Compliance

All P03 anti-scope items respected: no trampoline, no `seal_prop`/`unseal_prop`, no `PropSystem::seal` API additions. Module declarations (`pub mod elf;`, `pub mod hook;`) added correctly to `seal/mod.rs`. `HookHandle` field layout matches spec exactly. `install_init_hook` implements stage-A and stage-B as specified. `parse_libc_elf`, `gnu_lookup`, `linear_lookup`, `resolve_symbol` all present. Fixture crate and integration test present and correctly gated. `arena.rs` visibility bump is the minimal 3-token change the spec permitted.

---

### Issues

---

**[MAJOR] M1: `gnu_lookup` returns a symbol match without validating binding or section index**
File: `crates/resetprop/src/seal/elf.rs:496-504`
Issue: After the hash compare `((c ^ h) >> 1) == 0` passes and the name matches, `gnu_lookup` returns `Some(sym.st_value)` with no check on `sym.st_shndx` or `ELF_ST_BIND(sym.st_info)`. Bionic's `gnu_lookup` (`linker_soinfo.cpp:362-369`) additionally requires `is_symbol_global_and_defined(this, s)` which enforces:
  1. `ELF_ST_BIND(st_info) == STB_GLOBAL || STB_WEAK`, AND
  2. `st_shndx != SHN_UNDEF`
A `.dynsym` entry whose name matches but whose binding is `STB_LOCAL` or whose `st_shndx == SHN_UNDEF` (unresolved import) would produce a false match and a wrong `target_fn` address. For the specific target symbol `__system_property_update` in Android's bionic libc, this is not a realistic problem (bionic would not ship a local or undefined entry under that name). However the contract diverges from bionic's reference implementation in a way that could bite on atypical libc builds (HWASan, bootstrap) or future symbol changes.
Evidence:
```
linker_relocate.h:60-74:
  if (ELF_ST_BIND(s->st_info) == STB_GLOBAL || ELF_ST_BIND(s->st_info) == STB_WEAK)
    return s->st_shndx != SHN_UNDEF;
  return false;
```
```
linker_soinfo.cpp:362-365:
  if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
      check_symbol_version(versym, n, verneed) &&
      strcmp(...) == 0 &&
      is_symbol_global_and_defined(this, s)) { return symtab_ + n; }
```
Fix: After the name-match at `elf.rs:503`, add:
```rust
let bind = sym.st_info >> 4;
if (bind != STB_GLOBAL && bind != 2 /* STB_WEAK */) || sym.st_shndx == SHN_UNDEF {
    // not a usable defined symbol; keep walking
} else {
    return Some(sym.st_value);
}
```
(Declare `pub const STB_WEAK: u8 = 2;` alongside the existing constants.) This aligns the fast path with bionic's exact filter and prevents a false match on undefined/local entries.

---

**[MAJOR] M2: `parse_libc_elf` does not seek to file offset 0 before `read_to_end`, making it position-dependent**
File: `crates/resetprop/src/seal/elf.rs:241-248`
Issue: `parse_libc_elf` takes `&File` (immutable reference) and does `file.try_clone()?; f.read_to_end(...)`. `try_clone` duplicates the file descriptor but the duplicate **shares the same file offset** as the original (POSIX `dup(2)` semantics — both fds share the same `struct file` offset). If the caller has already advanced the file offset (e.g. by peeking at the magic bytes, reading the header, or any partial read), `read_to_end` will start from that non-zero offset and produce a truncated `bytes` buffer. All subsequent struct reads would be offset by the amount already consumed, silently producing garbage or `ElfParse` errors with misleading offsets. The `install_init_hook_stage_a` path opens a fresh `File::open` before passing to `parse_libc_elf`, so the production path is currently safe. The integration test at `elf_fixture_smoke.rs:73-75` also opens fresh. But the function's public contract (`pub fn parse_libc_elf(file: &File)`) makes no such guarantee, and future callers (P04 diagnostics, etc.) could violate it silently.
Evidence:
```rust
// elf.rs:247-248:
let mut f = file.try_clone()?;   // dup shares offset
f.read_to_end(&mut bytes)?;      // starts at current offset, not 0
```
Fix: Add a seek to zero before `read_to_end`:
```rust
use std::io::{Seek, SeekFrom};
let mut f = file.try_clone()?;
f.seek(SeekFrom::Start(0))
    .map_err(|e| Error::ElfParse(format!("seek to 0: {e}")))?;
f.read_to_end(&mut bytes)?;
```
This makes the function safe to call on a `File` that has been partially consumed, removing a latent correctness hazard from the public API.

---

**[MINOR] m1: `gnu_lookup` does not validate `strtab_size > 0` before passing it to `read_cstr_at` as `max_len`**
File: `crates/resetprop/src/seal/elf.rs:502`
Issue: `view.strtab_size` can be `0` when `DT_STRSZ` is absent (defaulted to `0` at `elf.rs:311`, `strtab_size: strtab_sz as usize` at `elf.rs:365`). When `strtab_size == 0`, `read_cstr_at(bytes, name_off, 0)` computes `hard_end = bytes.len().min(name_off + 0) = name_off`. The subsequent `if offset >= hard_end` check returns `None` immediately because `name_off >= name_off`. This means `gnu_lookup` silently returns `None` for every symbol when `DT_STRSZ` is absent, even if the names are readable. `linear_lookup` (line 560) shares this issue. The bug is masked in practice because bionic always emits `DT_STRSZ`, but the invariant is undocumented and the silent miss could be confusing.
Fix: When `strtab_size == 0`, pass `bytes.len()` as the bound instead: `let max_len = if view.strtab_size > 0 { view.strtab_size } else { bytes.len() };`. Alternatively, document the invariant with a debug assertion: `debug_assert!(view.strtab_size > 0, "DT_STRSZ absent — strtab names will not resolve");`.

---

**[MINOR] m2: `gnu_lookup` uses `(bloom_size - 1)` mask but does not verify `bloom_size` is a power of two**
File: `crates/resetprop/src/seal/elf.rs:456-467`
Issue: The bloom filter index `(h / BLOOM_MASK_BITS) & (bloom_size - 1)` is correct only when `bloom_size` is a power of two (the bitwise-AND acts as modulo only then). Bionic validates this at `linker.cpp:2912-2916`: `if (!powerof2(gnu_maskwords_)) { DL_ERR(...); return false; }`. Our code skips this check. A malformed `.so` with a non-power-of-two `bloom_size` would produce a bloom index that exceeds the actual array bounds or gives a wrong slot, leading to either an OOB read caught by the `u64_le` bounds check (returning `None`) or a false bloom hit that results in a bucket/chain walk on garbage data. In practice, all well-formed GNU_HASH tables have power-of-two bloom sizes; the risk is confined to malformed inputs.
Fix: Add `if !bloom_size.is_power_of_two() { return None; }` after the `bloom_size == 0` guard at `elf.rs:456`.

---

**[MINOR] m3: `hook.rs` Drop's `drop_best_effort` re-attaches to the tracee with a full SEIZE+INTERRUPT even when the tracee may already be dead**
File: `crates/resetprop/src/seal/hook.rs:271-301`
Issue: `drop_best_effort` calls `seal::maps::parse_maps(self.pid)` then `RemoteAttach::new(self.pid)` in Drop. If the process has died between `install_init_hook` returning and the handle being dropped, `parse_maps` will get `ENOENT` (the `/proc/<pid>/maps` file disappears) and the function returns early via `?` (propagated to Drop, which swallows it). This is correct behaviour. However, the comment at `hook.rs:305-310` warns that this unmap must NOT fire once the trampoline is live (P04), but provides no mechanism to suppress it — P04 will need to add a `trampoline_installed: bool` flag to `HookHandle`. This is acknowledged in the P03 spec and is not a bug in P03 scope, but the structural gap is worth flagging so P04 does not forget.
Fix: No code change required in P03. P04 must add `trampoline_installed: bool` to `HookHandle` and short-circuit `drop_best_effort` when `true`. Recommend adding a `// P04: add trampoline_installed guard here` comment at `hook.rs:305` so the skip point is obvious.

---

**[MINOR] m4: `DT_GNU_HASH` constant type is `i64` but the on-disk `d_tag` field is typically treated as signed `Elf64_Sxword` — the numeric value is fine but the constant could mislead**
File: `crates/resetprop/src/seal/elf.rs:70`
Issue: `pub const DT_GNU_HASH: i64 = 0x6fff_fef5;`. The value `0x6ffffef5 = 1879048949` fits in both `i32` and `i64` (positive), so no sign extension issue exists. The `d_tag` field in `Elf64_Dyn` is declared `i64` in the struct (`elf.rs:129`), which matches the ELF spec `Elf64_Sxword`. The type choice is internally consistent and correct. Minor concern: `/usr/include/elf.h:961` defines this as an unsigned `#define DT_GNU_HASH 0x6ffffef5`, which in C is an `int` or `unsigned int`. Our `i64` is a widened signed equivalent — no bit-pattern difference. Not a defect, logged for awareness.

---

### Positive Observations

1. **Bionic-exact GNU_HASH implementation.** The hash seed (5381), bloom bit width (64), word index masking `(bloom_size-1)`, chain compare `((c^h)>>1)==0`, and terminator `(c&1)!=0` all match bionic verbatim against the actual sources. The `linker.cpp` on-disk header layout (16-byte header: nbuckets, symoffset, bloom_size, bloom_shift; then bloom array; then buckets; then chain) is correctly decoded.

2. **Compile-time size asserts.** All four `#[repr(C)]` structs have `const _: () = assert!(mem::size_of::<T>() == N)` guards that catch layout regressions at compile time regardless of target.

3. **Overflow-safe arithmetic throughout.** Every array index computation uses `checked_add`/`checked_mul` with `?`-propagation. The `read_struct` bounds check prevents OOB at the `unsafe` boundary. `gnu_lookup` and `linear_lookup` both use `u32_le`/`u64_le` safe readers — zero `unsafe` code in the lookup paths.

4. **Correct `/proc/<pid>/map_files` path.** `hook.rs:111-113` formats the path as `/proc/{pid}/map_files/{start:x}-{end:x}` with lowercase hex — matching the kernel's naming convention — and derives `libc_base` from the row's `start` field, which is the correct ET_DYN load bias.

5. **`libc_hwasan.so` suffix guard.** `is_libc_row` uses `ends_with("/libc.so")` with the mandatory leading slash, correctly rejecting `libc_hwasan.so`. The dedicated test at `hook.rs:387-390` pins this invariant.

6. **`HookHandle::drop` zero-page guard.** The early return at `hook.rs:309` when `hook_page == 0` prevents a munmap(0, 4096) in the tracee from synthetic handles constructed in tests.

7. **Stage-B mmap errno decode.** The `(-4095..=-1).contains(&ret)` check at `hook.rs:213` correctly implements the Linux EMAX_ERRNO window per `linux-arm64-abi.md §11`.

8. **`try_clone` + `read_to_end` design rationale.** The choice to own the full file in `LibcElfView::bytes` avoids `unsafe` mmap lifetime juggling. For ~1 MB libc.so, this is the right trade-off.

---

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| MAJOR    | 2 (M1: missing symbol binding/shndx validation in gnu_lookup; M2: missing seek-to-0 before read_to_end) |
| MINOR    | 4 (m1: strtab_size=0 silently kills name resolution; m2: bloom_size power-of-two not checked; m3: Drop trampoline-live gap for P04; m4: DT_GNU_HASH type cosmetic) |

M1 is a contract divergence from bionic's own lookup filter that could produce a wrong `target_fn` on atypical builds. M2 is a latent API hazard that is safe on the current call sites but will silently corrupt reads if the `&File` argument is ever passed with a non-zero offset. Both MAJOR findings should be fixed before merge.

VERDICT: NEEDS_FIX
MAJOR findings: 2 (M1, M2)

## critic report

**Mode**: THOROUGH → escalated to ADVERSARIAL after 1 CRITICAL and 2 MAJOR surfaced.

**Scope verified**: P03 spec, checklist, REGISTRY §1-§8, P01/P02 audits context, all 6 source files listed in Scope, all 5 External API Verification sources.

---

### [SEVERITY: CRITICAL]
[DECISION CHALLENGED: `install_init_hook` re-parses `/proc/<pid>/maps` TWICE under two independent `RemoteAttach` windows — once in stage-A (`install_init_hook_stage_a` at `hook.rs:101-129`) and again inside stage-B's `derive_libc_scratch_pc` scan setup at `hook.rs:148-163`. Between stage-A's synchronous `parse_maps` + `File::open("/proc/1/map_files/<libc_start>-<libc_end>")` and stage-B's scratch-PC derivation, init is NOT ptrace-stopped.]
[WHY IT'S WEAK: Stage-A reads `/proc/1/maps` at time T0, resolves `libc_row.start` / `libc_row.end`, computes `target_fn = libc_base + st_value`, then RETURNS those values. Only at `hook.rs:185` does the RemoteAttach guard acquire. If init `dlopen`s a new library, `mremap`s libc, or (more plausibly on Android 15) if the APEX runtime swap-upgrades the libc mapping between T0 and the attach — extremely rare in practice but possible during Mainline module updates — then `target_fn` points into a stale/unmapped region, `libc_base..libc_end` passed into `derive_libc_scratch_pc` describes a window that no longer exists, and `scratch_pc = libc_base + slide_offset` either crashes `ptrace_peektext` with EFAULT or (worse) selects a scratch PC in an mmap'd region the kernel has since repurposed. The write_remote at `hook.rs:233` then stamps zeros into whatever has been mapped at the OLD `hook_page` (well — no, hook_page came from the stage-B mmap so that is safe), but the `saved_prologue` read at `hook.rs:243` reads from `target_fn` which is the STALE value computed in stage-A. If init is now running code whose prologue at that VA differs from what stage-A's libc had, P04's trampoline install will overwrite bytes whose saved copy is wrong, and Drop + unseal cannot revert faithfully. P02 round-2 audit explicitly flagged the analogous staleness as "M8: non-atomic mirror seal" and deferred with v2 plan. Here the TOCTOU window is inside a SINGLE install, not across two installs, and is architectural, not operational.]
[BETTER ALTERNATIVE: Acquire `RemoteAttach` FIRST, then call `parse_maps` ONCE inside the attach window, then open `/proc/<pid>/map_files/<start>-<end>`, parse the ELF, resolve the symbol, compute `target_fn`, derive the scratch PC from the SAME `libc_row`, and issue the remote mmap. The whole pipeline then holds under one ptrace-stop, and init cannot re-layout its address space underneath the install. Code structure: move `install_init_hook_stage_a`'s body after `RemoteAttach::new` and drop `libc_end` from the stage-A return shape. One `parse_maps` call is kept for diagnostics; the second is eliminated. Compare P02's `remote_remap_private` (arena.rs:270-473) which acquires `guard = RemoteAttach::new(pid)` at line 278 BEFORE calling `parse_maps` at line 281 — the same architectural pattern that was locked during P02 round 1.]
[WHEN IT MATTERS: Whenever init's mapping set changes between stage-A and stage-B: APEX module hot-swap (Mainline Train), a security update that triggers an init re-exec, any `mprotect` that splits a VMA, or simply aggressive scheduler behavior where a second ptrace-tracer (adb shell gdbserver attached to init for diagnostics) interacts. On a quiescent device this may never reproduce; on a CI device farm or production fleet, this is a latent intermittent-failure producer that will be impossible to reproduce in isolation and will silently corrupt P04's trampoline on the hit.]

---

### [SEVERITY: MAJOR]
[DECISION CHALLENGED: `HookHandle::drop_best_effort` (hook.rs:271-301) re-parses `/proc/<pid>/maps`, acquires a fresh `RemoteAttach`, re-derives a libc scratch PC, and issues a remote `munmap` — WHILE executing inside `Drop`. This runs unconditionally at handle drop unless `hook_page == 0`.]
[WHY IT'S WEAK: Three failure modes compound.
(a) P03 ships an `install_init_hook` that returns a `HookHandle` and does nothing else — no caller consumes it in the crate yet. Therefore the ONLY way `Drop` fires in the P03 deliverable is (i) a test literal like `hook_handle_size` which correctly guards via hook_page==0, or (ii) a future P04 caller that constructs the handle for diagnostic / error-unwind purposes. So Drop becomes live code at the exact moment P04 starts writing trampolines — and the module-doc warning at hook.rs:313-316 explicitly says "once the trampoline is live at `target_fn`, this Drop MUST NOT unmap". The escape hatch is written in English prose, not encoded in the type. P04 is one forgotten feature-flag away from munmap-ing a page that init is actively executing, which crashes PID 1 and reboots the device.
(b) Drop runs WITHOUT `&mut self` access to any "installed" flag, because there isn't one. The only guard is `hook_page == 0`, which stage-B sets to non-zero on success. So Drop cannot distinguish "page allocated but trampoline not yet written" (safe to munmap) from "page allocated AND trampoline live" (unsafe to munmap). The P03 API design forces P04 to either (i) add a new field and remember to set it, or (ii) completely rewrite Drop. Either way, Drop is a latent foot-gun.
(c) `parse_maps` + `RemoteAttach::new` + `ptrace_seize` inside Drop can all fail. They all propagate back via `?`, get discarded by `let _ = self.drop_best_effort();` at hook.rs:320, and leak the 4 KiB RWX page in init silently. No warning is emitted. An operator running seal/unseal in a loop during CI accumulates invisible RWX pages in PID 1.
[BETTER ALTERNATIVE: Choose ONE of:
- Make `HookHandle` non-Droppable by design. Consume it via explicit `fn uninstall(self) -> Result<()>` that performs the munmap under the install-site error context. The test `handle_drop_is_defined` is then replaced with a compile-check that `uninstall` exists. P04's lock-list install path becomes a state-machine `HookHandle::install_trampoline(self) -> InstalledHookHandle`, where InstalledHookHandle's Drop cannot unmap (the type no longer owns the page; the runtime does). This is the "typestate" pattern and it encodes the P04 safety rule in the compiler, not a doc comment.
- OR: Document the Drop behavior at the `pub` boundary and add an explicit `forget_hook_page(handle)` path for P04 to call before letting the handle drop. Far weaker than typestate but still improves on prose.
- At minimum: add a debug_assert or eprintln! on the drop-failure path so silent leaks surface in test runs.]
[WHEN IT MATTERS: (a) manifests the first time a P04 developer writes `return Err(...)` after trampoline install without first `mem::forget`-ing the handle — device reboots during integration test. (b) manifests when init transiently refuses ptrace (yama tightening, SELinux mid-boot) — Drop silently swallows, 4 KiB leak per call, observable only via `/proc/1/smaps` inspection. (c) is a hazard even without P04: any test that constructs a live HookHandle on an aarch64 target and panics before explicit cleanup leaks memory in init.]

---

### [SEVERITY: MAJOR]
[DECISION CHALLENGED: `install_init_hook` leaks the 4 KiB RWX hook page on ANY stage-B error path after `mmap` returns a valid address but before `Ok(HookHandle { ... })` is constructed (`hook.rs:213-259`). The code comment at hook.rs:221-223 acknowledges this: "From this point until the handle is returned, a failure leaks `hook_page` (4 KiB RWX) in the tracee. This is deliberate".]
[WHY IT'S WEAK: The rationale cited ("consistent with arena.rs's bootstrap-page leak policy") is not parallel. arena.rs leaks only on error-unwind and includes a munmap on the success path at arena.rs:459-466 — the leak window is the error path ONLY. Here, the error paths that can hit between mmap-success and handle-construction are:
(1) write_remote sentinel fails (hook.rs:233) — e.g. tracee scheduler hiccup, ESRCH, ENOSYS on a locked-down kernel.
(2) read_remote prologue fails (hook.rs:243) — same reasons.
(3) guard.detach() fails (hook.rs:251) — rare but documented in ptrace(2) for ESRCH.
On any of these, a 4 KiB RWX page persists in init's address space with no tracking. Over repeated install-fail-retry cycles (a CI or stress-test scenario), init's VM accumulates RWX pages, which is BOTH a reliability concern (OOM in the kernel's VMA tree eventually) AND a security degradation (each leaked RWX page is a persistent code-injection slot for any subsequent vulnerability).
The "just add a best-effort cleanup" is avoided in the doc comment on grounds that it "would duplicate the P02 round-2 M6 cleanup complexity". But P02 M6 is fixed — arena.rs now munmaps the bootstrap page on the success path (arena.rs:459-466). The complexity it refers to no longer exists in arena.rs, and hook.rs is free to use the same pattern.]
[BETTER ALTERNATIVE: Wrap the post-mmap error-propagation sites in explicit best-effort munmaps. Pattern (applied at each `?`-propagation after `hook_page` is bound):
```rust
let sentinel_res = unsafe { write_remote(pid, hook_page, &sentinel) };
if let Err(e) = sentinel_res {
    // Best-effort: we are still under the same RemoteAttach, scratch_pc is still valid.
    let _ = unsafe { remote_syscall_via_poke(pid, scratch_pc, NR_MUNMAP, [hook_page, HOOK_PAGE_SIZE, 0, 0, 0, 0]) };
    return Err(Error::HookInstallFailed(format!("stage-B: write sentinel: {e}")));
}
```
Applied 3x (sentinel, prologue, detach) this adds ~20 lines and eliminates the leak class entirely. The code is clearer than the prose rationale currently covering for its absence.]
[WHEN IT MATTERS: Any stress-test harness that exercises install failure paths (deliberate or incidental) on a long-running init. CI device farms running seal/unseal cycles during integration. Any time the sentinel write races an init resume (ESRCH). Over hours, init's RWX page count trends upward; on a 30-day device uptime with 1% install failure rate and 100 installs/day, init accumulates 30 * 100 * 0.01 = 30 leaked RWX pages = 120 KiB of persistent attacker-accessible code-injection space. Small but monotonically growing, and invisible to the operator because the error message gives no hint of the leak.]

---

### [SEVERITY: MAJOR]
[DECISION CHALLENGED: `resolve_symbol` (elf.rs:585-595) falls through from GNU_HASH to linear_lookup on a `None` return from `gnu_lookup`, but the doc comment at elf.rs:581-584 explicitly states this is deliberate "defensive" behavior against "a malformed GNU_HASH section (bad bloom filter, truncated chain)".]
[WHY IT'S WEAK: A correctly-formed GNU_HASH table's `None` return is authoritative — the symbol is NOT in the DSO. Falling through to linear scan in the well-formed case causes a silent ~3000-entry string-compare scan per lookup on every miss. This is: (a) a 100-1000x performance regression for miss cases (microseconds vs dozens of microseconds, multiplied by any future use of resolve_symbol in hot paths); (b) an information-leak from the parser about what "malformed" means — the doc comment admits the GNU_HASH invariants the impl relies on are neither verified at parse time nor repeatable across lookups; (c) a correctness hazard when the SAME symbol name appears in `.dynsym` in an UNHASHED slot (e.g. SHN_UNDEF import) vs a HASHED slot (definition) — linear_lookup skips SHN_UNDEF so this is masked today, but if any future refactor alters linear's filter, the fallback could return a stale or weak import address for a symbol the GNU_HASH path correctly said was absent.
Additionally, the FR-16 spec text explicitly says "prefers GNU_HASH when available and falls back to linear (per P03 spec §Approach)" — §Approach item 2 says "Linear scan … acceptable as a one-shot fallback when `DT_GNU_HASH` is absent". The falling-through-on-miss semantics the IMPLEMENTATION shipped is a SUPERSET of what the spec authorized. This is a scope drift.]
[BETTER ALTERNATIVE: Make the semantics match spec §Approach item 2 exactly:
```rust
pub fn resolve_symbol(view: &LibcElfView, name: &str) -> Result<u64> {
    if view.gnu_hash_offset.is_some() {
        return match gnu_lookup(view, name) {
            Some(v) => Ok(v),
            None => Err(Error::SymbolNotFound(name.into())),
        };
    }
    linear_lookup(view, name).ok_or_else(|| Error::SymbolNotFound(name.into()))
}
```
If the defensive fallback is genuinely wanted, it must be gated behind a separate entry point (`resolve_symbol_with_linear_fallback`) so the default stays fast and FR-16-compliant. The integration test at `elf_fixture_smoke.rs:84-100` already cross-checks both paths when `gnu_hash_offset.is_some()` — keeping that invariant requires no change to the dispatcher's hit semantics, only its miss semantics.]
[WHEN IT MATTERS: Every call to `resolve_symbol` for a symbol not in libc.so's exports. Today that's "never" because the only caller is stage-A looking up `__system_property_update`. As soon as P04 adds any introspection hook or propdetect grows heuristics that probe for optional symbols (the REGISTRY §1 "propdetect integration" row), every miss costs ~3000 struct reads + strcmps. Also: any user-built libc.so with a corrupt GNU_HASH (rare but reported in the wild for prebuilt Android variants) gets a surprising success where bionic's own linker would have failed — the two environments diverge silently.]

---

### [SEVERITY: MAJOR]
[DECISION CHALLENGED: `gnu_lookup` rejects bloom_size == 0 at elf.rs:456 but does NOT verify `bloom_size` is a power of two. It then computes `(bloom_size - 1)` as the word-index mask at elf.rs:467 — the classic "power-of-two assumption baked into a bitmask". Bionic linker.cpp:2912-2917 REJECTS non-powerof2 maskwords with `DL_ERR("invalid maskwords for gnu_hash ... expecting power to two")` BEFORE using the decremented value.]
[WHY IT'S WEAK: If we ever encounter a hand-rolled / obscure-toolchain libc.so where `bloom_size` is, say, 3 (non-PoT), then `bloom_size - 1 = 2 = 0b10`, which masks word_num to either 0 or 2 — skipping word index 1 entirely. `gnu_lookup` silently returns wrong answers (false negatives when the real hash lands in word 1, potentially false positives if another symbol hashes to a bucket that gets mis-routed). The spec's §Approach item 2 claims GNU_HASH is "bionic-exact" — but bionic REJECTS this input shape; our code accepts and silently corrupts lookups. Because `resolve_symbol` falls through on GNU_HASH `None`, a malformed-but-well-terminated GNU_HASH could return the WRONG `st_value` for a real symbol before the linear scan runs. Compound with Finding #4 (fallthrough on miss) and this becomes a silent corruption hazard.]
[BETTER ALTERNATIVE: Add a power-of-two check at parse time (in `parse_libc_elf` when the GNU_HASH header is first read) or at lookup time (in `gnu_lookup` before computing `word_idx`). Rust has a stable `u32::is_power_of_two()` method — one-liner:
```rust
if bloom_size == 0 || !bloom_size.is_power_of_two() {
    return None;
}
```
or at parse time, promote to `Error::ElfParse("GNU_HASH bloom_size not power of 2")`. Either matches bionic's contract and closes the divergence.]
[WHEN IT MATTERS: Any non-standard libc.so built with a toolchain that doesn't respect the GNU_HASH PoT invariant. Rare in practice for Android — but the Tier B flow is explicitly designed to handle "bootstrap libc, user-built libc, HWASan variants" (spec §Approach item 2 justifies the linear fallback with this). HWASan libc is the exact edge case where the toolchain could diverge, and the Tier B install would silently target the wrong function address on such a device.]

---

### [SEVERITY: MAJOR]
[DECISION CHALLENGED: `derive_libc_scratch_pc` (hook.rs:148-164) is invoked TWICE in the install+drop lifecycle — once in `install_init_hook` (hook.rs:193) and once in `HookHandle::drop_best_effort` (hook.rs:284). The scratch PC selection is non-deterministic between the two calls because `find_scratch_slot`'s behavior depends on which libc.text page landed at which `libc_base` at the moment of each call, AND the fallback path's SCRATCH_FALLBACK_MIN_OFFSET-based pick is byte-deterministic only if `libc_base..libc_end` hasn't moved.]
[WHY IT'S WEAK: The Drop path's comment at hook.rs:266-270 acknowledges the non-identity: "will pick the same slot stage-B used (or an equivalent one — the restore invariants do not require identity)". That invariant hinges on the `find_scratch_slot` caller documentation at arena.rs:127-135 which says restore is handled by RemoteAttach + save/restore guards inside `remote_syscall_via_poke`. This is correct for each INDIVIDUAL call under its OWN RemoteAttach, but it means: the Drop's munmap executes via a DIFFERENT scratch PC than the install's mmap, against a libc.text window that may have been (a) mprotected, (b) mremapped, or (c) part of an APEX hot-swap during the handle's lifetime. There is no invariant verifying that the scratch PC Drop picks is even inside `r-xp` at Drop time — `parse_maps` is re-run, but no cross-check against `self.target_fn` or the previously-known libc range is performed.
A secondary concern: the two scans each read up to 64 KiB of libc.text via `read_remote`. Two scans per install+drop cycle = 128 KiB of `process_vm_readv` traffic, double what arena.rs does. Not catastrophic, but unnecessary.]
[BETTER ALTERNATIVE: Cache the scratch PC and libc range in `HookHandle`:
```rust
pub struct HookHandle {
    pub(crate) pid: libc::pid_t,
    pub(crate) hook_page: u64,
    pub(crate) lock_list_len: u32,
    pub(crate) target_fn: u64,
    pub(crate) saved_prologue: [u8; 16],
    // Added for drop path consistency:
    pub(crate) libc_base: u64,
    pub(crate) libc_end: u64,
    pub(crate) scratch_pc: u64,
}
```
Drop then re-validates that `libc_base..libc_end` is still an `r-xp` mapping (via a single `parse_maps` + check) before using the cached `scratch_pc`. If the mapping has moved, Drop bails with an eprintln! and leaves the page mapped — loud failure rather than silent wrong-address write. This also halves the `read_remote` traffic because the second libc.text scan disappears.]
[WHEN IT MATTERS: Long-lived `HookHandle`s — exactly the shape P04 needs for the seal/unseal lifecycle, where a handle is held for the duration of a seal. Every minute the handle lives is another chance for init's address space to shift under it. On a production device this is vanishingly rare; on a fuzzed integration-test environment (kernel variants, Mainline hot-swap simulations) it is observable and non-deterministic.]

---

### [SEVERITY: MINOR]
[DECISION CHALLENGED: The `hook_handle_size` test at hook.rs:342-356 is misnamed. It tests field reachability and value round-tripping, not "size" (byte layout).]
[WHY IT'S WEAK: The checklist §Task 4 bullet "asserts the struct has the expected field layout (non-zero fields are reachable via accessors)" — the test name evokes `mem::size_of::<HookHandle>() == N` which it doesn't assert. A future reviewer reading `cargo test` output sees `hook_handle_size ok` and assumes a repr guard exists when none does.]
[BETTER ALTERNATIVE: Rename to `hook_handle_fields_round_trip`. Or add the actual size assertion as a separate compile-time `const _: () = assert!(mem::size_of::<HookHandle>() == 48);` — though `HookHandle` is not `repr(C)` so its size is not spec-locked and a compile-time assertion may be overreach. Rename only.]
[WHEN IT MATTERS: Documentation drift / reviewer confusion; no runtime impact.]

---

### [SEVERITY: MINOR]
[DECISION CHALLENGED: `gnu_lookup` at elf.rs:445 reads `nbuckets` / `symoffset` / `bloom_size` / `bloom_shift` via `u32_le` helper (safe) but reads `Elf64_Sym` via `read_struct` (unsafe) at elf.rs:500. Two read primitives for semantically equivalent "decode a fixed-layout struct from a bounded byte range" operation.]
[WHY IT'S WEAK: The self-audit §Task 2 Optimality note explicitly justifies this: `u32::from_le_bytes` is "no unsafe, same codegen", whereas `read_struct` remains unsafe with a SAFETY paragraph. Fine as documented, but it means future POD additions (e.g., if P04 ever decodes `Elf64_Rela`) need to re-decide per-type whether to use safe slice arithmetic or the unsafe `read_struct`. No convention is enforced; the codebase has two paths forever.]
[BETTER ALTERNATIVE: Pick one. A safe `read_struct` using `bytemuck::Pod` would eliminate the unsafe block entirely — but bytemuck is a forbidden crate per REGISTRY §1. An in-crate `SafePod` trait with per-type `from_le_bytes` implementations would be the no-dep version. Either way, either every POD read goes through the safe path or every POD read goes through `read_struct`; mixing is a consistency smell, not a bug.]
[WHEN IT MATTERS: Code-review bandwidth. No runtime impact.]

---

### Gaps — what the phase SHOULD have addressed and didn't

- **Drop safety across P03 → P04 boundary**: The checklist acknowledges at §Task 5 "P04 will override this behavior once the trampoline is live at `target_fn`". But the P03 artifact leaves a loaded footgun in a form P04 cannot detect without reading the doc comment. Typestate-based APIs (Finding #2) would make the hand-off enforceable.
- **No stress/soak posture**: The phase ships one `#[ignore]`-gated integration test that loads a cdylib exactly once. There is no test that exercises repeated install/drop cycles to catch the RWX page leak class from Finding #3, and no coverage for the GNU_HASH non-PoT edge from Finding #5. Both are in scope for "hand-rolled parser" and neither is on the test plan.
- **No defense against the APEX-swap window**: The spec §Approach item 3 calls out `/proc/<pid>/map_files/<start>-<end>` as defending against TOCTOU on disk. But it does NOT defend against the tracee's OWN address space shifting between stage-A and stage-B (Finding #1). This is the architectural defect.
- **Observability**: Drop silently swallows errors (hook.rs:320). `install_init_hook` emits no `eprintln!` warnings on any cold-path failure. Operator debugging of a Tier B install fail is limited to whatever string survives inside `HookInstallFailed`. REGISTRY §2 "no log crate" is a constraint but nothing forbids an `eprintln!` on pathological Drop failures, matching RemoteAttach's own pattern (arena.rs:223).
- **Test coverage of the bionic chain-walk end-to-end**: The `gnu_lookup_absent_returns_none` test at elf.rs:719 exercises only the bloom-rejects path. There is NO unit test that builds a fake `.dynsym + .dynstr + .gnu.hash` triple with a symbol that SHOULD be found, verifying the chain-walk's `((c ^ h) >> 1) == 0` match + terminator + name compare against bionic's exact semantics. The integration test handles this end-to-end, but unit tests should isolate the chain-walk invariants because they are the most fragile part of the algorithm.

---

### Multi-perspective notes

- **Skeptic angle**: The spec claims "bionic-exact" GNU_HASH semantics but the implementation diverges on the power-of-two bloom_size rejection (Finding #5). "Exact" has to mean "every input bionic rejects, we also reject, and every input bionic accepts, we accept identically." Weaker than claimed.
- **Executor (P04 developer) angle**: Reading `HookHandle`'s Drop comment at hook.rs:313-316, the P04 developer has to remember a doc-only invariant to avoid bricking init. Human memory is not a safety mechanism. The type should enforce.
- **Stakeholder angle**: The binary-size target of ≤400 KB is unaffected (elf.rs adds ~20 KB of code, hook.rs ~10 KB, both fit in the opt-level=s, LTO envelope). The scope commitment is met. But the architectural invariants the stakeholder values ("seal shall not crash init under any input") are under-defended by the current Drop + leak-on-error design.

---

### Verdict Justification

**Realist Check applied to all findings.**

Finding #1 (TOCTOU across stage-A/stage-B): worst case is `target_fn` points into a region init no longer has mapped at its old VA → `read_remote` returns EFAULT → stage-B surfaces `HookInstallFailed`; no init crash, no data loss, clean failure. Downgraded probability but severity remains CRITICAL because the implicit assumption "libc doesn't move between stage-A and stage-B" is load-bearing and undocumented, and because P04 will bake trampoline writes on top of a `target_fn` computed during this unprotected window. **Mitigated by**: the current code path happens to surface as a clean error in most cases. Kept at CRITICAL because it's an architectural flaw that blocks P04 correctness, not a runtime crash vector in P03 itself. If the audit decides P04 will perform its own re-validation of `target_fn` at trampoline-install time, this can be downgraded to MAJOR.

Finding #2 (Drop typestate): worst case on P04 integration is init reboot. Kept at MAJOR (not CRITICAL) because P04 must still write the typestate — so this is a "must-fix before P04" not "must-fix in P03". **Mitigated by**: P04 has not yet been written, so the hazard is latent, not active.

Finding #3 (RWX leak on partial-stage-B failure): realistic rate is <1% of installs in practice; 4 KiB per leak. Kept at MAJOR because RWX pages compound and auditable presence matters.

Finding #4 (resolve_symbol fallthrough): misses are rare today but propdetect integration (REGISTRY §1, row 38) will make them common. Kept at MAJOR for forward-compat.

Finding #5 (non-PoT bloom_size): extremely rare input; kept at MAJOR because it is a silent-wrong-answer class, which always outranks a silent-crash class.

Finding #6 (scratch PC re-derivation): observability issue, double cost. Kept at MAJOR because it is the mechanism through which Finding #1's TOCTOU would actually fire in Drop.

**Escalation trigger**: 1 CRITICAL + 5 MAJOR surfaced during Phases 2-4 → escalated to ADVERSARIAL mode for the remainder of the review. Adjacent modules (arena.rs, ptrace.rs surface) were checked for analogous hazards; the P02 round-2 fix pattern (`910ce69`) already covers arena.rs's equivalent error-path leaks, and the `remote_syscall_via_poke` save/restore guards at ptrace.rs:669-705 are sufficient for ptrace-level invariants. No new findings in adjacent modules.

**What would need to change for an upgrade**:
- CRITICAL (#1): Reorder `install_init_hook` so `RemoteAttach` wraps the ENTIRE pipeline. Move `parse_maps`, `File::open("/proc/<pid>/map_files/...")`, `parse_libc_elf`, and `resolve_symbol` inside the attach window. This is a ~15-line restructure in hook.rs.
- MAJOR (#2): Introduce typestate for HookHandle's Drop, OR add explicit `uninstall(self) -> Result<()>`, OR at minimum add an `installed: bool` flag + Drop guard.
- MAJOR (#3): Wrap post-mmap error sites in best-effort munmap (pattern shown above).
- MAJOR (#4): Narrow `resolve_symbol` fallthrough semantics to match §Approach item 2 exactly.
- MAJOR (#5): Add `bloom_size.is_power_of_two()` check before using `bloom_size - 1` as mask.
- MAJOR (#6): Cache scratch_pc + libc range in HookHandle, re-validate in Drop.

With these six changes, VERDICT would move from NEEDS_FIX → PASS. Minor findings (#7, #8) are log-only.

### Open Questions (unscored)

- Is `PtraceEvent::PTRACE_EVENT_STOP` the correct wait event inside a fresh `RemoteAttach` when init has threads actively syscall-stopping? P02 integration passed on device, so presumably yes, but the interaction with the wider wait_stop spurious-stops class (deferred as §8 MAJOR-5 from P02) is unclaimed for P03/P04.
- Should `LibcElfView::bytes` clear its owned `Vec<u8>` after all offsets are resolved? Holding ~1 MB of libc bytes for the lifetime of the `HookHandle` is fine but could be trimmed to just the SYMTAB + STRTAB + GNU_HASH sections. Minor optimization, not a P03 defect.
- The integration test at `elf_fixture_smoke.rs` uses `env!("CARGO_MANIFEST_DIR") + "/../../target/release/libelf_fixture.so"` — on a workspace with a non-default `target-dir` (e.g. `CARGO_TARGET_DIR=/tmp/build`), this path is wrong. Not a spec violation; just an ergonomic gap.

---

**VERDICT: NEEDS_FIX** (1 CRITICAL + 5 MAJOR)
