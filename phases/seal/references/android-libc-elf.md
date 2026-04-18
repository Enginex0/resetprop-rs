# Android libc.so ELF Parsing Reference (Rust)

Target: find `__system_property_update` in init's already-mapped libc.so from a ptrace-attached helper, without any external ELF crate.

All claims cite either `/usr/include/elf.h` (glibc ELF spec mirror), `/home/president/aosp-android15/bionic/` (AOSP Android 15), or the generic ELF gABI where indicated. Values marked `// VERIFY` were not located in consulted sources.

---

## 1. Where libc.so lives on Android 10–15

Since Android 10, Bionic (libc, libdl, libm, linker) ships inside the **Runtime APEX** `com.android.runtime`. Source: `/home/president/aosp-android15/bionic/apex/Android.bp` lines 32–43 declare:

```
apex { name: "com.android.runtime", ...
       native_shared_libs: [ "libc", "libm", "libdl", "libdl_android", ... ] }
```

and `/home/president/aosp-android15/bionic/apex/manifest.json` sets the mount name to `com.android.runtime`. The APEX is mounted at `/apex/com.android.runtime/`, with shared libs under `lib64/bionic/` (arm64) or `lib/bionic/` (arm32).

**On-device install paths**

| Arch | Runtime APEX (normal runtime) | Bootstrap (early boot fallback) |
|------|-------------------------------|---------------------------------|
| arm64 | `/apex/com.android.runtime/lib64/bionic/libc.so` | `/system/lib64/bootstrap/libc.so` |
| arm32 | `/apex/com.android.runtime/lib/bionic/libc.so`   | `/system/lib/bootstrap/libc.so`   |

Bootstrap bionic exists because `/apex` is not mounted until after init has already started. Init's entry point is linked against `/system/bin/bootstrap/linker64`, which uses the bootstrap bionic dir. Source: `/home/president/aosp-android15/bionic/linker/linker_main.cpp` line 385 comments:

> the bootstrap linker (/system/bin/bootstrap/linker[64])

and `/home/president/aosp-android15/bionic/linker/linker.cpp` line 2454:

> For the bootstrap linker, insert /system/${LIB}/bootstrap in front of /system/${LIB}

**Which libc does init have mapped post-boot?**

Init `execve`s itself (`init second_stage`) after the APEX is mounted (`/home/president/aosp-android15/system/core/init/main.cpp` — second-stage re-exec), which re-links against the APEX linker and APEX libc. By the time a debugger process can ptrace-attach PID 1 (well after boot), init's libc row in `/proc/1/maps` is the APEX path. Bootstrap libc remains on disk but is not mapped into init.

**/proc/1/maps row example (arm64)**

```
7fa1234000-7fa1330000 r-xp 00000000 fe:00 5821  /apex/com.android.runtime/lib64/bionic/libc.so
7fa1330000-7fa1340000 r--p 000fc000 fe:00 5821  /apex/com.android.runtime/lib64/bionic/libc.so
7fa1340000-7fa1350000 rw-p 0010c000 fe:00 5821  /apex/com.android.runtime/lib64/bionic/libc.so
```

The first `r-xp` row with offset 0 pins `libc_base`. Take the `<start>-<end>` of any row and open:

```
/proc/1/map_files/<start>-<end>
```

which is a symlink the kernel resolves to the exact inode init has mapped, bypassing any APEX/`overlayfs` TOCTOU. Source: `proc(5)` man page — `/proc/<pid>/map_files/` was added in Linux 3.3.

---

## 2. ELF64 structures (Rust)

Layouts copied from `/usr/include/elf.h` lines 81–97 (Ehdr), 697–707 (Phdr), 878–886 (Dyn), 530–538 (Sym). All little-endian on arm64 (`ELFDATA2LSB`).

```rust
#[repr(C)]
pub struct Elf64_Ehdr {
    pub e_ident:     [u8; 16], // 0x00  16  magic + class + data + version + pad
    pub e_type:      u16,      // 0x10   2  ET_DYN for shared libs
    pub e_machine:   u16,      // 0x12   2  EM_AARCH64 = 183
    pub e_version:   u32,      // 0x14   4  EV_CURRENT = 1
    pub e_entry:     u64,      // 0x18   8  entry point (unused for libs)
    pub e_phoff:     u64,      // 0x20   8  program header table file offset
    pub e_shoff:     u64,      // 0x28   8  section header table (may be absent)
    pub e_flags:     u32,      // 0x30   4
    pub e_ehsize:    u16,      // 0x34   2  = 64
    pub e_phentsize: u16,      // 0x36   2  = 56 on ELF64
    pub e_phnum:     u16,      // 0x38   2  program header count
    pub e_shentsize: u16,      // 0x3a   2  = 64 on ELF64
    pub e_shnum:     u16,      // 0x3c   2
    pub e_shstrndx:  u16,      // 0x3e   2
}                               // total 64 bytes

#[repr(C)]
pub struct Elf64_Phdr {
    pub p_type:   u32, // 0x00  4  PT_LOAD / PT_DYNAMIC / ...
    pub p_flags:  u32, // 0x04  4  PF_R | PF_W | PF_X
    pub p_offset: u64, // 0x08  8  file offset
    pub p_vaddr:  u64, // 0x10  8  virtual address in linking view
    pub p_paddr:  u64, // 0x18  8  physical (unused on Android)
    pub p_filesz: u64, // 0x20  8  bytes in file
    pub p_memsz:  u64, // 0x28  8  bytes in memory (>= p_filesz)
    pub p_align:  u64, // 0x30  8
}                       // total 56 bytes

#[repr(C)]
pub struct Elf64_Dyn {
    pub d_tag: i64, // 0x00  8  DT_*
    pub d_val: u64, // 0x08  8  interpreted as value or pointer per DT
}                    // total 16 bytes

#[repr(C)]
pub struct Elf64_Sym {
    pub st_name:  u32, // 0x00  4  offset into strtab
    pub st_info:  u8,  // 0x04  1  bind<<4 | type
    pub st_other: u8,  // 0x05  1  visibility
    pub st_shndx: u16, // 0x06  2  section index or SHN_UNDEF
    pub st_value: u64, // 0x08  8  virtual address offset from load base
    pub st_size:  u64, // 0x10  8
}                       // total 24 bytes
```

Note the ELF64 `Sym` layout differs from ELF32: on ELF64 `st_info/st_other/st_shndx` come before `st_value` for alignment. Verified from `elf.h` lines 530–538.

---

## 3. Constants (Rust)

All values verified from `/usr/include/elf.h`. Section numbers next to each.

```rust
// e_ident indices (lines 103–154)
pub const EI_MAG0:   usize = 0;      // 0x7f
pub const EI_MAG1:   usize = 1;      // b'E'
pub const EI_MAG2:   usize = 2;      // b'L'
pub const EI_MAG3:   usize = 3;      // b'F'
pub const EI_CLASS:  usize = 4;
pub const EI_DATA:   usize = 5;
pub const EI_VERSION: usize = 6;

pub const ELFMAG:       [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64:   u8 = 2;      // line 122
pub const ELFDATA2LSB:  u8 = 1;      // line 127
pub const EV_CURRENT:   u8 = 1;

// e_type (lines 160–161)
pub const ET_EXEC: u16 = 2;
pub const ET_DYN:  u16 = 3;

// e_machine (line 317)
pub const EM_AARCH64: u16 = 183;

// p_type (lines 717–731)
pub const PT_NULL:         u32 = 0;
pub const PT_LOAD:         u32 = 1;
pub const PT_DYNAMIC:      u32 = 2;
pub const PT_INTERP:       u32 = 3;
pub const PT_NOTE:         u32 = 4;
pub const PT_PHDR:         u32 = 6;
pub const PT_TLS:          u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK:    u32 = 0x6474_e551;
pub const PT_GNU_RELRO:    u32 = 0x6474_e552;

// p_flags
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// d_tag (lines 890–961). `Elf64_Dyn.d_tag` is Elf64_Sxword (signed 64),
// so use i64 literals. 0x6ffffef5 is positive in i64.
pub const DT_NULL:     i64 = 0;
pub const DT_NEEDED:   i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT:   i64 = 3;
pub const DT_HASH:     i64 = 4;
pub const DT_STRTAB:   i64 = 5;
pub const DT_SYMTAB:   i64 = 6;
pub const DT_RELA:     i64 = 7;
pub const DT_RELASZ:   i64 = 8;
pub const DT_RELAENT:  i64 = 9;
pub const DT_STRSZ:    i64 = 10;
pub const DT_SYMENT:   i64 = 11;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;

// st_info helpers (lines 579–581, 585–599)
#[inline] pub fn elf64_st_type(info: u8) -> u8 { info & 0xf }
#[inline] pub fn elf64_st_bind(info: u8) -> u8 { info >> 4 }

pub const STB_LOCAL:  u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK:   u8 = 2;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC:   u8 = 2;

// Section indices (line 413)
pub const SHN_UNDEF: u16 = 0;
```

Signed-vs-unsigned note: `Elf64_Dyn.d_tag` is `Elf64_Sxword` (signed). GNU-reserved tags like `DT_GNU_HASH = 0x6ffffef5` sign-extend. Compare as `u64` or match the tag read as `i64` against the value `0x6ffffef5_i64` (positive in `i64`).

---

## 4. Symbol resolution — step-by-step

Inputs the caller already has:

- `libc_base: u64` from `/proc/1/maps` (the `start` of the `r-xp` row with file offset 0).
- `fd` open on `/proc/1/map_files/<start>-<end>` (read-only, same inode init has mapped).

### 4.1 Read Ehdr at offset 0

```rust
let mut ehdr = [0u8; 64];
pread_exact(fd, &mut ehdr, 0)?;
let e: &Elf64_Ehdr = unsafe { &*(ehdr.as_ptr() as *const Elf64_Ehdr) };

assert_eq!(&e.e_ident[..4], &ELFMAG);
assert_eq!(e.e_ident[EI_CLASS], ELFCLASS64);
assert_eq!(e.e_ident[EI_DATA],  ELFDATA2LSB);
assert_eq!(e.e_machine, EM_AARCH64);
assert_eq!(e.e_type,    ET_DYN);
assert_eq!(e.e_phentsize as usize, 56);
```

### 4.2 Read the program header table

```rust
let mut phdrs = vec![0u8; 56 * e.e_phnum as usize];
pread_exact(fd, &mut phdrs, e.e_phoff)?;
```

Iterate `e.e_phnum` records, each 56 bytes, casting each to `&Elf64_Phdr`.

### 4.3 Build PT_LOAD map and locate PT_DYNAMIC

Collect tuples `(p_vaddr, p_offset, p_filesz)` for every `PT_LOAD` — this is the *linking view* used to translate a virtual address (what `DT_SYMTAB`, `DT_STRTAB`, `DT_GNU_HASH` point to) to a file offset:

```rust
fn vaddr_to_foff(loads: &[(u64, u64, u64)], vaddr: u64) -> Option<u64> {
    for &(va, off, sz) in loads {
        if vaddr >= va && vaddr < va + sz {
            return Some(off + (vaddr - va));
        }
    }
    None
}
```

Find the single `PT_DYNAMIC` entry; remember its `p_offset` and `p_filesz / 16` (entry count).

### 4.4 Walk Dyn entries until DT_NULL

```rust
let mut symtab_va: u64 = 0;
let mut strtab_va: u64 = 0;
let mut strtab_sz: u64 = 0;
let mut syment:    u64 = 0;
let mut gnu_hash_va: u64 = 0;

// read dyn section of size p_filesz
for dyn_ent in dyns {
    match dyn_ent.d_tag {
        6  /* DT_SYMTAB */   => symtab_va    = dyn_ent.d_val,
        5  /* DT_STRTAB */   => strtab_va    = dyn_ent.d_val,
        10 /* DT_STRSZ  */   => strtab_sz    = dyn_ent.d_val,
        11 /* DT_SYMENT */   => syment       = dyn_ent.d_val, // = 24
        t if t == DT_GNU_HASH => gnu_hash_va = dyn_ent.d_val,
        0  /* DT_NULL */     => break,
        _ => {}
    }
}
assert_eq!(syment, 24);
```

### 4.5 Translate virtual addresses to file offsets

```rust
let symtab_off = vaddr_to_foff(&loads, symtab_va).unwrap();
let strtab_off = vaddr_to_foff(&loads, strtab_va).unwrap();
let gnu_off    = if gnu_hash_va != 0 { vaddr_to_foff(&loads, gnu_hash_va) } else { None };
```

### 4.6 Choose the lookup path

- If `gnu_off.is_some()` → GNU_HASH (Section 5).
- Else → linear scan (Section 6).

---

## 5. GNU_HASH lookup algorithm

### 5.1 On-disk layout

```text
offset  size   field
  0      4     nbuckets     (u32)
  4      4     symoffset    (u32)  // first symbol index covered by the hash
  8      4     bloom_size   (u32)  // in 64-bit words; MUST be power of two
 12      4     bloom_shift  (u32)
 16      8*N   bloom[bloom_size]   (u64 each)
 16+8*N  4*B   buckets[nbuckets]   (u32 each, B = nbuckets)
 ...    ...   chain[...]           (u32 each, indexed by symtab index)
```

Source: `/home/president/aosp-android15/bionic/linker/linker.cpp` lines 2901–2910 reads the four u32 header words then treats the next bytes at `+16` as the bloom filter of `gnu_maskwords_` u64s, followed by `gnu_nbucket_` u32 buckets, followed by the chain. Bionic stores `gnu_maskwords_ = bloom_size - 1` internally as a bitmask (line 2917: `--gnu_maskwords_`). For your reader, keep `bloom_size` as-is and derive the mask on use.

### 5.2 Hash function (bionic ground truth)

`/home/president/aosp-android15/bionic/linker/linker_gnu_hash.h` lines 46–54:

```rust
pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        // h*33 + b ≡ h + (h << 5) + b  (bionic form)
        h = h.wrapping_add(h.wrapping_shl(5)).wrapping_add(b as u32);
    }
    h
}
```

The `.wrapping_mul(33).wrapping_add(b)` form produces the same u32.

### 5.3 Lookup (bionic ground truth)

From `linker_soinfo.cpp` lines 327–377. Rewritten for reading the raw on-disk tables rather than pointer-dereferencing pre-parsed fields:

```rust
pub fn gnu_lookup(
    name: &[u8],
    nbuckets: u32,
    symoffset: u32,
    bloom_size: u32,
    bloom_shift: u32,
    bloom: &[u64],      // bloom_size entries
    buckets: &[u32],    // nbuckets entries
    chain: &[u32],      // chain, indexed by symtab_index - symoffset
    symtab: &[Elf64_Sym],
    strtab: &[u8],
    target: &[u8],
) -> Option<u32> {
    let h = gnu_hash(name);

    // Step 1: bloom filter test
    let bits = 64u32; // ElfW(Addr) on arm64
    let word = bloom[((h / bits) & (bloom_size - 1)) as usize];
    let m1 = 1u64 << (h % bits);
    let m2 = 1u64 << ((h >> bloom_shift) % bits);
    if (word & m1) == 0 || (word & m2) == 0 { return None; }

    // Step 2: bucket
    let mut n = buckets[(h % nbuckets) as usize];
    if n == 0 { return None; }

    // Step 3: walk the chain. Bionic compares ((chain[n] ^ h) >> 1) == 0,
    // which is the "ignore low bit" compare. Low bit set = end of chain.
    loop {
        let idx = (n - symoffset) as usize;
        let c = chain[idx];
        if ((c ^ h) >> 1) == 0 {
            let sym = &symtab[n as usize];
            let name_off = sym.st_name as usize;
            let end = strtab[name_off..].iter().position(|&b| b == 0)?;
            if &strtab[name_off..name_off + end] == target {
                return Some(n);
            }
        }
        if (c & 1) != 0 { break; } // terminator
        n += 1;
    }
    None
}
```

For `__system_property_update` the `target` slice is exactly those 25 bytes (no trailing NUL). Citations: bionic chain-walk logic lines 360–371 (`((gnu_chain_[n] ^ hash) >> 1) == 0`, terminate when `chain[n] & 1 != 0`).

---

## 6. Linear-scan fallback

When `DT_GNU_HASH` is absent or you don't want to parse the hash table:

- `symtab_count = (strtab_off - symtab_off) / 24` is a reliable upper bound when strtab directly follows symtab (common libc layout). A safer source is `DT_HASH`'s `nchain` if present, or counting forward until the first zero `st_name`.
- For each index `i` in `[0, count)`, read a 24-byte `Elf64_Sym`, read the NUL-terminated name at `strtab_off + sym.st_name`, `memcmp` against `"__system_property_update"`.

libc has on the order of 2000–3000 exported symbols; a linear scan is a few microseconds. Acceptable for a one-shot startup lookup.

---

## 7. Computing the runtime address

```rust
// sym was found in the on-disk table
if sym.st_shndx == SHN_UNDEF { bail!("undefined — not our libc"); }
if elf64_st_type(sym.st_info) != STT_FUNC { bail!("not a function"); }

let fn_addr: u64 = libc_base + sym.st_value;
```

libc.so is position-independent `ET_DYN`. On Android arm64 its first `PT_LOAD` uses `p_vaddr = 0`, so `load_bias = libc_base` and `fn_addr = libc_base + st_value`. For defensive builds where the first PT_LOAD vaddr is non-zero, use `load_bias = libc_base - min_pt_load_vaddr`.

---

## 8. Edge cases

- **Stripped libc** — release libc.so drops `.symtab` but keeps `.dynsym` (the dynamic linker needs it). `__system_property_update` is a public export from `bionic/libc/include/sys/system_properties.h`, so it is always in `.dynsym` and covered by `DT_GNU_HASH`.
- **`--pack-dyn-relocs`** — Android's `lld` packs relative relocations (DT_ANDROID_REL / DT_RELR). This does not touch `.dynsym`, `.dynstr`, or `.gnu.hash`; symbol lookup is unaffected.
- **TEXTREL** — arm64 libc.so has no text relocations (bionic rejects `DT_TEXTREL`), so `libc_base + st_value` is the exact runtime address without relocation fixup.
- **libc_hwasan** — HWASan userdebug builds also ship `lib64/bionic/libc_hwasan.so` in the APEX. Normal builds never map it; read the exact filename from `/proc/1/maps`, don't hard-code.

---

## Source index (every claim)

| Claim | File / line |
|-------|-------------|
| APEX name `com.android.runtime` contains libc/libm/libdl/linker | `aosp-android15/bionic/apex/Android.bp:32-43` |
| APEX mount manifest | `aosp-android15/bionic/apex/manifest.json:1-4` |
| Bootstrap linker path `/system/bin/bootstrap/linker[64]` | `aosp-android15/bionic/linker/linker_main.cpp:385` |
| Bootstrap lib dir prefix logic | `aosp-android15/bionic/linker/linker.cpp:2454-2455` |
| `Elf64_Ehdr` layout | `/usr/include/elf.h:81-97` |
| `Elf64_Phdr` layout (p_type first, then p_flags) | `/usr/include/elf.h:697-707` |
| `Elf64_Dyn` layout | `/usr/include/elf.h:878-886` |
| `Elf64_Sym` layout | `/usr/include/elf.h:530-538` |
| `EI_*`, `ELFCLASS64`, `ELFDATA2LSB`, `EV_CURRENT` | `/usr/include/elf.h:103-131` |
| `ET_DYN = 3` | `/usr/include/elf.h:161` |
| `EM_AARCH64 = 183` | `/usr/include/elf.h:317` |
| `PT_*` constants | `/usr/include/elf.h:717-731` |
| `DT_*` constants including `DT_GNU_HASH = 0x6ffffef5` | `/usr/include/elf.h:890-961` |
| `STT_FUNC = 2`, `STB_GLOBAL = 1` | `/usr/include/elf.h:585-599` |
| `ELF64_ST_TYPE / BIND` = ELF32 variants | `/usr/include/elf.h:579-581` |
| `SHN_UNDEF = 0` | `/usr/include/elf.h:413` |
| GNU_HASH header layout (4 u32s then bloom then buckets then chain) | `aosp-android15/bionic/linker/linker.cpp:2901-2910` |
| GNU_HASH bloom-mask bits = pointer size | `aosp-android15/bionic/linker/linker_soinfo.cpp:330` (`kBloomMaskBits = sizeof(ElfW(Addr)) * 8`) |
| GNU hash function `h = h*33 + c`, seed 5381 | `aosp-android15/bionic/linker/linker_gnu_hash.h:46-54` |
| Chain compare `((chain[n] ^ h) >> 1) == 0`, terminator `chain[n] & 1` | `aosp-android15/bionic/linker/linker_soinfo.cpp:362, 371` |
| `/proc/<pid>/map_files/` resolves to open fd on exact mapped inode | `proc(5)` man page (Linux 3.3+) |
