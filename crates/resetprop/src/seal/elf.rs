//! Hand-rolled ELF64 walker for Android arm64 `libc.so`.
//!
//! P03 Task 1 scope: own the `#[repr(C)]` layouts, the validation constants, and
//! `parse_libc_elf` — which `read_to_end`s the target file, validates the
//! Ehdr, walks program headers to collect `PT_LOAD` tuples and locate
//! `PT_DYNAMIC`, then walks dynamic entries to record `symtab_offset`,
//! `strtab_offset`, `strtab_size`, and `gnu_hash_offset` (all translated to
//! file offsets via the PT_LOAD map).
//!
//! T2 adds `gnu_hash` + `gnu_lookup` (below): GNU_HASH djb2a form + on-disk
//! bloom/bucket/chain walk matching bionic `linker_soinfo.cpp::gnu_lookup`.
//! T3 (`linear_lookup` / `resolve_symbol`) lands in the next dispatcher and
//! will index into `LibcElfView::bytes` via the `pub(crate)` accessors below.
//!
//! Layouts and constants verified against `/usr/include/elf.h` — citations are
//! inlined at each declaration. No external ELF crate is used per REGISTRY §1
//! single-dep policy.

use std::fs::File;
use std::io::Read;
use std::mem;
use std::ptr;

use crate::error::{Error, Result};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// ELF magic — first four bytes of `e_ident`. `/usr/include/elf.h:103-107`.
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// `e_ident[EI_CLASS]` value for 64-bit objects. `/usr/include/elf.h:122`.
pub const ELFCLASS64: u8 = 2;

/// `e_ident[EI_DATA]` value for little-endian (2's complement). `/usr/include/elf.h:127`.
pub const ELFDATA2LSB: u8 = 1;

/// `e_type` value for shared object files. `/usr/include/elf.h:161`.
pub const ET_DYN: u16 = 3;

/// `e_machine` value for ARM AArch64. `/usr/include/elf.h:317`.
pub const EM_AARCH64: u16 = 183;

/// `p_type` value for loadable segments. `/usr/include/elf.h:717-731`.
pub const PT_LOAD: u32 = 1;

/// `p_type` value for the dynamic segment. `/usr/include/elf.h:717-731`.
pub const PT_DYNAMIC: u32 = 2;

/// `d_tag` end-of-dynamic-section marker. `/usr/include/elf.h:890-961`.
pub const DT_NULL: i64 = 0;

/// `d_tag` for the SysV hash table. `/usr/include/elf.h:890-961`.
pub const DT_HASH: i64 = 4;

/// `d_tag` for the string table virtual address. `/usr/include/elf.h:890-961`.
pub const DT_STRTAB: i64 = 5;

/// `d_tag` for the symbol table virtual address. `/usr/include/elf.h:890-961`.
pub const DT_SYMTAB: i64 = 6;

/// `d_tag` for the string table size in bytes. `/usr/include/elf.h:890-961`.
pub const DT_STRSZ: i64 = 10;

/// `d_tag` for `Elf64_Sym` entry size. `/usr/include/elf.h:890-961`.
pub const DT_SYMENT: i64 = 11;

/// `d_tag` for the GNU-style hash table virtual address. `/usr/include/elf.h:890-961`.
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;

/// `st_info` type field for function symbols. `/usr/include/elf.h:599`.
pub const STT_FUNC: u8 = 2;

/// `st_info` bind field for global symbols. `/usr/include/elf.h:586`.
pub const STB_GLOBAL: u8 = 1;

/// Reserved section index meaning "undefined". `/usr/include/elf.h:413`.
pub const SHN_UNDEF: u16 = 0;

// -----------------------------------------------------------------------------
// ELF64 structs (exact layouts per /usr/include/elf.h)
// -----------------------------------------------------------------------------

/// ELF64 file header. Layout: `/usr/include/elf.h:81-97`. Total: 64 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}
const _: () = assert!(mem::size_of::<Elf64_Ehdr>() == 64);

/// ELF64 program header. Layout: `/usr/include/elf.h:697-707`. Total: 56 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64_Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}
const _: () = assert!(mem::size_of::<Elf64_Phdr>() == 56);

/// ELF64 dynamic section entry. Layout: `/usr/include/elf.h:878-886`. Total: 16 bytes.
///
/// `d_tag` is signed per the ELF spec; the `d_val` union in `elf.h` is
/// collapsed to a single `u64` here because we only read it as an integer or
/// an address (both unsigned interpretations).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64_Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}
const _: () = assert!(mem::size_of::<Elf64_Dyn>() == 16);

/// ELF64 symbol table entry. Layout: `/usr/include/elf.h:530-538`. Total: 24 bytes.
///
/// Note: ELF64 reorders `st_info`/`st_other`/`st_shndx` before `st_value`
/// relative to ELF32 for natural alignment.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}
const _: () = assert!(mem::size_of::<Elf64_Sym>() == 24);

// -----------------------------------------------------------------------------
// LibcElfView — owned file bytes + resolved dynamic table offsets
// -----------------------------------------------------------------------------

/// Parsed view of an Android arm64 `libc.so`.
///
/// Owns the full file contents so `gnu_lookup` (T2) and the upcoming
/// `linear_lookup` (T3) can index into the buffer without mmap/lifetime
/// juggling. libc.so is ~1 MB, so holding the full buffer is cheap and
/// avoids unsafe. `syment` and `strtab_size` are read by T3's linear path;
/// the T2 lookup uses `symtab_offset`, `strtab_offset`, `strtab_size`, and
/// `gnu_hash_offset`.
#[allow(dead_code)]
#[derive(Debug)]
pub struct LibcElfView {
    /// The entire ELF file contents.
    pub(crate) bytes: Vec<u8>,
    /// File offset of the first `Elf64_Sym`. From `DT_SYMTAB` via `vaddr_to_foff`.
    pub(crate) symtab_offset: usize,
    /// File offset of the string table. From `DT_STRTAB` via `vaddr_to_foff`.
    pub(crate) strtab_offset: usize,
    /// String table size in bytes. From `DT_STRSZ`; `0` when the tag is absent.
    pub(crate) strtab_size: usize,
    /// File offset of the GNU_HASH table, if `DT_GNU_HASH` is present.
    pub(crate) gnu_hash_offset: Option<usize>,
    /// `DT_SYMENT` value — must equal `sizeof(Elf64_Sym) == 24`. Cached for T2/T3.
    pub(crate) syment: usize,
}

// -----------------------------------------------------------------------------
// vaddr → file offset translation
// -----------------------------------------------------------------------------

/// Translate a linking-view virtual address to a file offset using the PT_LOAD
/// map. Returns `None` if `vaddr` falls outside every PT_LOAD range.
///
/// Tuple shape: `(p_vaddr, p_offset, p_filesz)`.
fn vaddr_to_foff(pt_loads: &[(u64, u64, u64)], vaddr: u64) -> Option<usize> {
    for &(va, off, sz) in pt_loads {
        if vaddr >= va && vaddr < va + sz {
            return Some((vaddr - va + off) as usize);
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Unaligned struct read helper
// -----------------------------------------------------------------------------

/// Read a `#[repr(C)]` POD struct of size `N` from `bytes[off..off+N]` without
/// alignment requirements. Returns `Error::ElfParse` on bounds overflow.
///
/// # Safety contract
/// Caller must guarantee `T` is `#[repr(C)]`, has no padding-based invariants,
/// and that the source bytes are a valid bit pattern. All ELF64 POD types used
/// here (`Elf64_Ehdr`, `Elf64_Phdr`, `Elf64_Dyn`, `Elf64_Sym`) satisfy this.
fn read_struct<T: Copy>(bytes: &[u8], off: usize, what: &str) -> Result<T> {
    let size = mem::size_of::<T>();
    let end = off.checked_add(size).ok_or_else(|| {
        Error::ElfParse(format!("offset overflow reading {what}"))
    })?;
    if end > bytes.len() {
        return Err(Error::ElfParse(format!(
            "truncated {what} at offset {off} (need {size}, have {})",
            bytes.len().saturating_sub(off),
        )));
    }
    // SAFETY: bounds checked above; T is #[repr(C)] POD per this module's
    // contract (only Elf64_Ehdr / Elf64_Phdr / Elf64_Dyn / Elf64_Sym invoke
    // this); read_unaligned tolerates any alignment; a fresh `T` is produced
    // by value so no lifetime escapes the byte slice.
    let ptr = unsafe { bytes.as_ptr().add(off) as *const T };
    Ok(unsafe { ptr::read_unaligned(ptr) })
}

// -----------------------------------------------------------------------------
// parse_libc_elf — public entry point for P03
// -----------------------------------------------------------------------------

/// Parse an Android arm64 `libc.so` from a `File` handle into a [`LibcElfView`].
///
/// Reads the entire file into an owned `Vec<u8>`, validates the Ehdr magic,
/// class, data encoding, machine, type, and program-header entry size, walks
/// the program header table, locates the single `PT_DYNAMIC` segment, walks
/// its `Elf64_Dyn` entries until `DT_NULL`, and resolves `DT_SYMTAB`,
/// `DT_STRTAB`, `DT_GNU_HASH` virtual addresses to file offsets via the
/// collected `PT_LOAD` map.
///
/// Validation order (deterministic for reproducible error output):
/// magic → class → data → machine → type → phentsize.
pub fn parse_libc_elf(file: &File) -> Result<LibcElfView> {
    // ---- Load full file ----
    let mut bytes = Vec::new();
    {
        // `read_to_end` requires &mut File; clone the handle to keep the caller's
        // &File ergonomic contract. `try_clone` dups the fd cheaply.
        let mut f = file.try_clone()?;
        f.read_to_end(&mut bytes)?;
    }

    // ---- Ehdr ----
    let ehdr: Elf64_Ehdr = read_struct(&bytes, 0, "Ehdr")?;

    // Validation order locked by spec: magic → class → data → machine → type → phentsize.
    if ehdr.e_ident[..4] != ELFMAG {
        return Err(Error::ElfParse("bad magic".into()));
    }
    if ehdr.e_ident[4] != ELFCLASS64 {
        return Err(Error::ElfParse("EI_CLASS != ELFCLASS64".into()));
    }
    if ehdr.e_ident[5] != ELFDATA2LSB {
        return Err(Error::ElfParse("EI_DATA != ELFDATA2LSB".into()));
    }
    if ehdr.e_machine != EM_AARCH64 {
        return Err(Error::ElfParse("e_machine != EM_AARCH64".into()));
    }
    if ehdr.e_type != ET_DYN {
        return Err(Error::ElfParse("e_type != ET_DYN".into()));
    }
    if (ehdr.e_phentsize as usize) != mem::size_of::<Elf64_Phdr>() {
        return Err(Error::ElfParse(
            "e_phentsize != sizeof(Elf64_Phdr)".into(),
        ));
    }

    // ---- Program headers ----
    let phoff = ehdr.e_phoff as usize;
    let phentsize = ehdr.e_phentsize as usize;
    let phnum = ehdr.e_phnum as usize;

    let mut pt_loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut pt_dynamic: Option<(u64, u64, u64)> = None; // (vaddr, offset, filesz)

    for i in 0..phnum {
        let off = phoff
            .checked_add(i.checked_mul(phentsize).ok_or_else(|| {
                Error::ElfParse("phdr index overflow".into())
            })?)
            .ok_or_else(|| Error::ElfParse("phdr offset overflow".into()))?;
        let phdr: Elf64_Phdr = read_struct(&bytes, off, "Phdr")?;

        match phdr.p_type {
            PT_LOAD => pt_loads.push((phdr.p_vaddr, phdr.p_offset, phdr.p_filesz)),
            PT_DYNAMIC => {
                if pt_dynamic.is_none() {
                    // Defensive: ELF spec permits only one PT_DYNAMIC; if more
                    // than one appears, keep the first and silently accept.
                    pt_dynamic = Some((phdr.p_vaddr, phdr.p_offset, phdr.p_filesz));
                }
            }
            _ => {}
        }
    }

    let (_dyn_vaddr, dyn_off, dyn_filesz) = pt_dynamic
        .ok_or_else(|| Error::ElfParse("PT_DYNAMIC absent".into()))?;

    // ---- Walk PT_DYNAMIC until DT_NULL or filesz exhausted ----
    let mut symtab_va: Option<u64> = None;
    let mut strtab_va: Option<u64> = None;
    let mut strtab_sz: u64 = 0;
    let mut syment: u64 = 0;
    let mut gnu_hash_va: Option<u64> = None;

    let dyn_off = dyn_off as usize;
    let dyn_filesz = dyn_filesz as usize;
    let dyn_entries = dyn_filesz / mem::size_of::<Elf64_Dyn>();

    for i in 0..dyn_entries {
        let off = dyn_off
            .checked_add(i.checked_mul(mem::size_of::<Elf64_Dyn>()).ok_or_else(|| {
                Error::ElfParse("dyn index overflow".into())
            })?)
            .ok_or_else(|| Error::ElfParse("dyn offset overflow".into()))?;
        let d: Elf64_Dyn = read_struct(&bytes, off, "Dyn")?;

        match d.d_tag {
            DT_NULL => break,
            DT_SYMTAB => symtab_va = Some(d.d_val),
            DT_STRTAB => strtab_va = Some(d.d_val),
            DT_STRSZ => strtab_sz = d.d_val,
            DT_SYMENT => syment = d.d_val,
            DT_GNU_HASH => gnu_hash_va = Some(d.d_val),
            _ => {}
        }
    }

    let symtab_va = symtab_va.ok_or_else(|| Error::ElfParse("DT_SYMTAB absent".into()))?;
    let strtab_va = strtab_va.ok_or_else(|| Error::ElfParse("DT_STRTAB absent".into()))?;

    let symtab_offset = vaddr_to_foff(&pt_loads, symtab_va)
        .ok_or_else(|| Error::ElfParse("DT_SYMTAB vaddr outside PT_LOAD map".into()))?;
    let strtab_offset = vaddr_to_foff(&pt_loads, strtab_va)
        .ok_or_else(|| Error::ElfParse("DT_STRTAB vaddr outside PT_LOAD map".into()))?;
    let gnu_hash_offset = match gnu_hash_va {
        Some(va) => Some(
            vaddr_to_foff(&pt_loads, va)
                .ok_or_else(|| Error::ElfParse("DT_GNU_HASH vaddr outside PT_LOAD map".into()))?,
        ),
        None => None,
    };

    // `DT_SYMENT` is optional in principle but always present on bionic; when
    // absent default to the canonical 24. T2/T3 assert this at use-site.
    let syment = if syment == 0 {
        mem::size_of::<Elf64_Sym>()
    } else {
        syment as usize
    };

    Ok(LibcElfView {
        bytes,
        symtab_offset,
        strtab_offset,
        strtab_size: strtab_sz as usize,
        gnu_hash_offset,
        syment,
    })
}

// -----------------------------------------------------------------------------
// GNU_HASH lookup (T2)
// -----------------------------------------------------------------------------

/// Width of a single bloom-filter word, in bits. Matches bionic's
/// `kBloomMaskBits = sizeof(ElfW(Addr)) * 8` for arm64.
/// Source: `linker_soinfo.cpp:330`.
const BLOOM_MASK_BITS: u32 = 64;

/// djb2a hash used by GNU_HASH, bionic form.
///
/// `h * 33 + byte`, seeded at `5381`, encoded as
/// `h + (h << 5) + byte` with wrapping u32 arithmetic.
/// Source: `linker_gnu_hash.h:46-54`.
pub(crate) fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        h = h.wrapping_add(h.wrapping_shl(5)).wrapping_add(u32::from(b));
    }
    h
}

/// Read a little-endian `u32` at `off`, returning `None` on OOB.
///
/// Used for GNU_HASH header fields and for bucket/chain entries. Safe —
/// no `unsafe`, no alignment requirement.
fn u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    if end > bytes.len() {
        return None;
    }
    let slice: [u8; 4] = bytes[off..end].try_into().ok()?;
    Some(u32::from_le_bytes(slice))
}

/// Read a little-endian `u64` at `off`, returning `None` on OOB.
///
/// Used for bloom-filter words.
fn u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    if end > bytes.len() {
        return None;
    }
    let slice: [u8; 8] = bytes[off..end].try_into().ok()?;
    Some(u64::from_le_bytes(slice))
}

/// Read a NUL-terminated C string starting at `offset`, bounded by both
/// `offset + max_len` and `bytes.len()`. Returns the byte slice excluding
/// the NUL, or `None` if no NUL exists within the bound.
///
/// Shared by T2 (here) and T3 (linear_lookup) for `strtab` name resolution.
fn read_cstr_at(bytes: &[u8], offset: usize, max_len: usize) -> Option<&[u8]> {
    let hard_end = bytes.len().min(offset.checked_add(max_len)?);
    if offset >= hard_end {
        return None;
    }
    let window = &bytes[offset..hard_end];
    let nul = window.iter().position(|&b| b == 0)?;
    Some(&window[..nul])
}

/// Look up `name` in the view's GNU_HASH table and return the matched
/// symbol's `st_value`, or `None` if absent / the view has no GNU_HASH /
/// the table is malformed.
///
/// Never panics. Never returns `Err`; the T3 dispatcher wraps `None` into
/// the crate's `SymbolNotFound` variant. Algorithm matches bionic
/// `linker_soinfo.cpp:327-377` verbatim:
///   1. djb2a hash with seed 5381.
///   2. Bloom double-check at bits `h % 64` and `(h >> bloom_shift) % 64`.
///   3. Bucket `h % nbuckets`; zero bucket means absent.
///   4. Chain walk comparing `((chain[n] ^ h) >> 1) == 0`, terminating on
///      `chain[n] & 1`.
pub fn gnu_lookup(view: &LibcElfView, name: &str) -> Option<u64> {
    let hash_offset = view.gnu_hash_offset?;
    let bytes = &view.bytes;
    let target = name.as_bytes();

    // Header: nbuckets, symoffset, bloom_size, bloom_shift (4 x u32 LE).
    let nbuckets = u32_le(bytes, hash_offset)?;
    let symoffset = u32_le(bytes, hash_offset.checked_add(4)?)?;
    let bloom_size = u32_le(bytes, hash_offset.checked_add(8)?)?;
    let bloom_shift = u32_le(bytes, hash_offset.checked_add(12)?)?;

    if nbuckets == 0 || bloom_size == 0 {
        return None;
    }

    let bloom_base = hash_offset.checked_add(16)?;
    let bucket_base = bloom_base.checked_add((bloom_size as usize).checked_mul(8)?)?;
    let chain_base = bucket_base.checked_add((nbuckets as usize).checked_mul(4)?)?;

    let h = gnu_hash(target);

    // Step 1: bloom filter double-check.
    let word_idx = ((h / BLOOM_MASK_BITS) & (bloom_size - 1)) as usize;
    let word_off = bloom_base.checked_add(word_idx.checked_mul(8)?)?;
    let word = u64_le(bytes, word_off)?;
    let m1 = 1u64 << (h % BLOOM_MASK_BITS);
    let m2 = 1u64 << ((h >> bloom_shift) % BLOOM_MASK_BITS);
    if (word & m1) == 0 || (word & m2) == 0 {
        return None;
    }

    // Step 2: bucket lookup. Bucket zero means "definitely absent".
    let bucket_off = bucket_base.checked_add(((h % nbuckets) as usize).checked_mul(4)?)?;
    let mut n = u32_le(bytes, bucket_off)?;
    if n == 0 {
        return None;
    }

    // Guard against malformed tables where the first bucket index is below
    // symoffset (the chain is indexed by `n - symoffset`).
    if n < symoffset {
        return None;
    }

    // Step 3: chain walk. `((c ^ h) >> 1) == 0` is the hash-match candidate;
    // `(c & 1) != 0` marks the end of the chain.
    loop {
        let chain_idx = (n - symoffset) as usize;
        let chain_off = chain_base.checked_add(chain_idx.checked_mul(4)?)?;
        let c = u32_le(bytes, chain_off)?;

        if ((c ^ h) >> 1) == 0 {
            let sym_off = view
                .symtab_offset
                .checked_add((n as usize).checked_mul(mem::size_of::<Elf64_Sym>())?)?;
            let sym: Elf64_Sym = read_struct(bytes, sym_off, "Sym").ok()?;
            let name_off = view.strtab_offset.checked_add(sym.st_name as usize)?;
            let cand = read_cstr_at(bytes, name_off, view.strtab_size)?;
            if cand == target {
                return Some(sym.st_value);
            }
        }

        if (c & 1) != 0 {
            return None;
        }
        n = n.checked_add(1)?;
    }
}

// -----------------------------------------------------------------------------
// Linear symbol-table fallback (T3)
// -----------------------------------------------------------------------------

/// Linear scan of `.dynsym` for `name`, returning the matched symbol's
/// `st_value` or `None` on miss / malformed bounds.
///
/// This is the defensive net behind the GNU_HASH fast path in
/// [`resolve_symbol`]: a libc with a missing, truncated, or otherwise
/// malformed GNU_HASH section still permits symbol resolution as long as
/// `.dynsym` and `.dynstr` parse.
///
/// Bounds policy:
/// * `entries = (strtab_offset - symtab_offset) / size_of::<Elf64_Sym>()`.
///   ELF toolchains emit `.dynstr` immediately after `.dynsym` in the
///   read-only segment, so this yields the symbol count without needing
///   `DT_HASH.nchain`. If `strtab_offset <= symtab_offset` (malformed),
///   return `None`.
/// * Per-entry `read_struct` failures (truncation) short-circuit to `None`.
/// * Entries with `st_shndx == SHN_UNDEF (0)` are skipped — these are
///   imports with no usable `st_value`.
/// * Name comparison is byte-exact against `name.as_bytes()`.
///
/// Never panics.
pub fn linear_lookup(view: &LibcElfView, name: &str) -> Option<u64> {
    let bytes = &view.bytes;
    let target = name.as_bytes();

    if view.strtab_offset <= view.symtab_offset {
        return None;
    }
    let entries =
        (view.strtab_offset - view.symtab_offset) / mem::size_of::<Elf64_Sym>();

    for i in 0..entries {
        let sym_off = view
            .symtab_offset
            .checked_add(i.checked_mul(mem::size_of::<Elf64_Sym>())?)?;
        let sym: Elf64_Sym = read_struct(bytes, sym_off, "Sym").ok()?;

        if sym.st_shndx == SHN_UNDEF {
            continue;
        }

        let name_off = view.strtab_offset.checked_add(sym.st_name as usize)?;
        let cand = match read_cstr_at(bytes, name_off, view.strtab_size) {
            Some(c) => c,
            None => continue,
        };

        if cand == target {
            return Some(sym.st_value);
        }
    }

    None
}

/// Resolve `name` against `view`, preferring GNU_HASH and falling through
/// to the linear `.dynsym` scan on miss.
///
/// Dispatcher order (locked by spec §Approach item 2):
/// 1. If `view.gnu_hash_offset.is_some()`, call [`gnu_lookup`]; return on hit.
/// 2. Otherwise (or on GNU_HASH miss), call [`linear_lookup`]; return on hit.
/// 3. Neither resolved → `Err(Error::SymbolNotFound)`.
///
/// We deliberately do NOT skip linear when GNU_HASH is present but returns
/// `None`: a malformed GNU_HASH section (bad bloom filter, truncated chain)
/// should still permit linear to recover, which is the invariant the T4
/// symbol-patching pipeline relies on.
pub fn resolve_symbol(view: &LibcElfView, name: &str) -> Result<u64> {
    if view.gnu_hash_offset.is_some() {
        if let Some(v) = gnu_lookup(view, name) {
            return Ok(v);
        }
    }
    if let Some(v) = linear_lookup(view, name) {
        return Ok(v);
    }
    Err(Error::SymbolNotFound(name.into()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
impl LibcElfView {
    /// Build a view directly from pre-resolved offsets, without parsing a
    /// real ELF file. Test-only; exists so T2's bloom-rejects path can be
    /// exercised with a hand-crafted GNU_HASH section.
    pub(crate) fn from_parts(
        bytes: Vec<u8>,
        symtab_offset: usize,
        strtab_offset: usize,
        strtab_size: usize,
        gnu_hash_offset: Option<usize>,
    ) -> Self {
        Self {
            bytes,
            symtab_offset,
            strtab_offset,
            strtab_size,
            gnu_hash_offset,
            syment: mem::size_of::<Elf64_Sym>(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn ehdr_size_64() {
        assert_eq!(mem::size_of::<Elf64_Ehdr>(), 64);
    }

    #[test]
    fn phdr_size_56() {
        assert_eq!(mem::size_of::<Elf64_Phdr>(), 56);
    }

    #[test]
    fn dyn_size_16() {
        assert_eq!(mem::size_of::<Elf64_Dyn>(), 16);
    }

    #[test]
    fn sym_size_24() {
        assert_eq!(mem::size_of::<Elf64_Sym>(), 24);
    }

    /// Build a 64-byte buffer where the first 4 bytes are NOT `\x7fELF` and
    /// the remainder is zero-padded. `parse_libc_elf` must reject with the
    /// exact `"bad magic"` message before doing any further validation.
    #[test]
    fn parse_rejects_bad_magic() {
        let buf = [0u8; 64];
        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&buf).expect("write");
        tmp.flush().expect("flush");

        let file = File::open(tmp.path()).expect("open");
        let err = parse_libc_elf(&file).expect_err("must reject bad magic");
        match err {
            Error::ElfParse(msg) => assert_eq!(msg, "bad magic"),
            other => panic!("expected ElfParse(\"bad magic\"), got {other:?}"),
        }
    }

    /// Build a minimally valid Ehdr up through `e_ident` + class + data, then
    /// set `e_machine` to 0x3e (EM_X86_64). All earlier checks must pass;
    /// parse must reject at the machine step with the exact spec-locked string.
    #[test]
    fn parse_rejects_wrong_machine() {
        // Build a raw 64-byte Ehdr with the correct magic + class + data
        // and e_machine = 0x3e (EM_X86_64).
        let mut ehdr = [0u8; 64];
        // e_ident[0..4] = \x7fELF
        ehdr[0] = 0x7f;
        ehdr[1] = b'E';
        ehdr[2] = b'L';
        ehdr[3] = b'F';
        // EI_CLASS = ELFCLASS64 (2)
        ehdr[4] = ELFCLASS64;
        // EI_DATA = ELFDATA2LSB (1)
        ehdr[5] = ELFDATA2LSB;
        // EI_VERSION (6) — bionic does not validate; leave zero.
        // e_type at offset 0x10 (2 bytes) — set to ET_DYN so we don't trip
        // that validator before reaching e_machine (though validation order
        // is magic→class→data→machine→type, so machine is checked first).
        ehdr[0x10] = ET_DYN as u8;
        ehdr[0x11] = 0;
        // e_machine at offset 0x12 (2 bytes, little-endian) = 0x3e (EM_X86_64)
        ehdr[0x12] = 0x3e;
        ehdr[0x13] = 0x00;

        let mut tmp = NamedTempFile::new().expect("tempfile");
        tmp.write_all(&ehdr).expect("write");
        tmp.flush().expect("flush");

        let file = File::open(tmp.path()).expect("open");
        let err = parse_libc_elf(&file).expect_err("must reject wrong machine");
        match err {
            Error::ElfParse(msg) => assert_eq!(msg, "e_machine != EM_AARCH64"),
            other => panic!("expected ElfParse(\"e_machine != EM_AARCH64\"), got {other:?}"),
        }
    }

    /// djb2a seed and first-byte step match bionic's `linker_gnu_hash.h:46-54`.
    #[test]
    fn gnu_hash_seed_5381() {
        assert_eq!(gnu_hash(b""), 5381);
        let expected = 5381u32.wrapping_mul(33).wrapping_add(u32::from(b'_'));
        assert_eq!(gnu_hash(b"_"), expected);
    }

    /// Build a minimal GNU_HASH section where the bloom filter is all zeros,
    /// which must reject every lookup before reaching bucket/chain. Verifies
    /// the "definitely absent" short-circuit and that `gnu_lookup` never
    /// panics on a pathological-but-well-formed header.
    #[test]
    fn gnu_lookup_absent_returns_none() {
        // Layout: 16 B header, 8 B bloom (bloom_size=1), 4 B bucket (nbuckets=1),
        // 4 B chain terminator. Total 32 B.
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nbuckets
        bytes.extend_from_slice(&0u32.to_le_bytes()); // symoffset
        bytes.extend_from_slice(&1u32.to_le_bytes()); // bloom_size
        bytes.extend_from_slice(&6u32.to_le_bytes()); // bloom_shift
        bytes.extend_from_slice(&0u64.to_le_bytes()); // bloom[0] — rejects all
        bytes.extend_from_slice(&0u32.to_le_bytes()); // buckets[0]
        bytes.extend_from_slice(&1u32.to_le_bytes()); // chain[0], terminator

        let view = LibcElfView::from_parts(
            bytes,
            /* symtab_offset */ 0,
            /* strtab_offset */ 0,
            /* strtab_size   */ 0,
            /* gnu_hash_offset */ Some(0),
        );

        assert!(gnu_lookup(&view, "whatever").is_none());
    }
}
