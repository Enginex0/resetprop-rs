//! Tier B per-prop hook installer — stage-A (ELF parse + symbol resolution)
//! and stage-B (remote mmap + prologue snapshot).
//!
//! P03 Task 5 scope: extend T4's stage-A pipeline with the stage-B remote
//! operations that land the handle's `hook_page` and `saved_prologue` fields.
//! Stage-B reuses the same attach / scratch-slot / remote-syscall machinery
//! as `seal::arena::remote_remap_private` (P02): a `RemoteAttach` RAII guard
//! scopes the `PTRACE_SEIZE + INTERRUPT` window, `find_scratch_slot` picks an
//! 8-byte-aligned offset in libc.text, and `remote_syscall_via_poke` executes
//! the remote `mmap` via `PEEK / POKEDATA` (which bypasses VMA write bits and
//! so accepts an `r-xp` scratch PC inside libc.text).
//!
//! # Platform note
//!
//! Stage-B issues AArch64 register-level ptrace operations via
//! `seal::ptrace::remote_syscall_via_poke`. The AArch64-specific register
//! layout (`UserPtRegs`) is cfg-gated at its definition site in
//! `seal::ptrace`, so this module compiles cleanly on x86_64 hosts for dev
//! builds and tests; at runtime stage-B is only meaningful when the tracee
//! is an aarch64 process (Android device targets).
//!
//! All failure paths surface as [`Error::HookInstallFailed`] with a stage-
//! prefixed message (`"stage-A: <step>: <cause>"` /
//! `"stage-B: <step>: <cause>"`) per the P03 checklist FR-18 / FR-19.

use std::fs::File;

use crate::error::{Error, Result};
use crate::seal;
use crate::seal::arena::{find_scratch_slot, NR_MMAP, NR_MUNMAP};
use crate::seal::maps::MapEntry;
use crate::seal::ptrace::{
    getregset, ptrace_peektext, ptrace_poketext, read_remote, remote_syscall_via_poke, setregset,
    wait_stop, write_remote, PTRACE_CONT,
};

// ─────────────────────────────────────────────────────────────────────────────
// Stage-B constants (REGISTRY §1 canonical flag values)
// ─────────────────────────────────────────────────────────────────────────────

/// `PROT_READ | PROT_WRITE | PROT_EXEC` — the hook page must be executable
/// so P04's trampoline can be landed in it, writable so we can stamp the
/// zero sentinel + future lock-list entries, and readable for load paths.
const PROT_RWX: u64 = 0x7;

/// `MAP_PRIVATE | MAP_ANONYMOUS` — anonymous RWX page in the tracee.
const MAP_PRIVATE_ANON: u64 = 0x22;

/// 4 KiB — one base page on AArch64. Mirrors `BOOTSTRAP_PAGE_SIZE` in
/// `seal::arena` but kept local to keep the stage-B constant block self-
/// contained. Kept as `u64` because the remote-syscall ABI is 64-bit and
/// the value flows straight into `remote_syscall_via_poke` args.
const HOOK_PAGE_SIZE: u64 = 4096;

/// Upper bound on how much of libc.text is read while hunting for a scratch
/// slot. Matches `seal::arena::LIBC_SCAN_LIMIT` (64 KiB) so the two stage
/// pipelines share identical scan behaviour.
const LIBC_SCAN_LIMIT: usize = 64 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// P04 T3 — hook-page layout and i-cache sync constants
// ─────────────────────────────────────────────────────────────────────────────

/// Hook page byte offset of the lock-list base (empty-list sentinel NUL byte
/// lives at offset 0, written by P03 stage-B at `hook.rs:310-312`).
/// Reference: `P04-tier-b-part2.md §Approach item 4`.
pub(crate) const LOCK_LIST_OFFSET: u64 = 0;

/// Hook page byte offset where [`build_hook_body_bytes`]'s 92-byte body
/// lands. Byte 0 is the empty-list sentinel NUL; bytes 1..=3 are zero
/// alignment padding; the body starts at byte 4. Reference:
/// `P04-tier-b-part2.md §Approach item 4`.
pub(crate) const HOOK_BODY_OFFSET: u64 = 4;

/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` — kernel cmd byte for
/// cross-core instruction-cache synchronisation after writing instruction
/// bytes into another process's VMA. Primary i-cache sync path after the
/// trampoline write. Reference:
/// `references/arm64-a64-encoding.md §i-cache invalidation options`
/// (linux/membarrier.h cmd enum value).
pub(crate) const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: u64 = 0x80;

/// `__NR_membarrier` on AArch64 Linux. Source:
/// `asm-generic/unistd.h:683` cited by `linux-arm64-abi.md §1` line 29.
pub(crate) const NR_MEMBARRIER: u64 = 283;

/// Per-prop Tier B hook handle.
///
/// Returned by [`install_init_hook`]. Field layout is locked by the P03 spec —
/// P04 code (same crate) mutates `lock_list_len` / `saved_prologue` and flips
/// `trampoline_installed` to `true` after its prologue patch completes.
/// External callers only need the type in their signature, so fields are
/// `pub(crate)`.
///
/// Cached stage-A context (`libc_base`, `libc_end`, `scratch_pc`) lets
/// [`HookHandle::drop_best_effort`] reuse the install-time scratch PC
/// instead of re-parsing `/proc/<pid>/maps` and re-scanning libc.text at
/// Drop time. This removes a class of TOCTOU bugs (libc hot-swap between
/// install and drop re-deriving into a different VMA) and simplifies the
/// Drop body; the remaining stale-scratch edge case (hot-swap AFTER
/// install) surfaces as EFAULT/ESRCH from `remote_syscall_via_poke`, which
/// Drop already swallows under best-effort semantics.
#[allow(dead_code)]
pub struct HookHandle {
    pub(crate) pid: libc::pid_t,
    pub(crate) hook_page: u64,
    pub(crate) lock_list_len: u32,
    pub(crate) target_fn: u64,
    pub(crate) saved_prologue: [u8; 16],
    pub(crate) libc_base: u64,
    pub(crate) libc_end: u64,
    pub(crate) scratch_pc: u64,
    /// Typestate guard for Drop.
    ///
    /// Flipped to `true` by P04 after the trampoline is live at `target_fn`.
    /// Once true, Drop MUST NOT unmap `hook_page` — init executes inside
    /// that page. P04 is responsible for reverting the trampoline and
    /// unmapping the page explicitly before the handle is dropped.
    pub(crate) trampoline_installed: bool,
}

/// Predicate picking the executable `libc.so` mapping out of a parsed maps file.
///
/// Two independent gates per spec:
///   1. `perms == b"r-xp"` — skip the r--p / rw-p copies of the same file.
///   2. path ends with `"/libc.so"` (the leading slash is mandatory so
///      `libc_hwasan.so` does NOT false-match — checklist §Self-Audit Gate 4).
pub(crate) fn is_libc_row(entry: &MapEntry) -> bool {
    &entry.perms == b"r-xp"
        && entry
            .path
            .as_ref()
            .and_then(|p| p.as_os_str().to_str())
            .is_some_and(|s| s.ends_with("/libc.so"))
}

/// Stage-A of the hook install pipeline — RUN UNDER ATTACH.
///
/// Returns `(libc_base, libc_end, target_fn)` where `libc_base` / `libc_end`
/// are the `r-xp` row's `start` / `end` addresses and
/// `target_fn = libc_base + st_value("__system_property_update")`
/// (ET_DYN runtime math per references/android-libc-elf.md §7).
///
/// This MUST be called while the caller holds a live `RemoteAttach` on
/// `pid`. Every stage-A observation — `/proc/<pid>/maps`, the libc row,
/// `/proc/<pid>/map_files/<start>-<end>`, the parsed symbol — is a snapshot
/// of the tracee's address space, and running outside the attach window
/// opens a TOCTOU gap (APEX hot-swap / Mainline update) that lets stage-B
/// consume stale `(libc_base, libc_end, target_fn)` tuples. Mirrors P02's
/// pattern at `arena.rs:278-304` (attach, then parse maps).
///
/// Step tags preserved in error messages so operators can see exactly which
/// step failed without enabling debug logging.
fn stage_a_locked(pid: libc::pid_t) -> Result<(u64, u64, u64)> {
    let entries = seal::maps::parse_maps(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_maps: {e}")))?;

    let libc_row = entries.iter().find(|e| is_libc_row(e)).ok_or_else(|| {
        Error::HookInstallFailed(format!("stage-A: libc row not found in /proc/{pid}/maps"))
    })?;

    let libc_base = libc_row.start;
    let libc_end = libc_row.end;
    let map_path = format!(
        "/proc/{}/map_files/{:x}-{:x}",
        pid, libc_row.start, libc_row.end
    );

    let file = File::open(&map_path)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: open {map_path}: {e}")))?;

    let view = seal::elf::parse_libc_elf(&file)
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: parse_libc_elf: {e}")))?;

    let st_value = seal::elf::resolve_symbol(&view, "__system_property_update")
        .map_err(|e| Error::HookInstallFailed(format!("stage-A: resolve_symbol: {e}")))?;

    let target_fn = libc_base
        .checked_add(st_value)
        .ok_or_else(|| Error::HookInstallFailed("stage-A: target_fn overflow".into()))?;

    Ok((libc_base, libc_end, target_fn))
}

/// Pick an 8-byte-aligned scratch PC inside libc.text for
/// `remote_syscall_via_poke`.
///
/// Small helper extracted so both the initial install path and
/// `HookHandle::drop_best_effort` share one implementation: attach the
/// tracee first (the caller passes an already-acquired guard), read up to
/// `LIBC_SCAN_LIMIT` bytes of the executable libc mapping via
/// `read_remote`, and delegate slot selection to
/// `seal::arena::find_scratch_slot` (prefers a 4-NOP slide, falls back to
/// the first 8-byte-aligned offset ≥ 64 past section-start trampolines).
///
/// # Safety
///
/// The tracee must be ptrace-stopped for the duration of the call (the
/// caller is expected to hold a live `RemoteAttach`). `libc_base..libc_end`
/// must refer to the tracee's `r-xp` libc mapping.
unsafe fn derive_libc_scratch_pc(pid: libc::pid_t, libc_base: u64, libc_end: u64) -> Result<u64> {
    let libc_text_len = libc_end.saturating_sub(libc_base) as usize;
    let scan_len = core::cmp::min(libc_text_len, LIBC_SCAN_LIMIT);
    let mut scan_buf = vec![0u8; scan_len];

    // SAFETY: `libc_base..libc_base + scan_len` lies inside the tracee's
    // `r-xp` libc mapping (caller contract). `read_remote` uses
    // `process_vm_readv`, which needs only the R bit — satisfied by `r-xp`.
    // The tracee is ptrace-stopped via the caller's `RemoteAttach` guard.
    unsafe { read_remote(pid, libc_base, &mut scan_buf) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: read libc.text: {e}")))?;

    let slide_offset = find_scratch_slot(&scan_buf)
        .ok_or_else(|| Error::HookInstallFailed("stage-B: no scratch slot in libc.text".into()))?;

    Ok(libc_base + slide_offset as u64)
}

/// Install the per-prop hook in the target process.
///
/// All tracee observations — `/proc/<pid>/maps`, the libc ELF parse, the
/// symbol resolution, the scratch-PC scan, the remote `mmap`, the sentinel
/// write, and the prologue snapshot — execute inside a single
/// `RemoteAttach` window so the tracee's address space cannot shift
/// (APEX hot-swap, Mainline update) between observation and use. The
/// returned handle owns the remote page via [`HookHandle`]'s `Drop` impl
/// (best-effort `munmap` via `remote_syscall_via_poke`).
///
/// # Error cleanup
///
/// Failures after the `mmap` succeeds trigger a best-effort remote
/// `munmap` of `hook_page` before the error propagates, so the tracee
/// does not leak a 4 KiB RWX page on cold-path errors. The cleanup runs
/// under the same attach window that installed the page.
pub fn install_init_hook(pid: libc::pid_t) -> Result<HookHandle> {
    let guard = seal::arena::RemoteAttach::new(pid)
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: attach: {e}")))?;

    // C1 fix: stage-A runs INSIDE the attach window — no TOCTOU gap.
    let (libc_base, libc_end, target_fn) = stage_a_locked(pid)?;

    // SAFETY: `guard` holds the tracee ptrace-stopped for this block;
    // `libc_base..libc_end` is the `r-xp` libc row just returned by
    // stage-A on the same process. `remote_syscall_via_poke`'s contract
    // is satisfied by the resulting scratch PC (8-byte-aligned, inside
    // an executable mapping, guarded against concurrent threads by the
    // seize).
    let scratch_pc = unsafe { derive_libc_scratch_pc(pid, libc_base, libc_end) }?;

    let hook_page = remote_mmap_hook_page(pid, scratch_pc)?;

    // M6 fix: any error past this point leaks `hook_page` unless we
    // explicitly unmap. Wrap the remaining stage-B steps in a closure
    // and, on error, issue a best-effort remote munmap before
    // propagating — the tracee is still ptrace-stopped via `guard`.
    let saved_prologue = match finish_stage_b_locked(pid, hook_page, target_fn) {
        Ok(p) => p,
        Err(e) => {
            // SAFETY: tracee still ptrace-stopped via `guard`; munmap
            // is legal in this window. We discard the result because
            // best-effort cleanup must not mask the original error.
            let _ = unsafe {
                remote_syscall_via_poke(
                    pid,
                    scratch_pc,
                    NR_MUNMAP,
                    [hook_page, HOOK_PAGE_SIZE, 0, 0, 0, 0],
                )
            };
            return Err(e);
        }
    };

    // Explicit detach — reads cleaner than leaving it to Drop, and surfaces
    // any detach failure at the install site rather than swallowing it in
    // `RemoteAttach::drop`.
    guard
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: detach: {e}")))?;

    Ok(HookHandle {
        pid,
        hook_page,
        lock_list_len: 0,
        target_fn,
        saved_prologue,
        libc_base,
        libc_end,
        scratch_pc,
        trampoline_installed: false,
    })
}

/// Issue the remote `mmap` for `hook_page` and decode its return.
///
/// Linux returns `-errno` in `[-4095, -1]` and a valid address otherwise
/// (linux-arm64-abi.md §11). Any value in the errno window fails the
/// install regardless of sign bit.
fn remote_mmap_hook_page(pid: libc::pid_t, scratch_pc: u64) -> Result<u64> {
    // SAFETY: see `derive_libc_scratch_pc` for the scratch-PC invariants;
    // `remote_syscall_via_poke` saves / restores both the 8-byte scratch
    // word and the saved-regs snapshot before returning (ptrace.rs:669-705),
    // so no outer restore wrapper is required here.
    let ret = unsafe {
        remote_syscall_via_poke(
            pid,
            scratch_pc,
            NR_MMAP,
            [0, HOOK_PAGE_SIZE, PROT_RWX, MAP_PRIVATE_ANON, u64::MAX, 0],
        )
    }
    .map_err(|e| Error::HookInstallFailed(format!("stage-B: mmap: {e}")))?;

    if (-4095..=-1).contains(&ret) {
        return Err(Error::HookInstallFailed(format!(
            "stage-B: mmap returned -errno={}",
            -ret
        )));
    }
    Ok(ret as u64)
}

/// Finish stage-B after a successful `mmap`: write the zero sentinel on
/// `hook_page` and snapshot the 16-byte prologue at `target_fn`.
///
/// Runs under the caller's `RemoteAttach`. Returning `Err` is the trigger
/// for the caller's best-effort remote `munmap` cleanup path (M6 fix).
fn finish_stage_b_locked(pid: libc::pid_t, hook_page: u64, target_fn: u64) -> Result<[u8; 16]> {
    // Write the 4-byte zero sentinel (lock-list length = 0). The hook
    // page is PROT_READ | WRITE | EXEC per the mmap args, so
    // `process_vm_writev` inside `write_remote` respects the W bit
    // without needing a POKE transport.
    //
    // SAFETY: `hook_page` was just returned by a successful `mmap` in the
    // tracee; tracee remains ptrace-stopped via the caller's guard.
    let sentinel = [0u8; 4];
    unsafe { write_remote(pid, hook_page, &sentinel) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: write sentinel: {e}")))?;

    // Snapshot the 16-byte prologue at `target_fn`. P04's trampoline
    // encoder overwrites exactly this window, so preserving the originals
    // lets us revert (or, later, single-step-over) the hook cleanly.
    //
    // SAFETY: `target_fn` points inside libc.text `r-xp`; `read_remote`
    // uses `process_vm_readv` which needs only the R bit.
    let mut saved_prologue = [0u8; 16];
    unsafe { read_remote(pid, target_fn, &mut saved_prologue) }
        .map_err(|e| Error::HookInstallFailed(format!("stage-B: read prologue: {e}")))?;

    Ok(saved_prologue)
}

impl HookHandle {
    /// Best-effort remote `munmap` of the hook page during `Drop`.
    ///
    /// Reuses `self.scratch_pc` (cached at install time) instead of
    /// re-parsing `/proc/<pid>/maps` and re-scanning libc.text. This
    /// removes the Drop-time TOCTOU window: even if libc was hot-swapped
    /// between install and drop, we do not re-derive into a different
    /// VMA. The remaining stale-scratch edge case (hot-swap AFTER
    /// install so the old PC is no longer executable) surfaces as
    /// EFAULT/ESRCH from `remote_syscall_via_poke`, which the caller
    /// swallows under best-effort semantics. Drop is inherently
    /// fallible; this is an acceptable failure mode.
    fn drop_best_effort(&self) -> Result<()> {
        let guard = seal::arena::RemoteAttach::new(self.pid)?;

        // SAFETY: `guard` holds the tracee ptrace-stopped.
        // `self.scratch_pc` was validated at install time as an
        // 8-byte-aligned offset inside the tracee's `r-xp` libc
        // mapping; `remote_syscall_via_poke` bypasses VMA write bits
        // via PEEK/POKEDATA. `self.hook_page` was returned by
        // stage-B's mmap and is the only argument threaded into munmap.
        unsafe {
            remote_syscall_via_poke(
                self.pid,
                self.scratch_pc,
                NR_MUNMAP,
                [self.hook_page, HOOK_PAGE_SIZE, 0, 0, 0, 0],
            )?;
        }

        guard.detach()?;
        Ok(())
    }
}

impl Drop for HookHandle {
    fn drop(&mut self) {
        // Typestate guards (M5):
        //
        // * `hook_page == 0` — stage-B never completed, nothing to unmap.
        //   Covers the checklist edge case "Drop fires before stage-B
        //   completes".
        // * `trampoline_installed` — P04 has patched the prologue and
        //   init is executing inside `hook_page`. Unmapping here would
        //   crash init. P04 is responsible for reverting the trampoline
        //   and unmapping the page explicitly before the handle drops.
        //
        // Errors from the best-effort path are swallowed: Drop cannot
        // propagate, and panicking here would abort on unwind.
        if self.hook_page == 0 || self.trampoline_installed {
            return;
        }
        let _ = self.drop_best_effort();
    }
}

/// A64 (ARM64) instruction encoders.
///
/// Every output is an aligned little-endian `u32` word. All encoders are
/// `const fn` with inline `assert!` guards on immediate ranges; they run at
/// compile time when invoked inside a `const` context and panic at runtime
/// when out-of-range arguments are passed in a non-const call site.
///
/// # References
///
/// * ARM DDI 0487 Part C, Chapter C6 — A64 base instructions.
/// * `phases/seal/references/arm64-a64-encoding.md` — canonical opcode
///   table and bit-layout mirrors used by this module.
/// * REGISTRY §1 rows `Trampoline — 16 bytes at symbol entry`,
///   `Trampoline LDR opcode for ldr x16,[pc,#8]`, `ARM64 encoder` —
///   locked canonical hex values (`NOP=0xd503201f`, `RET=0xd65f03c0`,
///   `ISB=0xd5033fdf`, `SVC #0=0xd4000001`, `BRK #0=0xd4200000`,
///   `LDR x16,[pc,#8]=0x58000050`, `BR x16=0xd61f0200`).
///
/// Scope: Task 1 of P04 ships exactly the 7 consts + 15 helpers the phase
/// spec enumerates; no additional abstractions are introduced. Task 2 /
/// Task 3 of the same phase will consume these from `build_hook_body_bytes`
/// and `install_trampoline`; until then the symbols are dead from the
/// library's perspective, hence the module-level `allow(dead_code)`.
#[allow(dead_code)]
pub(crate) mod encoder {
    /// Signed-range check for a two's-complement `bits`-wide immediate.
    ///
    /// Used by branch / PC-relative encoders to guard the imm19 / imm26
    /// fields before masking.
    #[inline]
    const fn fits_signed(v: i32, bits: u32) -> bool {
        let half = 1i32 << (bits - 1);
        v >= -half && v < half
    }

    /// Mask `v` into the low `bits` bits as an unsigned value. Callers must
    /// have already verified the range via `fits_signed`.
    #[inline]
    const fn mask_signed(v: i32, bits: u32) -> u32 {
        (v as u32) & ((1u32 << bits) - 1)
    }

    /// `nop` — canonical hint encoding (C6.2.273).
    pub const NOP: u32 = 0xd503_201f;

    /// `ret x30` — C6.2.312 with Rn=30.
    pub const RET_X30: u32 = 0xd65f_03c0;

    /// `isb sy` — C6.2.187 with CRm=0b1111.
    pub const ISB_SY: u32 = 0xd503_3fdf;

    /// `svc #0` — C6.2.392, LL=01.
    pub const SVC_0: u32 = 0xd400_0001;

    /// `brk #0` — C6.2.44, LL=00.
    pub const BRK_0: u32 = 0xd420_0000;

    /// `ldr x16, [pc, #8]` — trampoline first word (REGISTRY §1).
    pub const LDR_X16_PC8: u32 = 0x5800_0050;

    /// `br x16` — trampoline second word (REGISTRY §1).
    pub const BR_X16: u32 = 0xd61f_0200;

    /// `svc #imm16` (C6.2.392). `imm16` occupies bits [20:5].
    pub const fn svc(imm16: u16) -> u32 {
        0xd400_0001 | ((imm16 as u32) << 5)
    }

    /// `brk #imm16` (C6.2.44). `imm16` occupies bits [20:5].
    pub const fn brk(imm16: u16) -> u32 {
        0xd420_0000 | ((imm16 as u32) << 5)
    }

    /// `ret xN` (C6.2.312). Rn in bits [9:5]; default arch alias uses Rn=30.
    pub const fn ret(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd65f_0000 | ((rn as u32) << 5)
    }

    /// `br xN` (C6.2.41). Rn in bits [9:5].
    pub const fn br(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd61f_0000 | ((rn as u32) << 5)
    }

    /// `blr xN` (C6.2.40). Rn in bits [9:5]; writes X30.
    pub const fn blr(rn: u8) -> u32 {
        assert!(rn < 32);
        0xd63f_0000 | ((rn as u32) << 5)
    }

    /// `ldr xt, [pc, #byte_offset]` (C6.2.200). `byte_offset` must be ×4
    /// and its imm19 field must fit a signed 19-bit value.
    pub const fn ldr_literal(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0x5800_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `add xd, xn, #imm12` (C6.2.4, sf=1, sh=0). `imm12` must fit 12 bits.
    pub const fn add_imm64(rd: u8, rn: u8, imm12: u16) -> u32 {
        assert!(rd < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
        0x9100_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rd as u32)
    }

    /// `movz xd, #imm16, LSL #(hw*16)` (C6.2.271, sf=1). `hw` in 0..=3.
    pub const fn movz(rd: u8, imm16: u16, hw: u8) -> u32 {
        assert!(rd < 32 && hw < 4);
        0xd280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
    }

    /// `movk xd, #imm16, LSL #(hw*16)` (C6.2.270, sf=1). `hw` in 0..=3.
    pub const fn movk(rd: u8, imm16: u16, hw: u8) -> u32 {
        assert!(rd < 32 && hw < 4);
        0xf280_0000 | ((hw as u32) << 21) | ((imm16 as u32) << 5) | (rd as u32)
    }

    /// `cbz xt, #byte_offset` (C6.2.48, sf=1). Signed 21-bit range, ×4.
    pub const fn cbz(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0xb400_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `cbnz xt, #byte_offset` (C6.2.47, sf=1). Signed 21-bit range, ×4.
    pub const fn cbnz(rt: u8, byte_offset: i32) -> u32 {
        assert!(rt < 32 && byte_offset % 4 == 0);
        let imm19 = byte_offset / 4;
        assert!(fits_signed(imm19, 19));
        0xb500_0000 | (mask_signed(imm19, 19) << 5) | (rt as u32)
    }

    /// `b #byte_offset` (C6.2.34). Signed 28-bit range, ×4.
    pub const fn b_rel(byte_offset: i32) -> u32 {
        assert!(byte_offset % 4 == 0);
        let imm26 = byte_offset / 4;
        assert!(fits_signed(imm26, 26));
        0x1400_0000 | mask_signed(imm26, 26)
    }

    /// `ldrb wt, [xn, #imm12]` unsigned-offset form (C6.2.203). Byte-scaled.
    pub const fn ldrb_imm(rt: u8, rn: u8, imm12: u16) -> u32 {
        assert!(rt < 32 && rn < 32 && (imm12 as u32) < (1 << 12));
        0x3940_0000 | ((imm12 as u32) << 10) | ((rn as u32) << 5) | (rt as u32)
    }

    /// `nop` — shorthand for the fixed opcode.
    pub const fn nop() -> u32 {
        NOP
    }

    /// `isb sy` — shorthand for the fixed opcode.
    pub const fn isb() -> u32 {
        ISB_SY
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// P04 T2 — pure hook-body encoder
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical 23-word (92-byte) hook-body template per
/// `references/arm64-a64-encoding.md` §Hook body sketch lines 383-407.
///
/// The template carries `nop` (0xd503_201f) in the three patch regions
/// (STOLEN_START=13..=16, RESTORE_LIT=19..=20, LOCK_LIST_LIT=21..=22). The
/// RESTORE and LOCK_LIST literal slots are documented as zeros in the
/// reference; we seed them with `nop` for the prologue mirrors and `0` for
/// the two u64 literal slots so uninitialised reads during construction
/// remain deterministic. [`build_hook_body_bytes`] overwrites all three
/// regions before returning, so the seed value is never observable.
const HOOK_BODY_TEMPLATE: [u32; 23] = [
    0xb400_01a0, // 0: cbz  x0, .fall_through  (+52)
    0x9101_8009, // 1: add  x9, x0, #96
    0x5800_026a, // 2: ldr  x10, =LOCK_LIST    (+76)
    0x3940_014b, // 3: ldrb w11, [x10]
    0x3400_012b, // 4: cbz  w11, .fall_through (+36)
    0x1400_0003, // 5: b .advance              (+12)  -- strcmp stub
    0x5280_0000, // 6: movz w0, #0
    0xd65f_03c0, // 7: ret
    0x9100_054a, // 8: add  x10, x10, #1
    0x17ff_fffa, // 9: b .next_entry           (-24)
    0xd503_201f, // 10: nop
    0xd503_201f, // 11: nop
    0xd503_201f, // 12: nop
    0xd503_201f, // 13: STOLEN_0 (patched)
    0xd503_201f, // 14: STOLEN_1 (patched)
    0xd503_201f, // 15: STOLEN_2 (patched)
    0xd503_201f, // 16: STOLEN_3 (patched)
    0x5800_0050, // 17: ldr x16, =RESTORE_TARGET (+8)
    0xd61f_0200, // 18: br  x16
    0x0000_0000, // 19: RESTORE_TARGET lo (patched)
    0x0000_0000, // 20: RESTORE_TARGET hi (patched)
    0x0000_0000, // 21: LOCK_LIST lo (patched)
    0x0000_0000, // 22: LOCK_LIST hi (patched)
];

/// Word index of the first stolen-prologue slot inside HOOK_BODY_TEMPLATE
/// (reference §Hook body sketch patch-point indices).
const STOLEN_START: usize = 13;
/// Word index of the RESTORE_TARGET u64 low half (literal at words 19..=20).
const RESTORE_LIT: usize = 19;
/// Word index of the LOCK_LIST u64 low half (literal at words 21..=22).
const LOCK_LIST_LIT: usize = 21;

/// Emit the 92-byte hook body for the Tier B per-prop guard.
///
/// Pure, deterministic, no ptrace, no I/O, no unsafe. Given the 16 bytes of
/// stolen prologue (captured by P03 stage-B into [`HookHandle::saved_prologue`]),
/// the lock-list base address in the tracee, and the resume address
/// (`target_fn + 16`), returns the 23-word hook body with the three patch
/// regions filled in little-endian order.
///
/// # Patch layout
///
/// * Words 13..=16 (`STOLEN_START..STOLEN_START+4`) ← `saved_prologue` decoded
///   as four LE `u32`s.
/// * Words 19..=20 (`RESTORE_LIT..RESTORE_LIT+2`) ← `return_addr` split into
///   low / high LE `u32` halves.
/// * Words 21..=22 (`LOCK_LIST_LIT..LOCK_LIST_LIT+2`) ← `lock_list_vaddr`
///   split into low / high LE `u32` halves.
///
/// The returned `Vec<u8>` is the little-endian byte serialisation of the
/// 23-word array per reference §Endianness (ARM64 Linux userspace is always
/// little-endian; each `u32` is stored LSB-first).
///
/// # References
///
/// * `references/arm64-a64-encoding.md` §Hook body sketch (canonical template)
/// * `references/arm64-a64-encoding.md` §Hook body sketch — Patch-point
///   indices (`STOLEN_START=13`, `RESTORE_LIT=19`, `LOCK_LIST_LIT=21`)
/// * REGISTRY §1 row `Hook page — 4 KB RWX anonymous mmap`
pub fn build_hook_body_bytes(
    saved_prologue: [u8; 16],
    lock_list_vaddr: u64,
    return_addr: u64,
) -> Vec<u8> {
    let mut body = HOOK_BODY_TEMPLATE;

    // Patch region 1: stolen prologue (words 13..=16, 16 bytes).
    for (i, word) in body[STOLEN_START..STOLEN_START + 4].iter_mut().enumerate() {
        let base = i * 4;
        *word = u32::from_le_bytes([
            saved_prologue[base],
            saved_prologue[base + 1],
            saved_prologue[base + 2],
            saved_prologue[base + 3],
        ]);
    }

    // Patch region 2: RESTORE_TARGET u64 (words 19..=20, LE lo+hi).
    body[RESTORE_LIT] = return_addr as u32;
    body[RESTORE_LIT + 1] = (return_addr >> 32) as u32;

    // Patch region 3: LOCK_LIST u64 (words 21..=22, LE lo+hi).
    body[LOCK_LIST_LIT] = lock_list_vaddr as u32;
    body[LOCK_LIST_LIT + 1] = (lock_list_vaddr >> 32) as u32;

    body.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// P04 T3 — trampoline installer + i-cache sync
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a single `isb` in the tracee by staging `isb ; brk #0` at
/// `scratch_pc`, flipping `pc`, resuming, waiting for the brk trap, and
/// restoring the original word and registers.
///
/// Mirrors the structural skeleton of
/// [`crate::seal::ptrace::remote_syscall_via_poke`] (at `ptrace.rs:627-705`)
/// but carries an instruction payload rather than a syscall payload — the
/// tracee never enters the kernel, so there is no `x8`, no args, no `x0`
/// decode. This is the fallback path for `install_trampoline`'s i-cache
/// sync when `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` returns `EINVAL`
/// (cmd missing) or `EPERM` (registration missing).
///
/// Errors after the POKE (wait_stop, regs restore) trigger a best-effort
/// restore of both the scratch word and the saved registers before the
/// original cause propagates; this matches the pattern in
/// `remote_syscall_via_poke` so libc.text is never left poisoned.
///
/// # Safety
///
/// Caller holds a live `RemoteAttach` on `pid`; `scratch_pc` is 4-byte
/// aligned, lies inside an executable mapping with at least 8 bytes of
/// room, and no other thread in the tracee is racing on those 8 bytes.
unsafe fn execute_remote_isb(pid: libc::pid_t, scratch_pc: u64) -> Result<()> {
    let payload: u64 = (encoder::ISB_SY as u64) | ((encoder::BRK_0 as u64) << 32);

    let saved_word = ptrace_peektext(pid, scratch_pc)?;
    ptrace_poketext(pid, scratch_pc, payload)?;

    let saved_regs = getregset(pid)?;
    let mut work = saved_regs;
    work.pc = scratch_pc;
    setregset(pid, &work)?;

    // SAFETY: `libc::ptrace` FFI; `addr` / `data` are NULL per PTRACE_CONT
    // contract; tracee is ptrace-stopped via the caller's RemoteAttach.
    let rc = unsafe {
        libc::ptrace(
            PTRACE_CONT as _,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if rc == -1 {
        let _ = ptrace_poketext(pid, scratch_pc, saved_word);
        let _ = setregset(pid, &saved_regs);
        return Err(Error::PtraceOp(std::io::Error::last_os_error()));
    }

    let wait_result = wait_stop(pid, 0);
    if wait_result.is_err() {
        let _ = ptrace_poketext(pid, scratch_pc, saved_word);
        let _ = setregset(pid, &saved_regs);
    }
    wait_result?;

    setregset(pid, &saved_regs)?;
    ptrace_poketext(pid, scratch_pc, saved_word)?;
    Ok(())
}

/// Best-effort revert of a partial trampoline write.
///
/// Called only from `install_trampoline`'s error paths after the 16-byte
/// trampoline POKE sequence has begun. Restores the original prologue by
/// decoding `saved_prologue` as two little-endian `u64` words and issuing
/// two `PTRACE_POKEDATA` writes. Errors are logged via `eprintln!` and
/// never returned — the caller is already propagating the original cause
/// and a second error would only obscure it.
fn revert_trampoline(pid: libc::pid_t, target_fn: u64, saved_prologue: &[u8; 16]) {
    let lo = u64::from_le_bytes([
        saved_prologue[0],
        saved_prologue[1],
        saved_prologue[2],
        saved_prologue[3],
        saved_prologue[4],
        saved_prologue[5],
        saved_prologue[6],
        saved_prologue[7],
    ]);
    let hi = u64::from_le_bytes([
        saved_prologue[8],
        saved_prologue[9],
        saved_prologue[10],
        saved_prologue[11],
        saved_prologue[12],
        saved_prologue[13],
        saved_prologue[14],
        saved_prologue[15],
    ]);
    if let Err(e) = ptrace_poketext(pid, target_fn, lo) {
        eprintln!("resetprop: revert_trampoline lo word failed: {e}");
    }
    if let Err(e) = ptrace_poketext(pid, target_fn + 8, hi) {
        eprintln!("resetprop: revert_trampoline hi word failed: {e}");
    }
}

/// Install the 16-byte absolute-target trampoline at `handle.target_fn`
/// and the 92-byte hook body at `handle.hook_page + HOOK_BODY_OFFSET`.
///
/// Write order is load-bearing: the hook body must be fully materialised
/// before the trampoline's `br x16` can land on a valid target, so the
/// body is written first (step 4) and the trampoline second (step 5). If
/// init is scheduled onto the trampoline mid-install, it sees either the
/// old prologue (trampoline not yet written) or a fully-formed hook
/// (trampoline written, body already in place) — never a half-formed
/// body.
///
/// After both writes land, the instruction cache on each core must be
/// synchronised with the updated data cache or the tracee may execute
/// stale bytes fetched before our POKEs. The primary path issues a
/// remote `membarrier(PRIVATE_EXPEDITED_SYNC_CORE)` (one syscall, no
/// symbol resolution); on `EINVAL` / `EPERM` (kernel lacks the cmd or
/// the tracee never registered) it falls back to
/// [`execute_remote_isb`].
///
/// On success, `handle.trampoline_installed` is flipped to `true` so
/// [`HookHandle::drop`] skips the `munmap` — init is now executing
/// inside the hook page.
///
/// # Error cleanup
///
/// Any failure after the trampoline write has begun (steps 5-7) triggers
/// a best-effort [`revert_trampoline`] under the same attach window
/// before the error propagates, so the tracee is not left running a
/// half-written trampoline.
pub fn install_trampoline(handle: &mut HookHandle) -> Result<()> {
    // Step 1: compute addresses.
    let lock_list_vaddr = handle.hook_page + LOCK_LIST_OFFSET;
    let hook_body_vaddr = handle.hook_page + HOOK_BODY_OFFSET;
    let resume_addr = handle.target_fn + 16;

    // Step 2: pure helper emits the 92-byte hook body.
    let body_bytes = build_hook_body_bytes(handle.saved_prologue, lock_list_vaddr, resume_addr);

    // Step 3: acquire attach RAII guard.
    let attach = seal::arena::RemoteAttach::new(handle.pid)
        .map_err(|e| Error::HookInstallFailed(format!("install_trampoline: attach: {e}")))?;

    // Steps 4-7 run under the attach. A failure in any of 5-7 must revert
    // the trampoline write before the error unwinds. Using a closure lets
    // `?` propagate cleanly while a trailing `match` runs the cleanup.
    let trampoline_result = (|| -> Result<()> {
        // Step 4: write hook body to the fresh PROT_RWX hook page.
        //
        // SAFETY: `handle.hook_page` is the fresh PROT_READ|WRITE|EXEC page
        // that P03 stage-B mmap'd via `remote_syscall_via_poke`
        // (`hook.rs:269-291`); the W bit is set so `process_vm_writev`
        // inside `write_remote` succeeds. The tracee is ptrace-stopped via
        // `attach`.
        unsafe { write_remote(handle.pid, hook_body_vaddr, &body_bytes) }.map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: write body: {e}"))
        })?;

        // Step 5: write the 16-byte trampoline at `target_fn`.
        //
        // `target_fn` lives inside libc.text `r-xp`, so `process_vm_writev`
        // EFAULTs. `PTRACE_POKEDATA` bypasses VMA write bits via
        // `ptrace_access_vm`. The trampoline is two LP64 words: word_lo
        // packs `ldr x16, [pc, #8]` (low 4 bytes) with `br x16` (high 4
        // bytes); word_hi is the absolute 64-bit literal target.
        let word_lo = (encoder::LDR_X16_PC8 as u64) | ((encoder::BR_X16 as u64) << 32);
        let word_hi = hook_body_vaddr;
        ptrace_poketext(handle.pid, handle.target_fn, word_lo).map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: poke tramp lo: {e}"))
        })?;
        ptrace_poketext(handle.pid, handle.target_fn + 8, word_hi).map_err(|e| {
            Error::HookInstallFailed(format!("install_trampoline: poke tramp hi: {e}"))
        })?;

        // Step 6: i-cache sync via remote membarrier (primary path).
        //
        // SAFETY: `handle.scratch_pc` is the 8-byte-aligned slot inside
        // libc.text cached at P03 install time (`hook.rs:218`); the tracee
        // is ptrace-stopped via `attach`; `remote_syscall_via_poke` saves
        // and restores both the scratch word and the saved-regs snapshot
        // internally before returning.
        let membarrier_ret = unsafe {
            remote_syscall_via_poke(
                handle.pid,
                handle.scratch_pc,
                NR_MEMBARRIER,
                [MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 0, 0, 0, 0],
            )
        }
        .map_err(|e| Error::HookInstallFailed(format!("install_trampoline: membarrier: {e}")))?;

        // Step 7: decode membarrier return, falling back to ISB staging
        // when the kernel rejects the cmd (EINVAL) or the tracee has not
        // registered (EPERM).
        if membarrier_ret >= 0 {
            return Ok(());
        }
        let einval_neg = -(libc::EINVAL as i64);
        let eperm_neg = -(libc::EPERM as i64);
        if membarrier_ret == einval_neg || membarrier_ret == eperm_neg {
            // SAFETY: same invariants as step 6 — `attach` holds the tracee
            // stopped; `handle.scratch_pc` is the cached libc.text slot.
            return unsafe { execute_remote_isb(handle.pid, handle.scratch_pc) };
        }
        if (-4095..=-1).contains(&membarrier_ret) {
            return Err(Error::HookInstallFailed(format!(
                "install_trampoline: membarrier returned -errno={}",
                -membarrier_ret
            )));
        }
        Ok(())
    })();

    if let Err(e) = trampoline_result {
        revert_trampoline(handle.pid, handle.target_fn, &handle.saved_prologue);
        if let Err(detach_err) = attach.detach() {
            eprintln!("resetprop: detach after install error failed: {detach_err}");
        }
        return Err(e);
    }

    // Step 8: flip typestate so Drop skips the munmap.
    handle.trampoline_installed = true;

    // Step 9: explicit detach surfaces any failure here at the install site.
    attach
        .detach()
        .map_err(|e| Error::HookInstallFailed(format!("install_trampoline: detach: {e}")))?;

    // Step 10.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk_entry(perms: &[u8; 4], path: Option<&str>) -> MapEntry {
        MapEntry {
            start: 0x7000_0000_0000,
            end: 0x7000_0010_0000,
            perms: *perms,
            offset: 0,
            path: path.map(PathBuf::from),
        }
    }

    /// Verifies the `HookHandle` field layout is reachable by `pub(crate)` access
    /// from within the module. Covers spec item "asserts the struct has the
    /// expected field layout (non-zero fields are reachable via accessors)".
    #[test]
    fn hook_handle_size() {
        let h = HookHandle {
            pid: 42,
            hook_page: 0xdeadbeef_cafebabe,
            lock_list_len: 7,
            target_fn: 0x1234_5678_9abc_def0,
            saved_prologue: [0xAB; 16],
            libc_base: 0x7000_0000_0000,
            libc_end: 0x7000_0010_0000,
            scratch_pc: 0x7000_0000_1000,
            trampoline_installed: false,
        };
        assert_eq!(h.pid, 42);
        assert_eq!(h.hook_page, 0xdeadbeef_cafebabe);
        assert_eq!(h.lock_list_len, 7);
        assert_eq!(h.target_fn, 0x1234_5678_9abc_def0);
        assert_eq!(h.saved_prologue, [0xAB; 16]);
        assert_eq!(h.libc_base, 0x7000_0000_0000);
        assert_eq!(h.libc_end, 0x7000_0010_0000);
        assert_eq!(h.scratch_pc, 0x7000_0000_1000);
        assert!(!h.trampoline_installed);
    }

    /// Exercises `is_libc_row` against the tricky cases called out in the
    /// checklist §Self-Audit Gate 4:
    ///   * APEX bionic path (canonical Android 10+) → match.
    ///   * Bootstrap libc path (early init) → match.
    ///   * `libc_hwasan.so` (suffix trap) → must NOT match.
    ///   * Non-executable row (`r--p`) → must NOT match even with matching name.
    ///   * Anonymous row with no path → must NOT match.
    #[test]
    fn libc_row_filter_r_xp_suffix() {
        let apex = mk_entry(
            b"r-xp",
            Some("/apex/com.android.runtime/lib64/bionic/libc.so"),
        );
        let bootstrap = mk_entry(b"r-xp", Some("/system/lib64/bootstrap/libc.so"));
        let hwasan = mk_entry(
            b"r-xp",
            Some("/apex/com.android.runtime/lib64/bionic/libc_hwasan.so"),
        );
        let wrong_perms = mk_entry(
            b"r--p",
            Some("/apex/com.android.runtime/lib64/bionic/libc.so"),
        );
        let anon = mk_entry(b"r-xp", None);

        assert!(is_libc_row(&apex), "APEX bionic libc.so must match");
        assert!(
            is_libc_row(&bootstrap),
            "/system/lib64/bootstrap/libc.so must match"
        );
        assert!(
            !is_libc_row(&hwasan),
            "libc_hwasan.so must NOT match (suffix trap)"
        );
        assert!(
            !is_libc_row(&wrong_perms),
            "r--p copy must NOT match (wrong perms)"
        );
        assert!(!is_libc_row(&anon), "anonymous row must NOT match");
    }

    /// Compile-time confirmation that `HookHandle` implements `Drop`. The
    /// stage-B Drop body exercises `remote_syscall_via_poke` against a
    /// live tracee and is therefore not unit-testable from an x86_64 host;
    /// this check is the narrow invariant we can enforce without device
    /// integration (the `tier_b_child_smoke` integration test lands in
    /// P04 per REGISTRY §3).
    #[test]
    fn handle_drop_is_defined() {
        // `T: Drop` is the exact bound the P03 T5 spec prescribes. Clippy's
        // `drop_bounds` lint prefers `std::mem::needs_drop`, but here we
        // specifically want to assert that `HookHandle` has a user-written
        // `Drop` impl (not merely contains fields that need dropping), so
        // the stronger bound is intentional.
        #[allow(drop_bounds)]
        fn _drop_compiles<T: Drop>() {}
        _drop_compiles::<HookHandle>();
    }

    // ─────────────────────────────────────────────────────────────────────
    // P04 T1 — A64 encoder submodule tests
    // ─────────────────────────────────────────────────────────────────────

    /// Round-trips a 16-byte absolute-target trampoline built from the
    /// encoder helpers against the canonical byte pattern from
    /// `references/arm64-a64-encoding.md` §Absolute-target trampoline.
    ///
    /// This is the strongest round-trip check we can run without a
    /// disassembler: it proves (a) `LDR_X16_PC8` and `BR_X16` consts match
    /// the helper-constructed forms for x16, and (b) the imm19 field of
    /// `ldr_literal(16, 8)` encodes to the expected `0x58000050` word.
    #[test]
    fn trampoline_from_helpers_matches_reference() {
        use super::encoder::{br, ldr_literal};

        let target: u64 = 0x0000_7fff_abcd_1234;
        let ldr = ldr_literal(16, 8).to_le_bytes();
        let br_x16 = br(16).to_le_bytes();
        let lo = (target as u32).to_le_bytes();
        let hi = ((target >> 32) as u32).to_le_bytes();

        let actual: [u8; 16] = [
            ldr[0], ldr[1], ldr[2], ldr[3], br_x16[0], br_x16[1], br_x16[2], br_x16[3], lo[0],
            lo[1], lo[2], lo[3], hi[0], hi[1], hi[2], hi[3],
        ];

        let expected: [u8; 16] = [
            0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6, 0x34, 0x12, 0xcd, 0xab, 0xff, 0x7f,
            0x00, 0x00,
        ];

        assert_eq!(actual, expected);
    }

    /// Defends the 7 pub consts against refactoring drift. Every value is
    /// pinned in REGISTRY §1 or `references/arm64-a64-encoding.md` §Instruction
    /// Table, so any change here must be accompanied by a REGISTRY amendment.
    #[test]
    fn opcodes_match_canonical_values() {
        use super::encoder::{BRK_0, BR_X16, ISB_SY, LDR_X16_PC8, NOP, RET_X30, SVC_0};

        assert_eq!(NOP, 0xd503_201f);
        assert_eq!(RET_X30, 0xd65f_03c0);
        assert_eq!(ISB_SY, 0xd503_3fdf);
        assert_eq!(SVC_0, 0xd400_0001);
        assert_eq!(BRK_0, 0xd420_0000);
        assert_eq!(LDR_X16_PC8, 0x5800_0050);
        assert_eq!(BR_X16, 0xd61f_0200);
    }

    // Bit-range assertion sub-tests. Each helper is exercised once with an
    // out-of-range argument to confirm the inline `assert!` fires. The
    // tests are split per-case so a single regression surfaces the exact
    // helper whose guard changed.

    #[test]
    #[should_panic]
    fn add_imm64_rejects_imm12_equal_to_4096() {
        let _ = super::encoder::add_imm64(0, 0, 4096);
    }

    #[test]
    #[should_panic]
    fn add_imm64_rejects_rd_equal_to_32() {
        let _ = super::encoder::add_imm64(32, 0, 0);
    }

    #[test]
    #[should_panic]
    fn ret_rejects_rn_equal_to_32() {
        let _ = super::encoder::ret(32);
    }

    #[test]
    #[should_panic]
    fn br_rejects_rn_equal_to_32() {
        let _ = super::encoder::br(32);
    }

    #[test]
    #[should_panic]
    fn blr_rejects_rn_equal_to_32() {
        let _ = super::encoder::blr(32);
    }

    #[test]
    #[should_panic]
    fn ldr_literal_rejects_unaligned_offset() {
        let _ = super::encoder::ldr_literal(0, 2);
    }

    #[test]
    #[should_panic]
    fn ldr_literal_rejects_imm19_overflow() {
        // imm19 signed range is [-2^18, 2^18 - 1] words = [-1048576, 1048572] bytes.
        // 1048576 (2^20) in bytes is one past the positive limit and must assert.
        let _ = super::encoder::ldr_literal(0, 1 << 20);
    }

    #[test]
    #[should_panic]
    fn movz_rejects_hw_equal_to_4() {
        let _ = super::encoder::movz(0, 0, 4);
    }

    #[test]
    #[should_panic]
    fn movk_rejects_hw_equal_to_4() {
        let _ = super::encoder::movk(0, 0, 4);
    }

    #[test]
    #[should_panic]
    fn cbz_rejects_unaligned_offset() {
        let _ = super::encoder::cbz(0, 2);
    }

    #[test]
    #[should_panic]
    fn cbnz_rejects_unaligned_offset() {
        let _ = super::encoder::cbnz(0, 2);
    }

    #[test]
    #[should_panic]
    fn b_rel_rejects_imm26_overflow() {
        // imm26 signed range is [-2^25, 2^25 - 1] words. 2^25 words = 2^27 bytes
        // = 134_217_728 is one past the positive limit and must assert.
        let _ = super::encoder::b_rel(1 << 27);
    }

    #[test]
    #[should_panic]
    fn ldrb_imm_rejects_imm12_equal_to_4096() {
        let _ = super::encoder::ldrb_imm(0, 0, 4096);
    }

    // ─────────────────────────────────────────────────────────────────────
    // P04 T2 — build_hook_body_bytes tests
    // ─────────────────────────────────────────────────────────────────────

    /// Verifies [`build_hook_body_bytes`] serialises the 23-word template
    /// with the three patch regions filled in the correct byte positions.
    ///
    /// Offsets derive directly from `references/arm64-a64-encoding.md`
    /// §Hook body sketch: word N lives at byte `N * 4`, so STOLEN_START=13
    /// lands at offset 52, RESTORE_LIT=19 lands at offset 76, and
    /// LOCK_LIST_LIT=21 lands at offset 84. Total length is 23 × 4 = 92
    /// bytes.
    #[test]
    fn build_hook_body_bytes_roundtrip() {
        let saved_prologue = [0xABu8; 16];
        let lock_list_vaddr: u64 = 0x1111_2222_3333_4444;
        let return_addr: u64 = 0xDEAD_BEEF_CAFE_BABE;

        let bytes = build_hook_body_bytes(saved_prologue, lock_list_vaddr, return_addr);

        assert_eq!(bytes.len(), 92, "hook body must be 23 words × 4 = 92 bytes");

        // Fixed prologue — reference HOOK_BODY[0..6].
        assert_eq!(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            0xb400_01a0,
            "word 0: cbz x0, .fall_through (+52)"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            0x9101_8009,
            "word 1: add x9, x0, #96"
        );

        // Match-exit pair at words 6..=7.
        assert_eq!(
            u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            0x5280_0000,
            "word 6: movz w0, #0"
        );
        assert_eq!(
            u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
            0xd65f_03c0,
            "word 7: ret"
        );

        // Patch region 1: STOLEN_START at words 13..=16 (bytes 52..68).
        assert_eq!(
            &bytes[52..68],
            &saved_prologue,
            "STOLEN_START must mirror saved_prologue bytes"
        );

        // Patch region 2: RESTORE_TARGET u64 at words 19..=20 (bytes 76..84).
        assert_eq!(
            u64::from_le_bytes([
                bytes[76], bytes[77], bytes[78], bytes[79], bytes[80], bytes[81], bytes[82],
                bytes[83],
            ]),
            return_addr,
            "RESTORE_TARGET literal must equal return_addr"
        );

        // Patch region 3: LOCK_LIST u64 at words 21..=22 (bytes 84..92).
        assert_eq!(
            u64::from_le_bytes([
                bytes[84], bytes[85], bytes[86], bytes[87], bytes[88], bytes[89], bytes[90],
                bytes[91],
            ]),
            lock_list_vaddr,
            "LOCK_LIST literal must equal lock_list_vaddr"
        );
    }

    /// Compile-time coercion that pins the public signature of
    /// [`build_hook_body_bytes`].
    ///
    /// A successful `fn`-pointer assignment proves the function takes
    /// exactly `([u8; 16], u64, u64)` and returns `Vec<u8>` with no hidden
    /// `&self`, `&mut self`, or `Self`-bound parameters — i.e. it cannot
    /// depend on a tracer context, a mutex guard, or any ptrace handle.
    /// This is the strongest purity assertion the type system alone can
    /// express. The runtime call with `[0; 16]` / `0` / `0` additionally
    /// proves the function executes with all zero inputs without panic
    /// (no hidden `assert!` on the patch values) and returns the
    /// spec-locked 92-byte length.
    #[test]
    fn build_hook_body_bytes_is_pure() {
        let _: fn([u8; 16], u64, u64) -> Vec<u8> = build_hook_body_bytes;

        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);
        assert_eq!(bytes.len(), 92);
    }

    /// Pins the fixed prologue words 0..=5 of the hook body against the
    /// canonical `HOOK_BODY` array in
    /// `references/arm64-a64-encoding.md` §Hook body sketch (lines 383-388).
    ///
    /// These six words are not in any patch region — a drift here would
    /// mean the strcmp stub / null-guard layout no longer matches the
    /// reference and any downstream `install_trampoline` consumer (P04 T3)
    /// would install a body that branches to the wrong offsets.
    #[test]
    fn build_hook_body_bytes_constants_from_reference() {
        let bytes = build_hook_body_bytes([0u8; 16], 0, 0);

        let expected: [u32; 6] = [
            0xb400_01a0, // 0: cbz x0, .fall_through (+52)
            0x9101_8009, // 1: add x9, x0, #96
            0x5800_026a, // 2: ldr x10, =LOCK_LIST (+76)
            0x3940_014b, // 3: ldrb w11, [x10]
            0x3400_012b, // 4: cbz w11, .fall_through (+36)
            0x1400_0003, // 5: b .advance (+12) — strcmp stub
        ];

        for (i, expected_word) in expected.iter().enumerate() {
            let base = i * 4;
            let actual = u32::from_le_bytes([
                bytes[base],
                bytes[base + 1],
                bytes[base + 2],
                bytes[base + 3],
            ]);
            assert_eq!(
                actual, *expected_word,
                "word {i} drifted from reference HOOK_BODY[{i}]"
            );
        }
    }
}
