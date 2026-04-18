//! Tier A arena seal — remote `MAP_PRIVATE|MAP_FIXED` remap of init's writable
//! view of a property arena. This file ships the mapping-lookup step (T1); the
//! remote ptrace-driven remap (T2) and the `seal_arena`/`unseal_arena`
//! orchestrators (T3) follow.

use std::path::Path;

use super::maps::{parse_maps, MapEntry};
use crate::error::{Error, Result};

/// Pure helper: scan a pre-parsed maps slice for init's writable view of
/// `arena_path`.
///
/// Returns the first entry whose path equals `arena_path` and whose permissions
/// start with `b"rw"`. If only a read-only (`b"r-"`) match exists — or no match
/// at all — the error is `ArenaNotMapped(arena_path.to_path_buf())`; the
/// variant is reused for the ro-only case because both conditions surface the
/// same operator-visible failure (init does not have a writable mapping we can
/// remap), and a single error shape keeps caller branches simple.
///
/// NOTE: `MapEntry` is not `Clone` in P01 by design (deriving `Clone` would
/// widen its public surface). We reconstruct a fresh struct literal here
/// rather than returning `&MapEntry`, because `find_arena_mapping` owns the
/// `Vec<MapEntry>` from `parse_maps` and a borrowed return would tie the
/// caller to that vec's lifetime.
#[allow(dead_code)] // consumed by T3 seal_arena orchestrator next session
fn find_arena_mapping_in(entries: &[MapEntry], arena_path: &Path) -> Result<MapEntry> {
    for entry in entries {
        if entry.path.as_deref() == Some(arena_path) && entry.perms.starts_with(b"rw") {
            return Ok(MapEntry {
                start: entry.start,
                end: entry.end,
                perms: entry.perms,
                offset: entry.offset,
                path: entry.path.clone(),
            });
        }
    }
    Err(Error::ArenaNotMapped(arena_path.to_path_buf()))
}

/// Locate init's writable mapping of `arena_path` in `/proc/<pid>/maps`.
#[allow(dead_code)] // consumed by T3 seal_arena orchestrator next session
pub(crate) fn find_arena_mapping(pid: libc::pid_t, arena_path: &Path) -> Result<MapEntry> {
    let entries = parse_maps(pid)?;
    find_arena_mapping_in(&entries, arena_path)
}

/// AArch64 `nop` instruction encoding: `d503201f` little-endian bytes
/// `[0x1f, 0x20, 0x03, 0xd5]`. Source: ARM ARM C6.2.203.
#[allow(dead_code)] // consumed by T3 seal_arena orchestrator next session
pub(crate) const ARM64_NOP: u32 = 0xd503_201f;

/// Scan `bytes` for the first 8-byte-aligned offset where at least four
/// consecutive `ARM64_NOP` words (16 bytes) appear.
///
/// Returns the offset into `bytes`. Callers add it to the mapping's start
/// address to get a scratch PC that is (a) inside an executable mapping,
/// (b) inside a benign nop run so restoring the original bytes after the
/// bootstrap `svc+brk` is trivial, and (c) 8-byte aligned so a two-word
/// blob writes atomically via a single PTRACE_POKEDATA.
///
/// Returns `None` if no qualifying run exists in `bytes`. The caller surfaces
/// this as `Error::HookInstallFailed` because the absence of a NOP slide in
/// init's libc.text is an environment failure, not a programming error.
#[allow(dead_code)] // consumed by T3 seal_arena orchestrator next session
pub(crate) fn find_nop_slide(bytes: &[u8]) -> Option<usize> {
    const NOP_BYTES: [u8; 4] = ARM64_NOP.to_le_bytes();
    if bytes.len() < 16 {
        return None;
    }
    let mut off = 0;
    while off + 16 <= bytes.len() {
        if off % 8 == 0
            && bytes[off..off + 4] == NOP_BYTES
            && bytes[off + 4..off + 8] == NOP_BYTES
            && bytes[off + 8..off + 12] == NOP_BYTES
            && bytes[off + 12..off + 16] == NOP_BYTES
        {
            return Some(off);
        }
        off += 4; // ARM64 instruction stride; 8-byte alignment filter applied above
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn mk(path: &str, perms: &[u8; 4], start: u64) -> MapEntry {
        MapEntry {
            start,
            end: start + 0x1000,
            perms: *perms,
            offset: 0,
            path: Some(PathBuf::from(path)),
        }
    }

    #[test]
    fn find_arena_mapping_picks_rw_view() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![
            mk(arena.to_str().unwrap(), b"r-xp", 0x1000),
            mk(arena.to_str().unwrap(), b"rw-p", 0xdead_0000),
        ];
        let hit = find_arena_mapping_in(&entries, arena).expect("rw match expected");
        assert!(hit.perms.starts_with(b"rw"));
        assert_eq!(hit.start, 0xdead_0000);
    }

    #[test]
    fn find_arena_mapping_rejects_ro_only_fixture() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![mk(arena.to_str().unwrap(), b"r-xp", 0x1000)];
        match find_arena_mapping_in(&entries, arena) {
            Err(Error::ArenaNotMapped(p)) => assert_eq!(p, arena.to_path_buf()),
            other => panic!("expected ArenaNotMapped, got {other:?}"),
        }
    }

    #[test]
    fn find_arena_mapping_returns_not_mapped_on_miss() {
        let arena = Path::new("/dev/__properties__/u:object_r:telephony_prop:s0");
        let entries = vec![
            mk("/some/other/file", b"rw-p", 0x1000),
            mk("/another/unrelated", b"rw-p", 0x2000),
        ];
        match find_arena_mapping_in(&entries, arena) {
            Err(Error::ArenaNotMapped(p)) => assert_eq!(p, arena.to_path_buf()),
            other => panic!("expected ArenaNotMapped, got {other:?}"),
        }
    }

    /// Build a byte buffer with `n` consecutive ARM64_NOP words at `offset`.
    fn with_nop_run(prefix_len: usize, nop_words: usize, suffix_len: usize) -> Vec<u8> {
        let nop = ARM64_NOP.to_le_bytes();
        let mut buf = vec![0xFFu8; prefix_len];
        for _ in 0..nop_words {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, suffix_len));
        buf
    }

    #[test]
    fn find_nop_slide_locates_first_aligned_run() {
        // 32 bytes of 0xFF, then 4 NOP words (16 bytes), then 16 bytes of 0xFF.
        // First qualifying 8-byte-aligned 4-NOP run starts at offset 32.
        let buf = with_nop_run(32, 4, 16);
        assert_eq!(find_nop_slide(&buf), Some(32));
    }

    #[test]
    fn find_nop_slide_returns_none_when_no_run_exists() {
        let buf = vec![0xFFu8; 64];
        assert!(find_nop_slide(&buf).is_none());
    }

    #[test]
    fn find_nop_slide_prefers_aligned_run_over_earlier_unaligned() {
        // Layout: [4 bytes 0xFF][4 NOPs at offset 4 — UNALIGNED][12 bytes 0xFF]
        //         [4 NOPs at offset 32 — ALIGNED][trailing 0xFF]
        // The unaligned run must be skipped; the aligned run at 32 wins.
        let nop = ARM64_NOP.to_le_bytes();
        let mut buf = vec![0xFFu8; 4];
        for _ in 0..4 {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, 12));
        assert_eq!(buf.len(), 32);
        for _ in 0..4 {
            buf.extend_from_slice(&nop);
        }
        buf.extend(std::iter::repeat_n(0xFFu8, 16));
        assert_eq!(find_nop_slide(&buf), Some(32));
    }
}
