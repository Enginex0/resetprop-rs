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
}
