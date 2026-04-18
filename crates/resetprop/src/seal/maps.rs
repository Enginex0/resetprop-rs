//! `/proc/<pid>/maps` line parser for the seal feature.
//!
//! Consumed by P02 (Tier A arena lookup in `/proc/1/maps`) and P03 (libc.so
//! base-address lookup for ELF parsing). The parser reads the entire maps
//! file in a single `std::fs::read_to_string` call — the kernel snapshots
//! the VMA list on open so partial reads are safe, and maps files for init
//! are on the order of a few hundred KiB in practice.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A single `/proc/<pid>/maps` entry.
///
/// Field layout locked by REGISTRY §1 via P01 spec §Tasks T2 / FR-13.
#[derive(Debug)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: [u8; 4],
    pub offset: u64,
    pub path: Option<PathBuf>,
}

/// Parse `/proc/<pid>/maps` into a flat `Vec<MapEntry>`.
///
/// Failures reading the file propagate through the existing
/// `From<std::io::Error> for Error` impl (`error.rs:61-68`), mapping EACCES /
/// EPERM to `Error::PermissionDenied` and everything else to `Error::Io`.
/// Malformed lines — bad hex, missing columns — surface as
/// `Error::AreaCorrupt` citing the source path and offending token.
pub fn parse_maps(pid: libc::pid_t) -> Result<Vec<MapEntry>> {
    let path = format!("/proc/{pid}/maps");
    let contents = std::fs::read_to_string(&path)?;
    let mut out = Vec::new();
    for line in contents.lines() {
        if let Some(entry) = parse_line(line, pid)? {
            out.push(entry);
        }
    }
    Ok(out)
}

/// Exact-path lookup helper used by P02 (arena file) and P03 (libc.so).
pub fn find_by_path<'a>(entries: &'a [MapEntry], path: &Path) -> Option<&'a MapEntry> {
    entries.iter().find(|e| e.path.as_deref() == Some(path))
}

/// Parse a single maps line. Returns `Ok(None)` for empty/whitespace-only lines.
/// Exposed to the in-file test module only.
pub(super) fn parse_line(line: &str, pid: libc::pid_t) -> Result<Option<MapEntry>> {
    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let corrupt = |detail: &str| -> Error {
        Error::AreaCorrupt(format!("/proc/{pid}/maps: {detail}"))
    };

    // Columns: ADDR perms offset dev inode [path]. Split on exactly the first
    // five single-space separators so any spaces inside the path column
    // (kernel writes raw spaces for some unusual paths — see the
    // `seq_path_root` call in `fs/proc/task_mmu.c`) survive verbatim.
    let mut it = trimmed.splitn(6, ' ');

    let addr = it.next().ok_or_else(|| corrupt("missing address column"))?;
    let perms_tok = it.next().ok_or_else(|| corrupt("missing perms column"))?;
    let offset_tok = it.next().ok_or_else(|| corrupt("missing offset column"))?;
    let _dev = it.next().ok_or_else(|| corrupt("missing dev column"))?;
    let _inode = it.next().ok_or_else(|| corrupt("missing inode column"))?;

    let (start_s, end_s) = addr
        .split_once('-')
        .ok_or_else(|| corrupt("address column missing '-' separator"))?;
    let start = u64::from_str_radix(start_s, 16)
        .map_err(|_| corrupt(&format!("invalid start address '{start_s}'")))?;
    let end = u64::from_str_radix(end_s, 16)
        .map_err(|_| corrupt(&format!("invalid end address '{end_s}'")))?;

    if perms_tok.len() != 4 {
        return Err(corrupt(&format!("perms column is not 4 bytes: '{perms_tok}'")));
    }
    let mut perms = [0u8; 4];
    perms.copy_from_slice(perms_tok.as_bytes());

    let offset = u64::from_str_radix(offset_tok, 16)
        .map_err(|_| corrupt(&format!("invalid offset '{offset_tok}'")))?;

    // Path column is the raw remainder after the inode. The kernel pads the
    // inode column with spaces for alignment (see `show_map_vma`), so the
    // raw remainder may start with one or more spaces — trim leading
    // whitespace, then preserve any interior whitespace verbatim.
    //
    // Strip the kernel's unlinked-file marker (see fs/proc/task_mmu.c
    // `show_map_vma` — it appends " (deleted)" to any VMA whose backing
    // dentry has been unlinked). Only this exact 10-byte suffix is
    // stripped; `[vdso]`, `[stack]`, `[heap]` stay verbatim.
    let path = match it.next() {
        None => None,
        Some(raw) => {
            let trimmed_path = raw.trim_start();
            if trimmed_path.is_empty() {
                None
            } else {
                const DELETED: &str = " (deleted)";
                let cleaned = trimmed_path.strip_suffix(DELETED).unwrap_or(trimmed_path);
                Some(PathBuf::from(cleaned))
            }
        }
    };

    Ok(Some(MapEntry {
        start,
        end,
        perms,
        offset,
        path,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maps_parse_minimal_line() {
        let line = "55a8b0000000-55a8b0002000 r-xp 00000000 fd:01 12345";
        let entry = parse_line(line, 1234).unwrap().expect("line should parse");
        assert_eq!(entry.start, 0x55a8_b000_0000);
        assert_eq!(entry.end, 0x55a8_b000_2000);
        assert_eq!(entry.perms, *b"r-xp");
        assert_eq!(entry.offset, 0);
        assert!(entry.path.is_none());
    }

    #[test]
    fn test_maps_parse_deleted_suffix() {
        let line = "7f0000000000-7f0000001000 rw-p 00000000 fd:01 23456 /tmp/foo (deleted)";
        let entry = parse_line(line, 1234).unwrap().expect("line should parse");
        assert_eq!(entry.path.as_deref(), Some(Path::new("/tmp/foo")));
    }

    #[test]
    fn test_maps_find_by_path_matches() {
        let entries = vec![
            MapEntry {
                start: 0x1000,
                end: 0x2000,
                perms: *b"r-xp",
                offset: 0,
                path: Some(PathBuf::from("/other")),
            },
            MapEntry {
                start: 0xdead_0000,
                end: 0xdead_1000,
                perms: *b"rw-p",
                offset: 0,
                path: Some(PathBuf::from("/target")),
            },
        ];
        let hit = find_by_path(&entries, Path::new("/target")).expect("should find /target");
        assert_eq!(hit.start, 0xdead_0000);
    }
}
