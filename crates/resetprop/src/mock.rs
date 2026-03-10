use std::path::{Path, PathBuf};

use crate::area::PropArea;

const PROP_AREA_MAGIC: u32 = 0x504f5250;
const PROP_AREA_VERSION: u32 = 0xfc6ed0ab;
const AREA_SIZE: usize = 128 * 1024; // 128KB, same as real Android

pub struct MockArea {
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl MockArea {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("mock_props");
        create_empty_area(&path);
        Self { path, _dir: dir }
    }

    pub fn open(&self) -> PropArea {
        PropArea::open(&self.path).expect("open mock area")
    }

    pub fn open_ro(&self) -> PropArea {
        PropArea::open_ro(&self.path).expect("open_ro mock area")
    }

    #[allow(dead_code)]
    pub fn dir(&self) -> &Path {
        self._dir.path()
    }
}

fn create_empty_area(path: &Path) {
    let mut buf = vec![0u8; AREA_SIZE];

    // root trie node: namelen=0, 20 fixed bytes + 1 null + 3 pad = 24 bytes
    let root_size: u32 = 24;
    buf[0..4].copy_from_slice(&root_size.to_ne_bytes());
    buf[8..12].copy_from_slice(&PROP_AREA_MAGIC.to_ne_bytes());
    buf[12..16].copy_from_slice(&PROP_AREA_VERSION.to_ne_bytes());

    std::fs::write(path, &buf).expect("write mock area");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_nonexistent_returns_none() {
        let mock = MockArea::new();
        let area = mock.open();
        assert!(area.get("no.such.prop").is_none());
    }

    #[test]
    fn set_then_get() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.test.name", "hello").unwrap();
        assert_eq!(area.get("ro.test.name").unwrap(), "hello");
    }

    #[test]
    fn set_overwrite() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("test.val", "first").unwrap();
        area.set("test.val", "second").unwrap();
        assert_eq!(area.get("test.val").unwrap(), "second");
    }

    #[test]
    fn delete_existing() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("to.delete", "gone").unwrap();
        assert!(area.get("to.delete").is_some());

        let ok = area.delete("to.delete").unwrap();
        assert!(ok);
        assert!(area.get("to.delete").is_none());
    }

    #[test]
    fn delete_nonexistent() {
        let mock = MockArea::new();
        let area = mock.open();
        assert!(!area.delete("no.such.prop").unwrap());
    }

    #[test]
    fn hexpatch_delete() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.lineage.version", "18.1").unwrap();
        assert!(area.get("ro.lineage.version").is_some());

        let ok = area.hexpatch_delete("ro.lineage.version").unwrap();
        assert!(ok);

        // original name should be gone
        assert!(area.get("ro.lineage.version").is_none());
    }

    #[test]
    fn list_all() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("a.b", "1").unwrap();
        area.set("c.d", "2").unwrap();
        area.set("e.f", "3").unwrap();

        let mut props: Vec<(String, String)> = Vec::new();
        area.foreach(|n, v| props.push((n.to_string(), v.to_string())));
        assert_eq!(props.len(), 3);

        let names: Vec<&str> = props.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"a.b"));
        assert!(names.contains(&"c.d"));
        assert!(names.contains(&"e.f"));
    }

    #[test]
    fn foreach_visits_all() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("x.y", "10").unwrap();
        area.set("x.z", "20").unwrap();

        let mut count = 0;
        area.foreach(|_, _| count += 1);
        assert_eq!(count, 2);
    }

    #[test]
    fn readonly_rejects_write() {
        let mock = MockArea::new();
        let ro = mock.open_ro();

        let result = ro.set("ro.test", "fail");
        assert!(result.is_err());
    }

    #[test]
    fn dotted_name_segments() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("a.b.c.d", "deep").unwrap();
        assert_eq!(area.get("a.b.c.d").unwrap(), "deep");

        // partial paths should not exist
        assert!(area.get("a.b.c").is_none());
        assert!(area.get("a.b").is_none());
    }

    #[test]
    fn empty_value() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("empty.val", "").unwrap();
        assert_eq!(area.get("empty.val").unwrap(), "");
    }

    #[test]
    fn max_short_value() {
        let mock = MockArea::new();
        let area = mock.open();

        let val = "x".repeat(91); // max short = 91 (PROP_VALUE_MAX - 1)
        area.set("max.short", &val).unwrap();
        assert_eq!(area.get("max.short").unwrap(), val);
    }

    #[test]
    fn value_too_long() {
        let mock = MockArea::new();
        let area = mock.open();

        let val = "x".repeat(92); // >= PROP_VALUE_MAX
        let result = area.set("too.long", &val);
        assert!(result.is_err());
    }

    #[test]
    fn multiple_props_same_prefix() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.build.type", "user").unwrap();
        area.set("ro.build.tags", "release-keys").unwrap();
        area.set("ro.build.flavor", "raven-user").unwrap();

        assert_eq!(area.get("ro.build.type").unwrap(), "user");
        assert_eq!(area.get("ro.build.tags").unwrap(), "release-keys");
        assert_eq!(area.get("ro.build.flavor").unwrap(), "raven-user");
    }

    #[test]
    fn hexpatch_preserves_siblings() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.build.type", "user").unwrap();
        area.set("ro.lineage.version", "18.1").unwrap();

        area.hexpatch_delete("ro.lineage.version").unwrap();

        // sibling under "ro" should survive
        assert_eq!(area.get("ro.build.type").unwrap(), "user");
    }

    #[test]
    fn open_invalid_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage");
        std::fs::write(&path, b"not a property area").unwrap();

        assert!(PropArea::open(&path).is_err());
    }
}
