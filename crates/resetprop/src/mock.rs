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

        assert!(area.get("ro.lineage.version").is_none());

        let mut found = None;
        area.foreach(|_, v| found = Some(v.to_string()));
        assert_eq!(found.unwrap(), "0");
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

    #[test]
    fn hexpatch_name_consistency() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.custom.feature", "enabled").unwrap();
        area.hexpatch_delete("ro.custom.feature").unwrap();

        // foreach should find exactly one renamed prop
        let mut props = Vec::new();
        area.foreach(|n, v| props.push((n.to_string(), v.to_string())));
        assert_eq!(props.len(), 1);

        let (mangled_name, _) = &props[0];
        assert_ne!(mangled_name, "ro.custom.feature");

        // trie lookup for the mangled name should resolve (trie and prop_info agree)
        let val = area.get(mangled_name);
        assert!(val.is_some(), "trie lookup for mangled name '{}' failed", mangled_name);
    }

    #[test]
    fn hexpatch_plausible_value() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.test.stealth", "secret").unwrap();
        area.hexpatch_delete("ro.test.stealth").unwrap();

        let mut found_value = None;
        area.foreach(|_, v| found_value = Some(v.to_string()));

        assert_eq!(found_value.unwrap(), "0");
    }

    #[test]
    fn harvest_pool_picks_from_area() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("vendor.thermal.monitor", "1").unwrap();
        area.set("vendor.display.config", "0").unwrap();

        let pool = crate::harvest::SegmentPool::from_area(&area);
        let used = std::collections::HashSet::new();

        let pick = pool.pick(7, &used);
        assert!(pick.is_some());
        let word = pick.unwrap();
        assert_eq!(word.len(), 7);
        // should be one of the 7-char segments from our area: "thermal", "display", "monitor", "config" (6 != 7)
        let valid = [b"thermal".to_vec(), b"display".to_vec(), b"monitor".to_vec()];
        assert!(valid.contains(&word), "unexpected pick: {:?}", String::from_utf8_lossy(&word));
    }

    #[test]
    fn compound_exact_length() {
        let used = std::collections::HashSet::new();
        for target_len in [1, 2, 3, 5, 10, 13, 15, 20, 25, 30, 50] {
            let result = crate::harvest::compound_generate(target_len, &used);
            assert_eq!(
                result.len(),
                target_len,
                "compound_generate({}) produced {} bytes: {:?}",
                target_len,
                result.len(),
                String::from_utf8_lossy(&result),
            );
        }
    }

    #[test]
    fn hexpatch_sequential_multiple_props() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.build.type", "user").unwrap();
        area.set("ro.lineage.version", "18.1").unwrap();
        area.set("ro.custom.romname", "test").unwrap();
        area.set("ro.debuggable", "1").unwrap();

        let before_count = {
            let mut c = 0;
            area.foreach(|_, _| c += 1);
            c
        };

        area.hexpatch_delete("ro.lineage.version").unwrap();
        area.hexpatch_delete("ro.custom.romname").unwrap();
        area.hexpatch_delete("ro.debuggable").unwrap();

        assert_eq!(area.get("ro.build.type").unwrap(), "user");
        assert!(area.get("ro.lineage.version").is_none());
        assert!(area.get("ro.custom.romname").is_none());
        assert!(area.get("ro.debuggable").is_none());

        let after_count = {
            let mut c = 0;
            area.foreach(|_, _| c += 1);
            c
        };
        assert_eq!(before_count, after_count, "prop count changed after hexpatch");
    }

    #[test]
    fn hexpatch_lone_prop_in_area() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.single.prop", "alone").unwrap();
        let ok = area.hexpatch_delete("ro.single.prop").unwrap();
        assert!(ok);
        assert!(area.get("ro.single.prop").is_none());

        let mut props = Vec::new();
        area.foreach(|n, v| props.push((n.to_string(), v.to_string())));
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].1, "0");

        // trie must still resolve the mangled name
        assert!(area.get(&props[0].0).is_some());
    }

    #[test]
    fn hexpatch_deep_path() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("a.bb.ccc.dddd.eeeee", "deep").unwrap();
        area.hexpatch_delete("a.bb.ccc.dddd.eeeee").unwrap();

        assert!(area.get("a.bb.ccc.dddd.eeeee").is_none());

        let mut props = Vec::new();
        area.foreach(|n, v| props.push((n.to_string(), v.to_string())));
        assert_eq!(props.len(), 1);

        let segments: Vec<&str> = props[0].0.split('.').collect();
        assert_eq!(segments.len(), 5);
        assert_eq!(segments[0].len(), 1);
        assert_eq!(segments[1].len(), 2);
        assert_eq!(segments[2].len(), 3);
        assert_eq!(segments[3].len(), 4);
        assert_eq!(segments[4].len(), 5);

        assert!(area.get(&props[0].0).is_some());
    }

    #[test]
    fn hexpatch_very_long_segment() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.customromverylongsegment.x", "v").unwrap();
        area.hexpatch_delete("ro.customromverylongsegment.x").unwrap();

        let mut props = Vec::new();
        area.foreach(|n, _| props.push(n.to_string()));
        assert_eq!(props.len(), 1);

        let segments: Vec<&str> = props[0].split('.').collect();
        // "customromverylongsegment" is 24 chars — tests compound generator territory
        assert_eq!(segments[1].len(), 24);
        assert!(area.get(&props[0]).is_some());
    }

    #[test]
    fn hexpatch_same_prop_twice() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.test.prop", "val").unwrap();
        assert!(area.hexpatch_delete("ro.test.prop").unwrap());
        assert!(!area.hexpatch_delete("ro.test.prop").unwrap());
    }

    #[test]
    fn hexpatch_duplicate_length_segments() {
        let mock = MockArea::new();
        let area = mock.open();

        // all leaf segments are 4 chars — tests collision avoidance within same path
        area.set("ro.abcd.efgh.ijkl", "val").unwrap();
        area.hexpatch_delete("ro.abcd.efgh.ijkl").unwrap();

        let mut props = Vec::new();
        area.foreach(|n, _| props.push(n.to_string()));
        assert_eq!(props.len(), 1);

        let segments: Vec<&str> = props[0].split('.').collect();
        // all non-shared 4-char segments must be different from each other
        let mut seen = std::collections::HashSet::new();
        for seg in &segments[1..] {
            assert_eq!(seg.len(), 4);
            assert!(seen.insert(*seg), "duplicate segment '{}' in mangled name", seg);
        }

        assert!(area.get(&props[0]).is_some());
    }

    #[test]
    fn hexpatch_serial_preserved() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.serial.test", "original").unwrap();

        // read raw serial before hexpatch via a get (serial encodes length in top byte)
        let (pi_off, _) = crate::trie::find(&area, "ro.serial.test").unwrap();
        let serial_before = area.atomic_u32(pi_off).load(std::sync::atomic::Ordering::Relaxed);
        // counter bits (1-15, 17-23) should be 0 for a freshly created prop
        let counter_before = serial_before & 0x00FE_FFFE;
        assert_eq!(counter_before, 0, "counter non-zero before hexpatch");

        area.hexpatch_delete("ro.serial.test").unwrap();

        // find the prop by its new name
        let mut mangled = String::new();
        area.foreach(|n, _| mangled = n.to_string());

        let (pi_off_after, _) = crate::trie::find(&area, &mangled).unwrap();
        assert_eq!(pi_off, pi_off_after, "prop_info moved after hexpatch");

        let serial_after = area.atomic_u32(pi_off).load(std::sync::atomic::Ordering::Relaxed);
        let counter_after = serial_after & 0x00FE_FFFE;
        assert_eq!(counter_after, 0, "counter bumped by stealth_write_value");

        let length_byte = (serial_after >> 24) & 0xFF;
        assert_eq!(length_byte, 1, "length byte should be 1 for value '0'");

        let dirty = serial_after & 1;
        assert_eq!(dirty, 0, "dirty bit set after stealth_write_value");

        let long_flag = serial_after & (1 << 16);
        assert_eq!(long_flag, 0, "kLongFlag set after stealth_write_value");
    }

    #[test]
    fn hexpatch_many_siblings_bst_integrity() {
        let mock = MockArea::new();
        let area = mock.open();

        let siblings = [
            "ro.build.type", "ro.build.tags", "ro.build.date",
            "ro.build.host", "ro.build.user", "ro.build.keys",
            "ro.lineage.version", "ro.custom.rom",
        ];
        for &prop in &siblings {
            area.set(prop, "test").unwrap();
        }

        area.hexpatch_delete("ro.lineage.version").unwrap();
        area.hexpatch_delete("ro.custom.rom").unwrap();

        // ALL ro.build.* siblings must still be accessible via trie lookup
        for &prop in &siblings[..6] {
            assert_eq!(
                area.get(prop).unwrap(), "test",
                "BST corrupted: {} not found after hexpatch", prop
            );
        }

        let mut count = 0;
        area.foreach(|_, _| count += 1);
        assert_eq!(count, siblings.len());
    }

    #[test]
    fn hexpatch_all_names_valid_ascii() {
        let mock = MockArea::new();
        let area = mock.open();

        area.set("ro.test.stealth", "val").unwrap();
        area.set("ro.vendor.camera", "1").unwrap();
        area.hexpatch_delete("ro.test.stealth").unwrap();

        area.foreach(|name, _| {
            for b in name.bytes() {
                assert!(
                    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-',
                    "invalid byte 0x{:02x} in mangled name '{}'", b, name,
                );
            }
            assert!(!name.starts_with('.'));
            assert!(!name.ends_with('.'));
            assert!(!name.contains(".."));
        });
    }
}
