use std::path::PathBuf;

use resetprop::PropArea;

fn mock_area() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mock_props");

    let mut buf = vec![0u8; 128 * 1024];
    let root_size: u32 = 20;
    buf[0..4].copy_from_slice(&root_size.to_ne_bytes());
    buf[8..12].copy_from_slice(&0x504f5250u32.to_ne_bytes());
    buf[12..16].copy_from_slice(&0xfc6ed0abu32.to_ne_bytes());
    std::fs::write(&path, &buf).unwrap();

    (dir, path)
}

fn populate_realistic(area: &PropArea) {
    let props = [
        ("ro.build.type", "user"),
        ("ro.build.tags", "release-keys"),
        ("ro.build.flavor", "raven-user"),
        ("ro.build.display.id", "TP1A.220624.014"),
        ("ro.build.fingerprint", "google/raven/raven:12/TP1A/8734"),
        ("ro.hardware", "tensor"),
        ("ro.debuggable", "0"),
        ("ro.secure", "1"),
        ("persist.sys.timezone", "America/New_York"),
        ("persist.sys.language", "en"),
        ("dalvik.vm.heapsize", "512m"),
        ("gsm.operator.alpha", "T-Mobile"),
        ("net.dns1", "8.8.8.8"),
        ("wifi.interface", "wlan0"),
        ("ro.lineage.version", "19.1-raven"),
        ("ro.custom.romname", "PixelExperience"),
        ("vendor.display.brightness", "128"),
        ("vendor.audio.policy", "default"),
    ];
    for (k, v) in props {
        area.set(k, v).unwrap();
    }
}

fn areas_from(path: &PathBuf) -> Vec<(PathBuf, PropArea)> {
    vec![(path.clone(), PropArea::open(path).unwrap())]
}

#[test]
fn detect_hexpatch_delete() {
    let (_dir, path) = mock_area();
    let area = PropArea::open(&path).unwrap();
    populate_realistic(&area);

    let before_count = count_props(&area);
    area.hexpatch_delete("ro.lineage.version").unwrap();
    area.hexpatch_delete("ro.custom.romname").unwrap();
    let after_count = count_props(&area);

    assert_eq!(before_count, after_count, "hexpatch must preserve count");

    let entries = area.inspect_props();
    let areas = areas_from(&path);

    let name_findings = propdetect_heuristics::check_orphan_names(&entries);
    let value_findings = propdetect_heuristics::check_value_anomaly(&entries);
    let serial_findings = propdetect_heuristics::check_serial(&entries);
    let coherence_findings = propdetect_heuristics::check_name_coherence(&areas);

    println!("\n=== HEXPATCH DETECTION RESULTS ===");
    for f in name_findings.iter().chain(&value_findings).chain(&serial_findings).chain(&coherence_findings) {
        println!("[{}] {}: {}", f.severity, f.check, f.detail);
    }

    // value_anomaly should catch the stealth "0" values
    assert!(!value_findings.is_empty(),
        "value_anomaly should flag hexpatch stealth values");

    // name_coherence should show NO mismatches (hexpatch renames both trie + prop_info)
    assert!(coherence_findings.is_empty(),
        "hexpatch should maintain trie/prop_info name consistency");

    // the original names must be gone
    assert!(area.get("ro.lineage.version").is_none());
    assert!(area.get("ro.custom.romname").is_none());
}

#[test]
fn detect_plain_delete() {
    let (_dir, path) = mock_area();
    let area = PropArea::open(&path).unwrap();
    populate_realistic(&area);

    let before_count = count_props(&area);
    area.delete("ro.lineage.version").unwrap();
    area.delete("ro.custom.romname").unwrap();
    let after_count = count_props(&area);

    assert_eq!(before_count - 2, after_count, "plain delete removes from enumeration");

    let areas = areas_from(&path);

    let count_findings = propdetect_heuristics::check_count(after_count);
    let trie_findings = propdetect_heuristics::check_trie_structure(&areas);

    println!("\n=== PLAIN DELETE DETECTION RESULTS ===");
    for f in count_findings.iter().chain(&trie_findings) {
        println!("[{}] {}: {}", f.severity, f.check, f.detail);
    }

    // trie_structure should detect orphan nodes left behind by delete
    let orphan_hits: Vec<_> = trie_findings.iter()
        .filter(|f| f.detail.contains("orphan"))
        .collect();
    println!("orphan findings: {}", orphan_hits.len());

    // property count dropped
    assert!(after_count < before_count);
}

#[test]
fn snapshot_diff_catches_hexpatch() {
    let (_dir, path) = mock_area();
    let area = PropArea::open(&path).unwrap();
    populate_realistic(&area);
    drop(area);

    let sys_before = resetprop::PropSystem::open_dir(_dir.path()).unwrap();
    let snap_before = propdetect_snapshot::capture(&sys_before);
    drop(sys_before);

    let area = PropArea::open(&path).unwrap();
    area.hexpatch_delete("ro.lineage.version").unwrap();
    drop(area);

    let sys_after = resetprop::PropSystem::open_dir(_dir.path()).unwrap();
    let snap_after = propdetect_snapshot::capture(&sys_after);

    let diffs = propdetect_snapshot::diff(&snap_before, &snap_after);

    println!("\n=== SNAPSHOT DIFF (HEXPATCH) ===");
    let mut removed = Vec::new();
    let mut added = Vec::new();
    for d in &diffs {
        match &d.kind {
            propdetect_snapshot::DiffKind::Removed { value } => {
                println!("- [{}] = {value}", d.name);
                removed.push(d.name.clone());
            }
            propdetect_snapshot::DiffKind::Added { value } => {
                println!("+ [{}] = {value}", d.name);
                added.push(d.name.clone());
            }
            propdetect_snapshot::DiffKind::Changed { old, new } => {
                println!("~ [{}] {old} -> {new}", d.name);
            }
            propdetect_snapshot::DiffKind::SerialChanged { old, new } => {
                println!("s [{}] {old:#x} -> {new:#x}", d.name);
            }
        }
    }

    // hexpatch: original name disappears, new name appears
    assert!(removed.contains(&"ro.lineage.version".to_string()),
        "original prop name should show as removed in diff");
    assert_eq!(added.len(), 1,
        "exactly one new prop name should appear (the renamed one)");

    // the added prop should have value "0"
    let added_entry = diffs.iter()
        .find(|d| matches!(d.kind, propdetect_snapshot::DiffKind::Added { .. }))
        .unwrap();
    if let propdetect_snapshot::DiffKind::Added { value } = &added_entry.kind {
        assert_eq!(value, "0", "hexpatch replacement should have value '0'");
    }

    // total count should be unchanged
    assert_eq!(snap_before.total_count, snap_after.total_count,
        "hexpatch must not change total property count");
}

#[test]
fn snapshot_diff_catches_plain_delete() {
    let (_dir, path) = mock_area();
    let area = PropArea::open(&path).unwrap();
    populate_realistic(&area);
    drop(area);

    let sys_before = resetprop::PropSystem::open_dir(_dir.path()).unwrap();
    let snap_before = propdetect_snapshot::capture(&sys_before);
    drop(sys_before);

    let area = PropArea::open(&path).unwrap();
    area.delete("ro.lineage.version").unwrap();
    drop(area);

    let sys_after = resetprop::PropSystem::open_dir(_dir.path()).unwrap();
    let snap_after = propdetect_snapshot::capture(&sys_after);

    let diffs = propdetect_snapshot::diff(&snap_before, &snap_after);

    println!("\n=== SNAPSHOT DIFF (PLAIN DELETE) ===");
    for d in &diffs {
        match &d.kind {
            propdetect_snapshot::DiffKind::Removed { value } => println!("- [{}] = {value}", d.name),
            propdetect_snapshot::DiffKind::Added { value } => println!("+ [{}] = {value}", d.name),
            _ => {}
        }
    }

    let removed: Vec<_> = diffs.iter()
        .filter(|d| matches!(d.kind, propdetect_snapshot::DiffKind::Removed { .. }))
        .map(|d| d.name.clone())
        .collect();
    let added: Vec<_> = diffs.iter()
        .filter(|d| matches!(d.kind, propdetect_snapshot::DiffKind::Added { .. }))
        .collect();

    assert!(removed.contains(&"ro.lineage.version".to_string()));
    assert!(added.is_empty(), "plain delete should not add any properties");
    assert_eq!(snap_after.total_count, snap_before.total_count - 1);
}

#[test]
fn delete_compact_leaves_no_orphans() {
    let (_dir, path) = mock_area();
    let area = PropArea::open(&path).unwrap();
    populate_realistic(&area);

    area.delete("ro.lineage.version").unwrap();
    area.delete("ro.custom.romname").unwrap();
    area.compact().unwrap();

    let areas = areas_from(&path);
    let trie_findings = propdetect_heuristics::check_trie_structure(&areas);

    let orphan_hits: Vec<_> = trie_findings.iter()
        .filter(|f| f.detail.contains("orphan"))
        .collect();
    assert!(orphan_hits.is_empty(),
        "found {} orphan findings after delete+compact", orphan_hits.len());
}

fn count_props(area: &PropArea) -> usize {
    let mut c = 0;
    area.foreach(|_, _| c += 1);
    c
}

mod propdetect_heuristics {
    pub use propdetect::heuristics::*;
}

mod propdetect_snapshot {
    pub use propdetect::snapshot::*;
}
