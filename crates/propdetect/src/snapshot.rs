use std::collections::BTreeMap;
use std::path::Path;

use resetprop::PropSystem;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub props: BTreeMap<String, PropValue>,
    pub total_count: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PropValue {
    pub value: String,
    pub serial: u32,
}

pub struct DiffEntry {
    pub name: String,
    pub kind: DiffKind,
}

pub enum DiffKind {
    Added { value: String },
    Removed { value: String },
    Changed { old: String, new: String },
    SerialChanged { old: u32, new: u32 },
}

pub fn capture(sys: &PropSystem) -> Snapshot {
    let mut props = BTreeMap::new();

    for (_, area) in sys.areas() {
        for entry in area.inspect_props() {
            props.insert(
                entry.name,
                PropValue {
                    value: entry.value,
                    serial: entry.serial,
                },
            );
        }
    }

    let total_count = props.len();
    Snapshot { props, total_count }
}

pub fn save(snapshot: &Snapshot, path: &Path) -> Result<(), String> {
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("write {}: {e}", path.display()))
}

pub fn load(path: &Path) -> Result<Snapshot, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    serde_json::from_str(&data).map_err(|e| format!("parse {}: {e}", path.display()))
}

pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<DiffEntry> {
    let mut entries = Vec::new();

    for (name, old) in &before.props {
        match after.props.get(name) {
            None => entries.push(DiffEntry {
                name: name.clone(),
                kind: DiffKind::Removed {
                    value: old.value.clone(),
                },
            }),
            Some(new) => {
                if old.value != new.value {
                    entries.push(DiffEntry {
                        name: name.clone(),
                        kind: DiffKind::Changed {
                            old: old.value.clone(),
                            new: new.value.clone(),
                        },
                    });
                } else if old.serial != new.serial {
                    entries.push(DiffEntry {
                        name: name.clone(),
                        kind: DiffKind::SerialChanged {
                            old: old.serial,
                            new: new.serial,
                        },
                    });
                }
            }
        }
    }

    for (name, new) in &after.props {
        if !before.props.contains_key(name) {
            entries.push(DiffEntry {
                name: name.clone(),
                kind: DiffKind::Added {
                    value: new.value.clone(),
                },
            });
        }
    }

    entries
}
