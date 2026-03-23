pub(crate) mod proto;
mod io;

use std::path::{Path, PathBuf};

use crate::Result;
pub use proto::Record;

const DEFAULT_DIR: &str = "/data/property";

/// Reads and writes Android's on-disk persistent property store at `/data/property/`.
///
/// Supports both the modern protobuf format and the legacy one-file-per-property layout.
pub struct PersistStore {
    dir: PathBuf,
    records: Vec<Record>,
}

impl PersistStore {
    pub fn load() -> Result<Self> {
        Self::load_dir(Path::new(DEFAULT_DIR))
    }

    pub fn load_dir(dir: &Path) -> Result<Self> {
        let records = if io::is_protobuf(dir) {
            let data = io::read_file(dir)?;
            if data.is_empty() {
                Vec::new()
            } else {
                proto::decode(&data)?
            }
        } else {
            load_legacy(dir)
        };
        Ok(Self { dir: dir.to_path_buf(), records })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.records.iter()
            .find(|r| r.name == name)
            .map(|r| r.value.as_str())
    }

    pub fn set(&mut self, name: &str, value: &str) -> Result<()> {
        if let Some(r) = self.records.iter_mut().find(|r| r.name == name) {
            r.value = value.to_string();
        } else {
            self.records.push(Record { name: name.to_string(), value: value.to_string() });
        }
        self.flush()
    }

    pub fn delete(&mut self, name: &str) -> Result<bool> {
        let before = self.records.len();
        self.records.retain(|r| r.name != name);
        if self.records.len() == before {
            return Ok(false);
        }
        self.flush()?;
        Ok(true)
    }

    pub fn list(&self) -> &[Record] {
        &self.records
    }

    fn flush(&self) -> Result<()> {
        let data = proto::encode(&self.records);
        io::atomic_write(&self.dir, &data)
    }
}

fn load_legacy(dir: &Path) -> Vec<Record> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut records = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("persist.") && !name.starts_with("next_boot.") {
            continue;
        }
        if !entry.path().is_file() {
            continue;
        }
        if let Ok(value) = std::fs::read_to_string(entry.path()) {
            records.push(Record { name, value: value.trim().to_string() });
        }
    }
    records
}
