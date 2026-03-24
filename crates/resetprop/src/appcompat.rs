use std::collections::HashMap;
use std::path::Path;

use crate::area::PropArea;

/// Manages Android 14+ appcompat_override mirror areas.
///
/// When properties are set or deleted in the main area, the corresponding
/// override area should receive the same write (fire-and-forget).
pub(crate) struct AppcompatAreas {
    areas: HashMap<String, PropArea>,
}

impl AppcompatAreas {
    /// Opens all property areas under the override directory.
    /// Returns `None` if the directory doesn't exist or contains no usable areas.
    pub(crate) fn open(override_dir: &Path) -> Option<Self> {
        if !override_dir.is_dir() {
            return None;
        }

        let entries = std::fs::read_dir(override_dir).ok()?;
        let mut areas = HashMap::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let area = PropArea::open(&path).or_else(|_| PropArea::open_ro(&path));
            if let Ok(a) = area {
                areas.insert(filename, a);
            }
        }

        if areas.is_empty() {
            return None;
        }

        Some(Self { areas })
    }

    /// Looks up the override area that mirrors the given main area filename.
    pub(crate) fn mirror_for(&self, main_filename: &str) -> Option<&PropArea> {
        self.areas.get(main_filename)
    }
}
