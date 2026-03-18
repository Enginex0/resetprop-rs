mod error;
mod area;
mod trie;
mod info;
mod dict;
mod harvest;
#[cfg(test)]
mod mock;

pub use error::{Error, Result};
pub use area::PropArea;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

const PROP_DIR: &str = "/dev/__properties__";

impl PropArea {
    pub fn get(&self, name: &str) -> Option<String> {
        let (pi_offset, _) = trie::find(self, name).ok()?;
        let pi = info::PropInfo::at(self, pi_offset).ok()?;
        Some(pi.read_value())
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        match trie::find(self, name) {
            Ok((pi_offset, _)) => {
                let pi = info::PropInfo::at(self, pi_offset)?;
                pi.write_value(value)
            }
            Err(Error::NotFound) => self.add(name, value),
            Err(e) => Err(e),
        }
    }

    fn validate_key(name: &str) -> Result<()> {
        if name.is_empty() || name.starts_with('.') || name.ends_with('.') || name.contains("..") {
            return Err(Error::InvalidKey);
        }
        Ok(())
    }

    fn add(&self, name: &str, value: &str) -> Result<()> {
        Self::validate_key(name)?;
        let mut remaining = name;
        // root trie node's children field is at data_offset + 16
        let mut children_offset = self.data_offset() + 16;

        loop {
            let (segment, rest) = match remaining.find('.') {
                Some(pos) => (&remaining[..pos], Some(&remaining[pos + 1..])),
                None => (remaining, None),
            };

            let parent_children = self.atomic_u32(children_offset);
            let node_off = trie::bst_insert(self, parent_children, segment.as_bytes())?;

            match rest {
                Some(r) => {
                    // next level: this node's children field is at node_off + 16
                    children_offset = node_off + 16;
                    remaining = r;
                }
                None => {
                    let pi_offset = info::alloc_prop_info(self, name, value)?;
                    let relative = (pi_offset - self.data_offset()) as u32;
                    self.atomic_u32(node_off + 4).store(relative, Ordering::Release);
                    return Ok(());
                }
            }
        }
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let (pi_offset, node_offset) = match trie::find(self, name) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        // detach prop_info from trie node
        self.atomic_u32(node_offset + 4).store(0, Ordering::Release);

        // wipe prop_info value and name
        let pi = info::PropInfo::at(self, pi_offset)?;
        pi.zero_value()?;

        // zero the name in prop_info
        let name_start = pi_offset + 96;
        if let Some(ptr) = self.ptr_at(name_start) {
            unsafe {
                let mut i = 0;
                while name_start + i < self.len() && *ptr.add(i) != 0 {
                    *ptr.add(i) = 0;
                    i += 1;
                }
            }
        }

        Ok(true)
    }

    pub fn hexpatch_delete(&self, name: &str) -> Result<bool> {
        let path = match trie::find_path(self, name) {
            Ok(v) => v,
            Err(Error::NotFound) => return Ok(false),
            Err(e) => return Err(e),
        };

        let (pi_offset, _) = trie::find(self, name)?;
        let pool = harvest::SegmentPool::from_area(self);
        let mut used: HashSet<Vec<u8>> = HashSet::new();

        for &node_off in &path {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            used.insert(node.name_bytes().to_vec());
        }

        let mut chosen: Vec<Vec<u8>> = Vec::with_capacity(path.len());

        let last_idx = path.len() - 1;
        for (idx, &node_off) in path.iter().enumerate() {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            let original = node.name_bytes().to_vec();

            if self.is_shared_segment(&node, idx == last_idx) {
                chosen.push(original);
                continue;
            }

            let replacement = harvest::replacement(&original, &used, &pool);
            used.insert(replacement.clone());

            unsafe {
                std::ptr::copy_nonoverlapping(
                    replacement.as_ptr(),
                    node.name_ptr(),
                    replacement.len(),
                );
            }

            chosen.push(replacement);
        }

        // write mangled name to prop_info using the SAME segments chosen for the trie
        let name_start = pi_offset + 96;
        if let Some(ptr) = self.ptr_at(name_start) {
            let old_len = name.len();
            unsafe {
                std::ptr::write_bytes(ptr, 0, old_len + 1);
                let mut i = 0;
                for (idx, seg) in chosen.iter().enumerate() {
                    if idx > 0 {
                        *ptr.add(i) = b'.';
                        i += 1;
                    }
                    std::ptr::copy_nonoverlapping(seg.as_ptr(), ptr.add(i), seg.len());
                    i += seg.len();
                }
            }
        }

        let pi = info::PropInfo::at(self, pi_offset)?;
        pi.stealth_write_value()?;

        Ok(true)
    }

    fn is_shared_segment(&self, node: &trie::TrieNode<'_>, is_leaf: bool) -> bool {
        // intermediate node with its own property (e.g. "ro.lineage" alongside "ro.lineage.version")
        if !is_leaf && node.prop_offset().load(Ordering::Relaxed) != 0 {
            return true;
        }

        let children = node.children().load(Ordering::Acquire);
        if children == 0 {
            return false;
        }

        if let Ok(child) = trie::TrieNode::from_offset(self, self.data_offset() + children as usize) {
            let left = child.left().load(Ordering::Relaxed);
            let right = child.right().load(Ordering::Relaxed);
            left != 0 || right != 0
        } else {
            false
        }
    }

    pub fn foreach<F: FnMut(&str, &str)>(&self, mut cb: F) {
        trie::foreach(self, |pi_offset| {
            if let Ok(pi) = info::PropInfo::at(self, pi_offset) {
                let name = pi.read_name();
                let value = pi.read_value();
                if !name.is_empty() {
                    cb(&name, &value);
                }
            }
        });
    }
}

const SERIAL_FILE: &str = "properties_serial";
const SKIP_FILES: &[&str] = &["property_info", SERIAL_FILE];

pub struct PropSystem {
    areas: Vec<(PathBuf, PropArea)>,
    serial_area: Option<(PathBuf, PropArea)>,
}

impl PropSystem {
    pub fn open() -> Result<Self> {
        Self::open_dir(Path::new(PROP_DIR))
    }

    pub fn open_dir(dir: &Path) -> Result<Self> {
        let mut areas = Vec::new();
        let entries = std::fs::read_dir(dir).map_err(|e| -> Error { e.into() })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if SKIP_FILES.contains(&name) {
                continue;
            }
            let area = PropArea::open(&path).or_else(|_| PropArea::open_ro(&path));
            match area {
                Ok(a) => areas.push((path, a)),
                Err(_) => continue,
            }
        }

        if areas.is_empty() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no property areas in {}", dir.display()),
            )));
        }

        let serial_path = dir.join(SERIAL_FILE);
        let serial_area = PropArea::open(&serial_path).ok().map(|a| (serial_path, a));

        Ok(Self { areas, serial_area })
    }

    fn notify(&self) {
        if let Some((_, ref sa)) = self.serial_area {
            sa.bump_serial_and_wake();
        }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        for (_, area) in &self.areas {
            if let Some(val) = area.get(name) {
                return Some(val);
            }
        }
        None
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        for (_, area) in &self.areas {
            if area.get(name).is_some() {
                area.set(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        for (_, area) in &self.areas {
            if area.writable() {
                area.set(name, value)?;
                self.notify();
                return Ok(());
            }
        }
        Err(Error::PermissionDenied(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no writable property area",
        )))
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        for (_, area) in &self.areas {
            match area.delete(name) {
                Ok(true) => {
                    self.notify();
                    return Ok(true);
                }
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    pub fn hexpatch_delete(&self, name: &str) -> Result<bool> {
        for (_, area) in &self.areas {
            match area.hexpatch_delete(name) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }

    pub fn list(&self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        for (_, area) in &self.areas {
            area.foreach(|name, value| {
                result.push((name.to_string(), value.to_string()));
            });
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    pub fn privatize(&mut self) -> Result<()> {
        for (path, area) in &mut self.areas {
            area.privatize(path)?;
        }
        if let Some((path, area)) = &mut self.serial_area {
            area.privatize(path)?;
        }
        Ok(())
    }

    pub fn leak(self) {
        let mut sys = self;
        for (_, area) in &mut sys.areas {
            area.leak();
        }
        if let Some((_, ref mut area)) = sys.serial_area {
            area.leak();
        }
    }
}
