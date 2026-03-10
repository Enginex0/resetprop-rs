mod error;
mod area;
mod trie;
mod info;
mod dict;

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

    fn add(&self, name: &str, value: &str) -> Result<()> {
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

        let mut used: HashSet<Vec<u8>> = HashSet::new();

        // collect existing names at each level to avoid collisions
        for &node_off in &path {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            used.insert(node.name_bytes().to_vec());
        }

        // rename each trie segment in the path
        for &node_off in &path {
            let node = trie::TrieNode::from_offset(self, node_off)?;
            let original = node.name_bytes().to_vec();

            // skip segments shared with other properties (like "ro", "persist")
            // heuristic: if node has children beyond our target, it's shared
            if self.is_shared_segment(&node) {
                continue;
            }

            let replacement = dict::replacement(&original, &used);
            used.insert(replacement.clone());

            let ptr = node.name_ptr();
            unsafe {
                std::ptr::copy_nonoverlapping(replacement.as_ptr(), ptr, replacement.len());
            }
        }

        // zero the prop_info value
        let pi = info::PropInfo::at(self, pi_offset)?;
        pi.zero_value()?;

        // also mangle the full name stored in prop_info
        let name_start = pi_offset + 96;
        if let Some(ptr) = self.ptr_at(name_start) {
            let name_bytes = name.as_bytes();
            let mut mangled_used = HashSet::new();
            unsafe {
                let mut i = 0;
                for segment in name.split('.') {
                    if i > 0 {
                        i += 1; // skip the dot (keep it)
                    }
                    let seg_bytes = segment.as_bytes();
                    let replacement = dict::replacement(seg_bytes, &mangled_used);
                    mangled_used.insert(replacement.clone());
                    std::ptr::copy_nonoverlapping(
                        replacement.as_ptr(),
                        ptr.add(i),
                        replacement.len().min(name_bytes.len() - i),
                    );
                    i += seg_bytes.len();
                }
            }
        }

        Ok(true)
    }

    fn is_shared_segment(&self, node: &trie::TrieNode<'_>) -> bool {
        // a segment is shared if it has children (other props use this prefix)
        let children = node.children().load(Ordering::Acquire);
        if children == 0 {
            return false;
        }

        // check if there are multiple children or BST branches
        if let Ok(child) = trie::TrieNode::from_offset(self, self.data_offset() + children as usize) {
            let left = child.left().load(Ordering::Relaxed);
            let right = child.right().load(Ordering::Relaxed);
            // if the child node has siblings, this segment is definitely shared
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

pub struct PropSystem {
    areas: Vec<(PathBuf, PropArea)>,
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
            // skip property_info (context mapping file, not a prop area)
            if path.file_name().map(|n| n == "property_info").unwrap_or(false) {
                continue;
            }
            match PropArea::open(&path) {
                Ok(area) => areas.push((path, area)),
                Err(_) => continue,
            }
        }

        if areas.is_empty() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no property areas in {}", dir.display()),
            )));
        }

        Ok(Self { areas })
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
        // try existing areas first
        for (_, area) in &self.areas {
            if area.get(name).is_some() {
                return area.set(name, value);
            }
        }
        // property doesn't exist yet — add to first writable area
        for (_, area) in &self.areas {
            if area.writable() {
                return area.set(name, value);
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
                Ok(true) => return Ok(true),
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
}
