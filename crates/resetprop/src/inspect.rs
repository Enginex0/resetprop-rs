use std::sync::atomic::Ordering;

use crate::area::PropArea;
use crate::info::PropInfo;
use crate::trie::TrieNode;

pub struct PropEntry {
    pub name: String,
    pub value: String,
    pub serial: u32,
}

pub struct TrieNodeEntry {
    pub path: String,
    pub offset: usize,
    pub prop_offset: u32,
    pub has_children: bool,
    pub name_segment: String,
    pub prop_info_name: Option<String>,
}

pub struct ArenaStats {
    pub bytes_used: usize,
    pub bytes_total: usize,
}

impl PropArea {
    pub fn inspect_props(&self) -> Vec<PropEntry> {
        let mut entries = Vec::new();
        crate::trie::foreach(self, |pi_offset| {
            if let Ok(pi) = PropInfo::at(self, pi_offset) {
                let name = pi.read_name();
                if name.is_empty() {
                    return;
                }
                let value = pi.read_value();
                let serial = pi.serial_raw();
                entries.push(PropEntry { name, value, serial });
            }
        });
        entries
    }

    pub fn inspect_trie(&self) -> Vec<TrieNodeEntry> {
        let mut entries = Vec::new();
        let root = TrieNode::root(self);
        let children = root.children().load(Ordering::Acquire);
        if children != 0 {
            walk_bst(self, self.data_offset() + children as usize, "", &mut entries);
        }
        entries
    }

    pub fn arena_stats(&self) -> ArenaStats {
        let used = self.bytes_used().load(Ordering::Acquire) as usize;
        let total = self.len().saturating_sub(crate::area::HEADER_SIZE);
        ArenaStats {
            bytes_used: used,
            bytes_total: total,
        }
    }
}

fn walk_bst(area: &PropArea, offset: usize, prefix: &str, out: &mut Vec<TrieNodeEntry>) {
    let node = match TrieNode::from_offset(area, offset) {
        Ok(n) => n,
        Err(_) => return,
    };

    let left = node.left().load(Ordering::Acquire);
    if left != 0 {
        walk_bst(area, area.data_offset() + left as usize, prefix, out);
    }

    let seg_bytes = node.name_bytes();
    let seg = String::from_utf8_lossy(seg_bytes).into_owned();
    let path = if prefix.is_empty() {
        seg.clone()
    } else {
        format!("{prefix}.{seg}")
    };

    let prop_off = node.prop_offset().load(Ordering::Acquire);
    let has_children = node.children().load(Ordering::Acquire) != 0;

    let prop_info_name = if prop_off != 0 {
        PropInfo::at(area, area.data_offset() + prop_off as usize)
            .ok()
            .map(|pi| pi.read_name())
    } else {
        None
    };

    out.push(TrieNodeEntry {
        path: path.clone(),
        offset,
        prop_offset: prop_off,
        has_children,
        name_segment: seg,
        prop_info_name,
    });

    let children = node.children().load(Ordering::Acquire);
    if children != 0 {
        walk_bst(area, area.data_offset() + children as usize, &path, out);
    }

    let right = node.right().load(Ordering::Acquire);
    if right != 0 {
        walk_bst(area, area.data_offset() + right as usize, prefix, out);
    }
}

impl PropInfo<'_> {
    pub(crate) fn serial_raw(&self) -> u32 {
        self.serial_atomic().load(Ordering::Acquire)
    }
}
