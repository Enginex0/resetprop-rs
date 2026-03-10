use std::cmp::Ordering;
use std::sync::atomic::{AtomicU32, Ordering as AO};

use crate::area::PropArea;
use crate::error::{Error, Result};

const TRIE_NODE_FIXED: usize = 20; // namelen(4) + prop(4) + left(4) + right(4) + children(4)

pub(crate) fn cmp_prop_name(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

pub(crate) struct TrieNode<'a> {
    area: &'a PropArea,
    offset: usize,
}

impl<'a> TrieNode<'a> {
    pub(crate) fn root(area: &'a PropArea) -> Self {
        Self {
            area,
            offset: area.data_offset(),
        }
    }

    pub(crate) fn from_offset(area: &'a PropArea, offset: usize) -> Result<Self> {
        if offset + TRIE_NODE_FIXED > area.len() {
            return Err(Error::AreaCorrupt("trie node OOB".into()));
        }
        Ok(Self { area, offset })
    }

    fn namelen(&self) -> u32 {
        self.area.read_u32(self.offset)
    }

    fn prop_offset(&self) -> &AtomicU32 {
        self.area.atomic_u32(self.offset + 4)
    }

    pub(crate) fn left(&self) -> &AtomicU32 {
        self.area.atomic_u32(self.offset + 8)
    }

    pub(crate) fn right(&self) -> &AtomicU32 {
        self.area.atomic_u32(self.offset + 12)
    }

    pub(crate) fn children(&self) -> &AtomicU32 {
        self.area.atomic_u32(self.offset + 16)
    }

    pub(crate) fn name_bytes(&self) -> &[u8] {
        let len = self.namelen() as usize;
        let start = self.offset + TRIE_NODE_FIXED;
        unsafe { std::slice::from_raw_parts(self.area.base().add(start), len) }
    }

    pub(crate) fn name_ptr(&self) -> *mut u8 {
        unsafe { self.area.base().add(self.offset + TRIE_NODE_FIXED) }
    }

    #[allow(dead_code)]
    pub(crate) fn total_size(&self) -> usize {
        let raw = TRIE_NODE_FIXED + self.namelen() as usize + 1;
        (raw + 3) & !3
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
}

/// Find a property's prop_info offset by dotted name.
/// Returns (prop_info_offset, last_trie_node_offset) or NotFound.
pub(crate) fn find(area: &PropArea, name: &str) -> Result<(usize, usize)> {
    let mut current = TrieNode::root(area);
    let mut remaining = name;

    loop {
        let (segment, rest) = match remaining.find('.') {
            Some(pos) => (&remaining[..pos], Some(&remaining[pos + 1..])),
            None => (remaining, None),
        };

        if segment.is_empty() {
            return Err(Error::NotFound);
        }

        let children_off = current.children().load(AO::Acquire);
        if children_off == 0 {
            return Err(Error::NotFound);
        }

        current = bst_find(area, area.data_offset() + children_off as usize, segment.as_bytes())?;

        match rest {
            Some(r) => remaining = r,
            None => break,
        }
    }

    let prop_off = current.prop_offset().load(AO::Acquire);
    if prop_off == 0 {
        return Err(Error::NotFound);
    }
    Ok((area.data_offset() + prop_off as usize, current.offset()))
}

fn bst_find<'a>(area: &'a PropArea, offset: usize, name: &[u8]) -> Result<TrieNode<'a>> {
    let mut node = TrieNode::from_offset(area, offset)?;
    loop {
        match cmp_prop_name(name, node.name_bytes()) {
            Ordering::Equal => return Ok(node),
            Ordering::Less => {
                let left = node.left().load(AO::Acquire);
                if left == 0 {
                    return Err(Error::NotFound);
                }
                node = TrieNode::from_offset(area, area.data_offset() + left as usize)?;
            }
            Ordering::Greater => {
                let right = node.right().load(AO::Acquire);
                if right == 0 {
                    return Err(Error::NotFound);
                }
                node = TrieNode::from_offset(area, area.data_offset() + right as usize)?;
            }
        }
    }
}

/// Walk the entire trie, calling `cb(prop_info_offset)` for every property.
pub(crate) fn foreach<F>(area: &PropArea, mut cb: F)
where
    F: FnMut(usize),
{
    walk_node(area, &TrieNode::root(area), &mut cb);
}

fn walk_node<F: FnMut(usize)>(area: &PropArea, node: &TrieNode<'_>, cb: &mut F) {
    let prop_off = node.prop_offset().load(AO::Acquire);
    if prop_off != 0 {
        cb(area.data_offset() + prop_off as usize);
    }

    let left = node.left().load(AO::Acquire);
    if left != 0 {
        if let Ok(n) = TrieNode::from_offset(area, area.data_offset() + left as usize) {
            walk_node(area, &n, cb);
        }
    }

    let right = node.right().load(AO::Acquire);
    if right != 0 {
        if let Ok(n) = TrieNode::from_offset(area, area.data_offset() + right as usize) {
            walk_node(area, &n, cb);
        }
    }

    let children = node.children().load(AO::Acquire);
    if children != 0 {
        if let Ok(n) = TrieNode::from_offset(area, area.data_offset() + children as usize) {
            walk_node(area, &n, cb);
        }
    }
}

/// BST insert: returns offset of existing or newly inserted node.
pub(crate) fn bst_insert(area: &PropArea, parent_children: &AtomicU32, name: &[u8]) -> Result<usize> {
    let root_off = parent_children.load(AO::Acquire);
    if root_off == 0 {
        let off = alloc_trie_node(area, name)?;
        let relative = (off - area.data_offset()) as u32;
        parent_children.store(relative, AO::Release);
        return Ok(off);
    }

    let mut current_off = area.data_offset() + root_off as usize;
    loop {
        let node = TrieNode::from_offset(area, current_off)?;
        match cmp_prop_name(name, node.name_bytes()) {
            Ordering::Equal => return Ok(current_off),
            Ordering::Less => {
                let left = node.left().load(AO::Acquire);
                if left != 0 {
                    current_off = area.data_offset() + left as usize;
                } else {
                    let off = alloc_trie_node(area, name)?;
                    let relative = (off - area.data_offset()) as u32;
                    node.left().store(relative, AO::Release);
                    return Ok(off);
                }
            }
            Ordering::Greater => {
                let right = node.right().load(AO::Acquire);
                if right != 0 {
                    current_off = area.data_offset() + right as usize;
                } else {
                    let off = alloc_trie_node(area, name)?;
                    let relative = (off - area.data_offset()) as u32;
                    node.right().store(relative, AO::Release);
                    return Ok(off);
                }
            }
        }
    }
}

fn alloc_trie_node(area: &PropArea, name: &[u8]) -> Result<usize> {
    let total = (TRIE_NODE_FIXED + name.len() + 1 + 3) & !3;
    let offset = area.alloc(total)?;

    unsafe {
        let base = area.base().add(offset);
        std::ptr::write_bytes(base, 0, total);
        // namelen
        (base as *mut u32).write(name.len() as u32);
        // name bytes
        std::ptr::copy_nonoverlapping(name.as_ptr(), base.add(TRIE_NODE_FIXED), name.len());
    }
    Ok(offset)
}

/// Walk the trie path for a dotted name, collecting trie node offsets.
/// Used by hexpatch to know which segments to rename.
pub(crate) fn find_path(area: &PropArea, name: &str) -> Result<Vec<usize>> {
    let mut path = Vec::new();
    let mut current = TrieNode::root(area);
    let mut remaining = name;

    loop {
        let (segment, rest) = match remaining.find('.') {
            Some(pos) => (&remaining[..pos], Some(&remaining[pos + 1..])),
            None => (remaining, None),
        };

        if segment.is_empty() {
            return Err(Error::NotFound);
        }

        let children_off = current.children().load(AO::Acquire);
        if children_off == 0 {
            return Err(Error::NotFound);
        }

        let found = bst_find(area, area.data_offset() + children_off as usize, segment.as_bytes())?;
        path.push(found.offset());
        current = found;

        match rest {
            Some(r) => remaining = r,
            None => break,
        }
    }

    Ok(path)
}
