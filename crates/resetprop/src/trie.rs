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

    pub(crate) fn namelen(&self) -> u32 {
        self.area.read_u32(self.offset)
    }

    pub(crate) fn prop_offset(&self) -> &AtomicU32 {
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
        let len = (self.namelen() as usize).min(self.area.len().saturating_sub(self.offset + TRIE_NODE_FIXED));
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
    let max_steps = area.len() / TRIE_NODE_FIXED;
    let mut steps = 0usize;
    let mut node = TrieNode::from_offset(area, offset)?;
    loop {
        if steps >= max_steps {
            return Err(Error::AreaCorrupt("BST cycle detected".into()));
        }
        steps += 1;
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
    use std::collections::HashSet;

    let mut stack = vec![TrieNode::root(area).offset()];
    let mut visited = HashSet::new();

    while let Some(off) = stack.pop() {
        if !visited.insert(off) {
            continue;
        }

        let node = match TrieNode::from_offset(area, off) {
            Ok(n) => n,
            Err(_) => continue,
        };

        let prop_off = node.prop_offset().load(AO::Acquire);
        if prop_off != 0 {
            cb(area.data_offset() + prop_off as usize);
        }

        let children = node.children().load(AO::Acquire);
        if children != 0 {
            stack.push(area.data_offset() + children as usize);
        }

        let right = node.right().load(AO::Acquire);
        if right != 0 {
            stack.push(area.data_offset() + right as usize);
        }

        let left = node.left().load(AO::Acquire);
        if left != 0 {
            stack.push(area.data_offset() + left as usize);
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

pub(crate) fn prune(area: &PropArea) {
    let _ = prune_subtree(area, area.data_offset());
}

fn prune_subtree(area: &PropArea, abs_offset: usize) -> bool {
    let node = match TrieNode::from_offset(area, abs_offset) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let mut is_leaf = true;

    let children = node.children().load(AO::Acquire);
    if children != 0 {
        if prune_subtree(area, area.data_offset() + children as usize) {
            node.children().store(0, AO::Release);
        } else {
            is_leaf = false;
        }
    }

    let left = node.left().load(AO::Acquire);
    if left != 0 {
        if prune_subtree(area, area.data_offset() + left as usize) {
            node.left().store(0, AO::Release);
        } else {
            is_leaf = false;
        }
    }

    let right = node.right().load(AO::Acquire);
    if right != 0 {
        if prune_subtree(area, area.data_offset() + right as usize) {
            node.right().store(0, AO::Release);
        } else {
            is_leaf = false;
        }
    }

    if !is_leaf || node.prop_offset().load(AO::Acquire) != 0 {
        return false;
    }

    let namelen = node.namelen() as usize;
    unsafe {
        if namelen > 0 {
            std::ptr::write_bytes(node.name_ptr(), 0, namelen);
        }
        if let Some(ptr) = area.ptr_at(abs_offset) {
            std::ptr::write_bytes(ptr, 0, TRIE_NODE_FIXED);
        }
    }
    true
}
