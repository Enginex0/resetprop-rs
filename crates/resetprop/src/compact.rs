use std::collections::HashMap;
use std::sync::atomic::Ordering as AO;

use crate::area::PropArea;
use crate::error::Result;
use crate::trie::TrieNode;

const PROP_INFO_FIXED: usize = 96;
const LONG_FLAG: u32 = 1 << 16;
const LONG_PROP_ERROR_SIZE: usize = 56;
const TRIE_HEADER_SIZE: usize = 20;
const DIRTY_BACKUP_SIZE: usize = 92;

struct LiveAlloc {
    offset: usize,
    size: usize,
}

pub(crate) fn compact(area: &PropArea) -> Result<bool> {
    let mut allocs: Vec<LiveAlloc> = Vec::new();
    let mut trie_offsets: Vec<usize> = Vec::new();
    let mut long_props: Vec<(usize, usize)> = Vec::new();

    if has_dirty_backup(area) {
        allocs.push(LiveAlloc {
            offset: area.data_offset() + TRIE_HEADER_SIZE,
            size: DIRTY_BACKUP_SIZE,
        });
    }

    collect(area, area.data_offset(), &mut allocs, &mut trie_offsets, &mut long_props)?;

    allocs.sort_by_key(|a| a.offset);
    allocs.dedup_by_key(|a| a.offset);

    if allocs.is_empty() {
        return Ok(false);
    }

    let has_hole = has_gaps(area, &allocs);
    if !has_hole {
        return Ok(false);
    }

    let mut remap: HashMap<usize, usize> = HashMap::new();
    let mut cursor = allocs[0].offset;

    for alloc in &allocs {
        remap.insert(alloc.offset, cursor);
        if cursor != alloc.offset {
            unsafe {
                std::ptr::copy(
                    area.base().add(alloc.offset) as *const u8,
                    area.base().add(cursor),
                    alloc.size,
                );
            }
        }
        cursor += alloc.size;
    }

    patch_trie_pointers(area, &trie_offsets, &remap);
    patch_long_values(area, &long_props, &remap);

    let old_end = area.data_offset() + area.bytes_used().load(AO::Acquire) as usize;
    if cursor < old_end {
        unsafe { std::ptr::write_bytes(area.base().add(cursor), 0, old_end - cursor); }
    }

    let new_used = (cursor - area.data_offset()) as u32;
    area.bytes_used().store(new_used, AO::Release);

    Ok(true)
}

fn collect(
    area: &PropArea,
    node_abs: usize,
    allocs: &mut Vec<LiveAlloc>,
    trie_offsets: &mut Vec<usize>,
    long_props: &mut Vec<(usize, usize)>,
) -> Result<()> {
    let node = TrieNode::from_offset(area, node_abs)?;
    let namelen = node.namelen() as usize;
    let node_size = if namelen == 0 {
        TRIE_HEADER_SIZE
    } else {
        (TRIE_HEADER_SIZE + namelen + 1 + 3) & !3
    };

    allocs.push(LiveAlloc { offset: node_abs, size: node_size });
    trie_offsets.push(node_abs);

    let prop_rel = node.prop_offset().load(AO::Acquire);
    if prop_rel != 0 {
        let pi_abs = area.data_offset() + prop_rel as usize;
        let name_len = strlen_at(area, pi_abs + PROP_INFO_FIXED);
        let pi_total = (PROP_INFO_FIXED + name_len + 1 + 3) & !3;
        allocs.push(LiveAlloc { offset: pi_abs, size: pi_total });

        let serial = area.read_u32(pi_abs);
        if serial & LONG_FLAG != 0 {
            let rel = area.read_u32(pi_abs + 4 + LONG_PROP_ERROR_SIZE) as usize;
            let long_abs = pi_abs + rel;
            let val_len = strlen_at(area, long_abs);
            let aligned = (val_len + 1 + 3) & !3;
            allocs.push(LiveAlloc { offset: long_abs, size: aligned });
            long_props.push((pi_abs, long_abs));
        }
    }

    let left_rel = node.left().load(AO::Acquire);
    if left_rel != 0 {
        collect(area, area.data_offset() + left_rel as usize, allocs, trie_offsets, long_props)?;
    }

    let children_rel = node.children().load(AO::Acquire);
    if children_rel != 0 {
        collect(area, area.data_offset() + children_rel as usize, allocs, trie_offsets, long_props)?;
    }

    let right_rel = node.right().load(AO::Acquire);
    if right_rel != 0 {
        collect(area, area.data_offset() + right_rel as usize, allocs, trie_offsets, long_props)?;
    }

    Ok(())
}

fn strlen_at(area: &PropArea, offset: usize) -> usize {
    let mut len = 0;
    while offset + len < area.len() {
        if unsafe { *area.base().add(offset + len) } == 0 {
            break;
        }
        len += 1;
    }
    len
}

fn has_gaps(area: &PropArea, allocs: &[LiveAlloc]) -> bool {
    for i in 0..allocs.len() - 1 {
        if allocs[i].offset + allocs[i].size != allocs[i + 1].offset {
            return true;
        }
    }
    let last = &allocs[allocs.len() - 1];
    let end = last.offset + last.size;
    let used_end = area.data_offset() + area.bytes_used().load(AO::Acquire) as usize;
    end < used_end
}

fn patch_trie_pointers(area: &PropArea, trie_offsets: &[usize], remap: &HashMap<usize, usize>) {
    let data_offset = area.data_offset();

    for &old_off in trie_offsets {
        let new_off = match remap.get(&old_off) {
            Some(&v) => v,
            None => continue,
        };
        let node = match TrieNode::from_offset(area, new_off) {
            Ok(n) => n,
            Err(_) => continue,
        };

        for field in [node.prop_offset(), node.left(), node.right(), node.children()] {
            let old_rel = field.load(AO::Acquire);
            if old_rel == 0 {
                continue;
            }
            let old_abs = data_offset + old_rel as usize;
            if let Some(&new_abs) = remap.get(&old_abs) {
                field.store((new_abs - data_offset) as u32, AO::Release);
            }
        }
    }
}

fn patch_long_values(area: &PropArea, long_props: &[(usize, usize)], remap: &HashMap<usize, usize>) {
    for &(old_pi, old_lv) in long_props {
        let new_pi = match remap.get(&old_pi) {
            Some(&v) => v,
            None => continue,
        };
        let new_lv = match remap.get(&old_lv) {
            Some(&v) => v,
            None => continue,
        };
        let new_rel = (new_lv - new_pi) as u32;
        area.atomic_u32(new_pi + 4 + LONG_PROP_ERROR_SIZE).store(new_rel, AO::Release);
    }
}

fn has_dirty_backup(area: &PropArea) -> bool {
    let root = match TrieNode::from_offset(area, area.data_offset()) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let children = root.children().load(AO::Acquire);
    if children != 0 && children as usize == TRIE_HEADER_SIZE {
        return false;
    }
    if children == 0 {
        return area.bytes_used().load(AO::Acquire) as usize == TRIE_HEADER_SIZE + DIRTY_BACKUP_SIZE;
    }
    true
}
