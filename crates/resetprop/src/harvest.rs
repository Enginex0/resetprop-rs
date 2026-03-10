use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};

use crate::area::PropArea;
use crate::dict;

const STEMS: &[&[u8]] = &[
    b"hw", b"sv", b"fm", b"nv", b"tp", b"bt", b"qc", b"sf",
    b"cfg", b"drv", b"hal", b"dev", b"arm", b"log", b"dsp",
    b"svc", b"v8a", b"gpu", b"adb", b"vhw", b"mmc", b"usb",
];

fn rand_index(n: usize) -> usize {
    let state = RandomState::new();
    let mut h = state.build_hasher();
    h.write_usize(n);
    h.finish() as usize % n
}

pub(crate) struct SegmentPool {
    buckets: HashMap<usize, Vec<Vec<u8>>>,
}

impl SegmentPool {
    pub(crate) fn from_area(area: &PropArea) -> Self {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut buckets: HashMap<usize, Vec<Vec<u8>>> = HashMap::new();

        area.foreach(|name, _| {
            for seg in name.split('.') {
                let b = seg.as_bytes().to_vec();
                if seen.insert(b.clone()) {
                    buckets.entry(b.len()).or_default().push(b);
                }
            }
        });

        Self { buckets }
    }

    pub(crate) fn pick(&self, len: usize, used: &HashSet<Vec<u8>>) -> Option<Vec<u8>> {
        let pool = self.buckets.get(&len)?;
        let candidates: Vec<_> = pool.iter().filter(|w| !used.contains(*w)).collect();
        if candidates.is_empty() {
            return None;
        }
        let idx = rand_index(candidates.len());
        Some(candidates[idx].clone())
    }
}

pub(crate) fn replacement(
    original: &[u8],
    used: &HashSet<Vec<u8>>,
    pool: &SegmentPool,
) -> Vec<u8> {
    let len = original.len();

    if let Some(w) = pool.pick(len, used) {
        if w != original {
            return w;
        }
    }

    if let Some(w) = dict::replacement(original, used) {
        return w;
    }

    compound_generate(len, used)
}

pub(crate) fn compound_generate(len: usize, used: &HashSet<Vec<u8>>) -> Vec<u8> {
    if len <= 2 {
        let mut buf = vec![b'v'; len];
        if used.contains(&buf) {
            buf[0] = b'z';
        }
        return buf;
    }

    if let Some(buf) = dot_split(len, used) {
        return buf;
    }

    // underscore join for lengths dot_split can't cover (3, 4)
    for &s1 in STEMS {
        if s1.len() + 1 >= len {
            continue;
        }
        let remain = len - s1.len() - 1;
        for &s2 in STEMS {
            if s2 == s1 {
                continue;
            }
            let buf = if s2.len() == remain {
                [s1, s2].join(&b'_')
            } else {
                continue;
            };
            if buf.len() == len && !used.contains(&buf) {
                return buf;
            }
        }
    }

    let mut buf = Vec::with_capacity(len);
    let fill = b"svc_hal_cfg_drv_";
    for i in 0..len {
        buf.push(fill[i % fill.len()]);
    }
    if used.contains(&buf) {
        buf[0] = b'z';
    }
    buf
}

// join 2/3-char stems with dots to hit exact target length
fn dot_split(len: usize, used: &HashSet<Vec<u8>>) -> Option<Vec<u8>> {
    // k segments with (k-1) dots: min = 2k+(k-1) = 3k-1, max = 3k+(k-1) = 4k-1
    let k_min = (len + 2) / 4;
    let k_max = (len + 1) / 3;
    if k_min < 2 || k_min > k_max {
        return None;
    }

    let k = k_min;
    let content = len - (k - 1);
    if content < 2 * k || content > 3 * k {
        return None;
    }
    let n3 = content - 2 * k;
    let n2 = k - n3;

    let stems3: Vec<&[u8]> = STEMS.iter().filter(|s| s.len() == 3).copied().collect();
    let stems2: Vec<&[u8]> = STEMS.iter().filter(|s| s.len() == 2).copied().collect();
    if stems3.len() < n3 || stems2.len() < n2 {
        return None;
    }

    let mut buf = Vec::with_capacity(len);
    let off3 = rand_index(stems3.len().max(1));
    let off2 = rand_index(stems2.len().max(1));

    for i in 0..n3 {
        if !buf.is_empty() {
            buf.push(b'.');
        }
        buf.extend_from_slice(stems3[(off3 + i) % stems3.len()]);
    }
    for i in 0..n2 {
        if !buf.is_empty() {
            buf.push(b'.');
        }
        buf.extend_from_slice(stems2[(off2 + i) % stems2.len()]);
    }

    if buf.len() != len || used.contains(&buf) {
        return None;
    }
    Some(buf)
}
