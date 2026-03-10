use std::collections::{HashMap, HashSet};

use crate::area::PropArea;
use crate::dict;

const STEMS: &[&[u8]] = &[
    b"hw", b"sv", b"fm", b"nv", b"tp", b"bt", b"qc", b"sf",
    b"cfg", b"drv", b"hal", b"dev", b"arm", b"log", b"dsp",
    b"svc", b"v8a", b"gpu", b"adb", b"vhw", b"mmc", b"usb",
];

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
        pool.iter().find(|w| !used.contains(*w)).cloned()
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

    // try stem_stem_... patterns joined by underscores
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
            } else if s2.len() < remain && remain - s2.len() <= 3 {
                // pad with digits: s1_s2_NN
                let pad = remain - s2.len() - 1;
                let mut v = Vec::with_capacity(len);
                v.extend_from_slice(s1);
                v.push(b'_');
                v.extend_from_slice(s2);
                v.push(b'_');
                for i in 0..pad {
                    v.push(b'0' + (i as u8 % 10));
                }
                v
            } else {
                continue;
            };

            if buf.len() == len && !used.contains(&buf) {
                return buf;
            }
        }
    }

    // absolute fallback: repeat a stem pattern to fill
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
