use std::path::Path;

const NO_CONTEXT: u32 = 0xFFFF_FFFF;
const HEADER_SIZE: usize = 24;
const NODE_SIZE: usize = 28;
const ENTRY_SIZE: usize = 16;

pub(crate) struct PropertyContext {
    inner: Inner,
}

enum Inner {
    Binary {
        data: Vec<u8>,
        contexts_off: usize,
        root_off: usize,
    },
    Text {
        entries: Vec<(String, String)>,
    },
}

fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
    let bytes = data.get(off..off + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn str_at(data: &[u8], off: usize) -> Option<&str> {
    if off >= data.len() {
        return None;
    }
    let rest = &data[off..];
    let nul = rest.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&rest[..nul]).ok()
}

struct Header {
    contexts_off: usize,
    root_off: usize,
}

fn parse_header(data: &[u8]) -> Option<Header> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    let version = read_u32_at(data, 0)?;
    if version != 1 {
        return None;
    }
    let size = read_u32_at(data, 8)? as usize;
    if size > data.len() {
        return None;
    }
    let contexts_off = read_u32_at(data, 12)? as usize;
    let root_off = read_u32_at(data, 20)? as usize;
    if contexts_off >= data.len() || root_off >= data.len() {
        return None;
    }
    Some(Header {
        contexts_off,
        root_off,
    })
}

struct Node {
    property_entry: u32,
    num_children: u32,
    child_nodes_off: u32,
    num_prefixes: u32,
    prefix_entries_off: u32,
    num_exact: u32,
    exact_entries_off: u32,
}

fn read_node(data: &[u8], off: usize) -> Option<Node> {
    if off + NODE_SIZE > data.len() {
        return None;
    }
    Some(Node {
        property_entry: read_u32_at(data, off)?,
        num_children: read_u32_at(data, off + 4)?,
        child_nodes_off: read_u32_at(data, off + 8)?,
        num_prefixes: read_u32_at(data, off + 12)?,
        prefix_entries_off: read_u32_at(data, off + 16)?,
        num_exact: read_u32_at(data, off + 20)?,
        exact_entries_off: read_u32_at(data, off + 24)?,
    })
}

struct Entry {
    name_offset: u32,
    namelen: u32,
    context_index: u32,
}

fn read_entry(data: &[u8], off: usize) -> Option<Entry> {
    if off + ENTRY_SIZE > data.len() {
        return None;
    }
    Some(Entry {
        name_offset: read_u32_at(data, off)?,
        namelen: read_u32_at(data, off + 4)?,
        context_index: read_u32_at(data, off + 8)?,
    })
}

fn entry_name<'a>(data: &'a [u8], entry: &Entry) -> Option<&'a str> {
    let off = entry.name_offset as usize;
    let len = entry.namelen as usize;
    if off + len > data.len() {
        return None;
    }
    std::str::from_utf8(data.get(off..off + len)?).ok()
}

fn context_str(data: &[u8], contexts_off: usize, index: u32) -> Option<&str> {
    if index == NO_CONTEXT {
        return None;
    }
    let count = read_u32_at(data, contexts_off)?;
    if index >= count {
        return None;
    }
    let slot_off = contexts_off + 4 + (index as usize) * 4;
    let str_off = read_u32_at(data, slot_off)? as usize;
    str_at(data, str_off)
}

fn array_offset(data: &[u8], array_base: u32, idx: u32) -> Option<u32> {
    let off = (array_base as usize) + (idx as usize) * 4;
    read_u32_at(data, off)
}

fn child_name(data: &[u8], child_node_off: usize) -> Option<&str> {
    let node = read_node(data, child_node_off)?;
    if node.property_entry == 0 {
        return None;
    }
    let entry = read_entry(data, node.property_entry as usize)?;
    entry_name(data, &entry)
}

fn resolve_binary<'a>(data: &'a [u8], contexts_off: usize, root_off: usize, name: &str) -> Option<&'a str> {
    let mut best: Option<u32> = None;
    let mut node_off = root_off;
    let mut remaining = name;

    loop {
        let node = read_node(data, node_off)?;

        // (a) Record node's own context
        if node.property_entry != 0 {
            let entry = read_entry(data, node.property_entry as usize)?;
            if entry.context_index != NO_CONTEXT {
                best = Some(entry.context_index);
            }
        }

        // (b) Check prefix entries (ordered longest-to-shortest, first match wins)
        check_prefixes(data, &node, remaining, &mut best);

        let (segment, rest) = match remaining.find('.') {
            Some(pos) => (&remaining[..pos], Some(&remaining[pos + 1..])),
            None => (remaining, None),
        };

        // (c) Binary search child_nodes for this segment
        if let Some(child_off) = find_child(data, &node, segment) {
            node_off = child_off;
            match rest {
                Some(r) => remaining = r,
                None => {
                    // All segments consumed; check final node
                    let final_node = read_node(data, node_off)?;

                    if final_node.property_entry != 0 {
                        let entry = read_entry(data, final_node.property_entry as usize)?;
                        if entry.context_index != NO_CONTEXT {
                            best = Some(entry.context_index);
                        }
                    }

                    // (d) Check exact_match_entries at the final child
                    check_exact(data, &final_node, segment, &mut best);

                    break;
                }
            }
        } else {
            break;
        }
    }

    let idx = best?;
    context_str(data, contexts_off, idx)
}

fn check_prefixes(data: &[u8], node: &Node, remaining: &str, best: &mut Option<u32>) {
    if node.num_prefixes == 0 {
        return;
    }
    for i in 0..node.num_prefixes {
        let entry_off = match array_offset(data, node.prefix_entries_off, i) {
            Some(o) => o as usize,
            None => continue,
        };
        let entry = match read_entry(data, entry_off) {
            Some(e) => e,
            None => continue,
        };
        let prefix = match entry_name(data, &entry) {
            Some(n) => n,
            None => continue,
        };
        if remaining.starts_with(prefix) && entry.context_index != NO_CONTEXT {
            *best = Some(entry.context_index);
            return; // first match wins (longest-to-shortest order)
        }
    }
}

fn check_exact(data: &[u8], node: &Node, segment: &str, best: &mut Option<u32>) {
    if node.num_exact == 0 {
        return;
    }

    let count = node.num_exact;
    let mut lo: u32 = 0;
    let mut hi: u32 = count;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let entry_off = match array_offset(data, node.exact_entries_off, mid) {
            Some(o) => o as usize,
            None => return,
        };
        let entry = match read_entry(data, entry_off) {
            Some(e) => e,
            None => return,
        };
        let name = match entry_name(data, &entry) {
            Some(n) => n,
            None => return,
        };
        match segment.cmp(name) {
            std::cmp::Ordering::Equal => {
                if entry.context_index != NO_CONTEXT {
                    *best = Some(entry.context_index);
                }
                return;
            }
            std::cmp::Ordering::Less => hi = mid,
            std::cmp::Ordering::Greater => lo = mid + 1,
        }
    }
}

fn find_child(data: &[u8], node: &Node, segment: &str) -> Option<usize> {
    if node.num_children == 0 {
        return None;
    }

    let count = node.num_children;
    let mut lo: u32 = 0;
    let mut hi: u32 = count;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let child_off = array_offset(data, node.child_nodes_off, mid)? as usize;
        let name = child_name(data, child_off)?;
        match segment.cmp(name) {
            std::cmp::Ordering::Equal => return Some(child_off),
            std::cmp::Ordering::Less => hi = mid,
            std::cmp::Ordering::Greater => lo = mid + 1,
        }
    }
    None
}

const TEXT_PATHS: &[&str] = &[
    "/system/etc/selinux/plat_property_contexts",
    "/vendor/etc/selinux/vendor_property_contexts",
    "/system/etc/selinux/property_contexts",
];

fn load_text() -> Option<Vec<(String, String)>> {
    let mut entries = Vec::new();

    for path in TEXT_PATHS {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let prefix = match parts.next() {
                Some(p) => p,
                None => continue,
            };
            let context = match parts.next() {
                Some(c) => c,
                None => continue,
            };
            entries.push((prefix.to_string(), context.to_string()));
        }
    }

    if entries.is_empty() {
        return None;
    }

    entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    Some(entries)
}

fn resolve_text<'a>(entries: &'a [(String, String)], name: &str) -> Option<&'a str> {
    for (prefix, context) in entries {
        if name.starts_with(prefix.as_str()) {
            return Some(context.as_str());
        }
    }
    None
}

impl PropertyContext {
    /// Try to load from property_info binary file, fall back to text files.
    /// Returns None if nothing parseable found.
    pub(crate) fn load(dir: &Path) -> Option<Self> {
        if let Some(ctx) = Self::load_binary(dir) {
            return Some(ctx);
        }
        Self::load_text()
    }

    fn load_binary(dir: &Path) -> Option<Self> {
        let path = dir.join("property_info");
        let data = std::fs::read(&path).ok()?;
        let header = parse_header(&data)?;

        // Sanity: verify we can at least read the contexts array count
        read_u32_at(&data, header.contexts_off)?;
        // Verify root node is readable
        read_node(&data, header.root_off)?;

        Some(Self {
            inner: Inner::Binary {
                data,
                contexts_off: header.contexts_off,
                root_off: header.root_off,
            },
        })
    }

    fn load_text() -> Option<Self> {
        let entries = load_text()?;
        Some(Self {
            inner: Inner::Text { entries },
        })
    }

    /// Resolve a property name to its area filename.
    /// Returns None if no match (caller falls back to linear scan).
    pub(crate) fn resolve(&self, name: &str) -> Option<&str> {
        match &self.inner {
            Inner::Binary {
                data,
                contexts_off,
                root_off,
            } => resolve_binary(data, *contexts_off, *root_off, name),
            Inner::Text { entries } => resolve_text(entries, name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BlobBuilder {
        buf: Vec<u8>,
    }

    impl BlobBuilder {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }

        fn pos(&self) -> u32 {
            self.buf.len() as u32
        }

        fn write_u32(&mut self, val: u32) {
            self.buf.extend_from_slice(&val.to_le_bytes());
        }

        fn write_str(&mut self, s: &str) -> u32 {
            let off = self.pos();
            self.buf.extend_from_slice(s.as_bytes());
            self.buf.push(0);
            off
        }

        fn align4(&mut self) {
            while self.buf.len() % 4 != 0 {
                self.buf.push(0);
            }
        }
    }

    /// Build a minimal property_info blob with:
    ///   root
    ///     ├─ child "ro" (context: "u:object_r:default_prop:s0")
    ///     │   └─ child "build" (context: "u:object_r:build_prop:s0")
    ///     │       exact_match: "type" (context: "u:object_r:build_prop:s0")
    ///     └─ child "persist" (context: "u:object_r:persist_prop:s0")
    fn build_test_blob() -> Vec<u8> {
        let mut b = BlobBuilder::new();

        // Reserve header (24 bytes), fill later
        for _ in 0..6 {
            b.write_u32(0);
        }

        // --- Context strings ---
        let ctx_default_off = b.write_str("u:object_r:default_prop:s0");
        b.align4();
        let ctx_build_off = b.write_str("u:object_r:build_prop:s0");
        b.align4();
        let ctx_persist_off = b.write_str("u:object_r:persist_prop:s0");
        b.align4();

        // --- ContextsArray ---
        let contexts_array_off = b.pos();
        b.write_u32(3); // count
        b.write_u32(ctx_default_off);
        b.write_u32(ctx_build_off);
        b.write_u32(ctx_persist_off);

        // --- Name strings ---
        let name_ro_off = b.write_str("ro");
        b.align4();
        let name_build_off = b.write_str("build");
        b.align4();
        let name_type_off = b.write_str("type");
        b.align4();
        let name_persist_off = b.write_str("persist");
        b.align4();

        // --- PropertyEntry structs ---
        // entry for "ro": context index 0
        let entry_ro_off = b.pos();
        b.write_u32(name_ro_off);
        b.write_u32(2); // namelen
        b.write_u32(0); // context_index = 0 (default_prop)
        b.write_u32(0); // type_index

        // entry for "build": context index 1
        let entry_build_off = b.pos();
        b.write_u32(name_build_off);
        b.write_u32(5); // namelen
        b.write_u32(1); // context_index = 1 (build_prop)
        b.write_u32(0);

        // entry for "type" exact match: context index 1
        let entry_type_off = b.pos();
        b.write_u32(name_type_off);
        b.write_u32(4); // namelen
        b.write_u32(1); // context_index = 1 (build_prop)
        b.write_u32(0);

        // entry for "persist": context index 2
        let entry_persist_off = b.pos();
        b.write_u32(name_persist_off);
        b.write_u32(7); // namelen
        b.write_u32(2); // context_index = 2 (persist_prop)
        b.write_u32(0);

        // --- exact_match_entries array for "build" node ---
        let exact_array_off = b.pos();
        b.write_u32(entry_type_off);

        // --- child_nodes offset arrays ---
        // Root's children: [ro_node, persist_node] (sorted alphabetically)
        let root_children_array_off = b.pos();
        let ro_node_off_placeholder = b.pos();
        b.write_u32(0); // placeholder for persist_node offset
        b.write_u32(0); // placeholder for ro_node offset

        // ro's children: [build_node]
        let ro_children_array_off = b.pos();
        let build_node_off_placeholder = b.pos();
        b.write_u32(0); // placeholder for build_node offset

        // --- TrieNodeInternal structs ---
        // "build" node (leaf with exact_match)
        let build_node_off = b.pos();
        b.write_u32(entry_build_off); // property_entry
        b.write_u32(0);               // num_child_nodes
        b.write_u32(0);               // child_nodes
        b.write_u32(0);               // num_prefixes
        b.write_u32(0);               // prefix_entries
        b.write_u32(1);               // num_exact_matches
        b.write_u32(exact_array_off); // exact_match_entries

        // "ro" node
        let ro_node_off = b.pos();
        b.write_u32(entry_ro_off);            // property_entry
        b.write_u32(1);                        // num_child_nodes
        b.write_u32(ro_children_array_off);    // child_nodes
        b.write_u32(0);                        // num_prefixes
        b.write_u32(0);                        // prefix_entries
        b.write_u32(0);                        // num_exact_matches
        b.write_u32(0);                        // exact_match_entries

        // "persist" node
        let persist_node_off = b.pos();
        b.write_u32(entry_persist_off); // property_entry
        b.write_u32(0);
        b.write_u32(0);
        b.write_u32(0);
        b.write_u32(0);
        b.write_u32(0);
        b.write_u32(0);

        // root node
        let root_off = b.pos();
        b.write_u32(0);                         // property_entry (none)
        b.write_u32(2);                          // num_child_nodes
        b.write_u32(root_children_array_off);    // child_nodes
        b.write_u32(0);                          // num_prefixes
        b.write_u32(0);                          // prefix_entries
        b.write_u32(0);                          // num_exact_matches
        b.write_u32(0);                          // exact_match_entries

        // --- Patch child_nodes arrays with actual offsets ---
        // Root children: sorted by name. "persist" < "ro" alphabetically
        let bytes = persist_node_off.to_le_bytes();
        b.buf[root_children_array_off as usize..root_children_array_off as usize + 4]
            .copy_from_slice(&bytes);
        let bytes = ro_node_off.to_le_bytes();
        b.buf[ro_node_off_placeholder as usize + 4..ro_node_off_placeholder as usize + 8]
            .copy_from_slice(&bytes);

        // ro children: [build_node]
        let bytes = build_node_off.to_le_bytes();
        b.buf[build_node_off_placeholder as usize..build_node_off_placeholder as usize + 4]
            .copy_from_slice(&bytes);

        // --- Fill header ---
        let total = b.buf.len() as u32;
        let header_bytes = [
            1u32.to_le_bytes(),               // current_version
            1u32.to_le_bytes(),               // minimum_version
            total.to_le_bytes(),              // size
            contexts_array_off.to_le_bytes(), // contexts_offset
            0u32.to_le_bytes(),               // types_offset (unused)
            root_off.to_le_bytes(),           // root_offset
        ];
        for (i, chunk) in header_bytes.iter().enumerate() {
            b.buf[i * 4..i * 4 + 4].copy_from_slice(chunk);
        }

        b.buf
    }

    #[test]
    fn binary_resolve_ro_build_type() {
        let data = build_test_blob();
        let header = parse_header(&data).unwrap();
        let result = resolve_binary(&data, header.contexts_off, header.root_off, "ro.build.type");
        assert_eq!(result, Some("u:object_r:build_prop:s0"));
    }

    #[test]
    fn binary_resolve_ro_build_prefix() {
        let data = build_test_blob();
        let header = parse_header(&data).unwrap();
        // "ro.build" should match the build node's own context
        let result = resolve_binary(&data, header.contexts_off, header.root_off, "ro.build");
        assert_eq!(result, Some("u:object_r:build_prop:s0"));
    }

    #[test]
    fn binary_resolve_ro_fallback() {
        let data = build_test_blob();
        let header = parse_header(&data).unwrap();
        // "ro.unknown" matches "ro" node context (no "unknown" child)
        let result = resolve_binary(&data, header.contexts_off, header.root_off, "ro.unknown");
        assert_eq!(result, Some("u:object_r:default_prop:s0"));
    }

    #[test]
    fn binary_resolve_persist() {
        let data = build_test_blob();
        let header = parse_header(&data).unwrap();
        let result = resolve_binary(&data, header.contexts_off, header.root_off, "persist.sys.timezone");
        assert_eq!(result, Some("u:object_r:persist_prop:s0"));
    }

    #[test]
    fn binary_resolve_unknown_returns_none() {
        let data = build_test_blob();
        let header = parse_header(&data).unwrap();
        // root has no property_entry, so unknown top-level returns None
        let result = resolve_binary(&data, header.contexts_off, header.root_off, "unknown.prop");
        assert_eq!(result, None);
    }

    #[test]
    fn corrupt_header_returns_none() {
        assert!(parse_header(&[]).is_none());
        assert!(parse_header(&[0u8; 23]).is_none());

        // Wrong version
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_header(&data).is_none());
    }

    #[test]
    fn text_resolve_longest_prefix() {
        let entries = vec![
            ("ro.build.".to_string(), "build_ctx".to_string()),
            ("ro.".to_string(), "ro_ctx".to_string()),
            ("persist.".to_string(), "persist_ctx".to_string()),
        ];
        // Already sorted longest first
        assert_eq!(resolve_text(&entries, "ro.build.type"), Some("build_ctx"));
        assert_eq!(resolve_text(&entries, "ro.debuggable"), Some("ro_ctx"));
        assert_eq!(resolve_text(&entries, "persist.sys.tz"), Some("persist_ctx"));
        assert_eq!(resolve_text(&entries, "dalvik.vm.heapsize"), None);
    }

    #[test]
    fn text_empty_returns_none() {
        let entries: Vec<(String, String)> = vec![];
        assert_eq!(resolve_text(&entries, "anything"), None);
    }
}
