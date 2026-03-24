use std::collections::HashSet;
use std::path::PathBuf;

use resetprop::inspect::PropEntry;
use resetprop::PropArea;

pub struct Finding {
    pub severity: Severity,
    pub check: &'static str,
    pub detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warn => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRIT"),
        }
    }
}

const COUNT_MIN: usize = 300;
const COUNT_MAX: usize = 800;

const KNOWN_PREFIXES: &[&str] = &[
    "ro", "persist", "sys", "init", "net", "gsm", "ril", "dalvik", "hw",
    "wifi", "bluetooth", "dhcp", "service", "selinux", "debug", "log",
    "ctl", "vendor", "config", "security", "cache", "dev", "vold",
    "media", "audio", "camera", "pm", "am", "wm", "input",
    "telephony", "phone", "ims", "setupwizard", "tombstoned",
    "runtime", "heapprofd", "libc", "wrap", "sendbug", "drm",
    "keyguard", "crypto", "apex", "adb", "external_storage",
];

const NUMERIC_NAME_HINTS: &[&str] = &[
    "debuggable", "secure", "adb", "enabled", "connected", "locked",
    "booted", "ready", "completed", "running", "active", "supported",
    "present", "available", "configured", "mounted", "visible",
    "encrypted", "verified", "charged", "docked", "usb", "charging",
    "count", "size", "max", "min", "timeout", "delay", "interval",
    "level", "version", "index", "id", "port", "pid", "uid",
    "width", "height", "density", "dpi", "fps",
];

const INIT_TIME_PREFIXES: &[&str] = &[
    "ro.", "dalvik.", "persist.", "wifi.", "gsm.", "ril.", "net.",
];

pub fn check_count(total: usize) -> Vec<Finding> {
    let mut findings = Vec::new();
    if total < COUNT_MIN {
        findings.push(Finding {
            severity: Severity::Critical,
            check: "count_anomaly",
            detail: format!(
                "property count {total} is below expected minimum {COUNT_MIN} \
                 (possible bulk deletion via prune+compact)"
            ),
        });
    } else if total > COUNT_MAX {
        findings.push(Finding {
            severity: Severity::Info,
            check: "count_anomaly",
            detail: format!("property count {total} is above typical maximum {COUNT_MAX}"),
        });
    }
    findings
}

pub fn check_orphan_names(props: &[PropEntry]) -> Vec<Finding> {
    let known: HashSet<&str> = KNOWN_PREFIXES.iter().copied().collect();
    let mut findings = Vec::new();

    for p in props {
        let prefix = match p.name.split('.').next() {
            Some(s) => s,
            None => continue,
        };
        if known.contains(prefix) {
            continue;
        }
        if !prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
            findings.push(Finding {
                severity: Severity::Critical,
                check: "orphan_name",
                detail: format!(
                    "[{}] has non-alphanumeric prefix segment '{prefix}'",
                    p.name,
                ),
            });
            continue;
        }
        // short segments that look like dictionary stubs from hexpatch
        if prefix.len() <= 3 && !known.contains(prefix) {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "orphan_name",
                detail: format!(
                    "[{}] has unknown short prefix '{prefix}' (possible hexpatch artifact)",
                    p.name,
                ),
            });
        }
    }
    findings
}

pub fn check_value_anomaly(props: &[PropEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for p in props {
        if p.value != "0" {
            continue;
        }
        let name_lower = p.name.to_ascii_lowercase();
        let looks_numeric = NUMERIC_NAME_HINTS
            .iter()
            .any(|hint| name_lower.contains(hint));
        if looks_numeric {
            continue;
        }
        // "0" value on a name that doesn't suggest boolean/numeric
        findings.push(Finding {
            severity: Severity::Warn,
            check: "value_anomaly",
            detail: format!(
                "[{}]=0 but name does not suggest boolean/numeric context \
                 (possible hexpatch stealth_write_value)",
                p.name,
            ),
        });
    }
    findings
}

pub fn check_serial(props: &[PropEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for p in props {
        let counter = (p.serial >> 1) & 0x7FFF;
        let is_init_prefix = INIT_TIME_PREFIXES.iter().any(|pfx| p.name.starts_with(pfx));

        // init-time prop with unexpectedly high serial counter
        if is_init_prefix && counter > 4 {
            findings.push(Finding {
                severity: Severity::Info,
                check: "serial_counter",
                detail: format!(
                    "[{}] serial counter={counter} (raw={:#x}) is high for init-time property",
                    p.name, p.serial,
                ),
            });
        }

        // non-init prefix but serial=0 could indicate hexpatch preserved a fresh counter
        if !is_init_prefix && counter == 0 && p.value == "0" {
            findings.push(Finding {
                severity: Severity::Warn,
                check: "serial_counter",
                detail: format!(
                    "[{}]=0 with serial counter=0 (raw={:#x}), \
                     looks like hexpatch with preserved init serial",
                    p.name, p.serial,
                ),
            });
        }
    }
    findings
}

pub fn check_trie_structure(areas: &[(PathBuf, PropArea)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (path, area) in areas {
        let nodes = area.inspect_trie();
        let stats = area.arena_stats();
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");

        let mut orphan_leaves = 0u32;
        for node in &nodes {
            if node.prop_offset == 0 && !node.has_children {
                orphan_leaves += 1;
                if orphan_leaves <= 5 {
                    findings.push(Finding {
                        severity: Severity::Warn,
                        check: "trie_structure",
                        detail: format!(
                            "[{fname}] orphan leaf node at offset {:#x}, \
                             path '{}' (no prop, no children, possible incomplete prune)",
                            node.offset, node.path,
                        ),
                    });
                }
            }
        }

        if orphan_leaves > 5 {
            findings.push(Finding {
                severity: Severity::Critical,
                check: "trie_structure",
                detail: format!(
                    "[{fname}] {orphan_leaves} total orphan leaf nodes detected \
                     (showing first 5 above)",
                ),
            });
        }

        // arena utilization check: large gaps suggest compaction happened
        let utilization = if stats.bytes_total > 0 {
            (stats.bytes_used as f64 / stats.bytes_total as f64) * 100.0
        } else {
            100.0
        };
        if utilization < 30.0 && stats.bytes_total > 4096 {
            findings.push(Finding {
                severity: Severity::Info,
                check: "trie_structure",
                detail: format!(
                    "[{fname}] arena {:.1}% utilized ({} / {} bytes), \
                     low utilization may indicate compaction",
                    utilization, stats.bytes_used, stats.bytes_total,
                ),
            });
        }
    }

    findings
}

pub fn check_name_coherence(areas: &[(PathBuf, PropArea)]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (path, area) in areas {
        let nodes = area.inspect_trie();
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("?");

        for node in &nodes {
            if node.prop_offset == 0 {
                continue;
            }
            let trie_path = &node.path;
            let pi_name = match &node.prop_info_name {
                Some(n) => n,
                None => continue,
            };

            if trie_path != pi_name {
                findings.push(Finding {
                    severity: Severity::Critical,
                    check: "name_coherence",
                    detail: format!(
                        "[{fname}] trie path '{}' != prop_info name '{}' at offset {:#x} \
                         (name mismatch, possible hexpatch bug or partial rename)",
                        trie_path, pi_name, node.offset,
                    ),
                });
            }
        }
    }

    findings
}
