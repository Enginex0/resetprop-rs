use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

// bionic's opaque prop_info handle
#[repr(C)]
struct prop_info {
    _opaque: [u8; 0],
}

extern "C" {
    fn __system_property_foreach(
        cb: extern "C" fn(*const prop_info, *mut c_void),
        cookie: *mut c_void,
    ) -> i32;

    fn __system_property_read_callback(
        pi: *const prop_info,
        cb: extern "C" fn(*mut c_void, *const c_char, *const c_char, u32),
        cookie: *mut c_void,
    );
}

struct PropCollector {
    props: Mutex<BTreeMap<String, PropValue>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct PropValue {
    value: String,
    serial: u32,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    props: BTreeMap<String, PropValue>,
    total_count: usize,
}

extern "C" fn foreach_cb(pi: *const prop_info, cookie: *mut c_void) {

    extern "C" fn read_cb(cookie: *mut c_void, name: *const c_char, value: *const c_char, serial: u32) {
        let collector = unsafe { &*(cookie as *const PropCollector) };
        let name = unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned();
        let value = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();
        collector.props.lock().unwrap().insert(name, PropValue { value, serial });
    }

    unsafe {
        __system_property_read_callback(pi, read_cb, cookie as *mut c_void);
    }
}

fn enumerate() -> BTreeMap<String, PropValue> {
    let collector = PropCollector {
        props: Mutex::new(BTreeMap::new()),
    };
    unsafe {
        __system_property_foreach(
            foreach_cb,
            &collector as *const PropCollector as *mut c_void,
        );
    }
    collector.props.into_inner().unwrap()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(|s| s.as_str()) {
        Some("--snapshot") => {
            let path = match args.get(1) {
                Some(p) => p,
                None => { eprintln!("usage: propdetect-bionic --snapshot <file>"); return ExitCode::FAILURE; }
            };
            cmd_snapshot(Path::new(path))
        }
        Some("--diff") => {
            let (a, b) = match (args.get(1), args.get(2)) {
                (Some(a), Some(b)) => (a, b),
                _ => { eprintln!("usage: propdetect-bionic --diff <before> <after>"); return ExitCode::FAILURE; }
            };
            cmd_diff(Path::new(a), Path::new(b))
        }
        Some("-h" | "--help") => { print_usage(); ExitCode::SUCCESS }
        None => cmd_detect(),
        Some(s) => { eprintln!("unknown arg: {s}"); ExitCode::FAILURE }
    }
}

fn cmd_snapshot(path: &Path) -> ExitCode {
    let props = enumerate();
    let total_count = props.len();
    let snap = Snapshot { props, total_count };
    let json = serde_json::to_string_pretty(&snap).unwrap();
    if let Err(e) = std::fs::write(path, json) {
        eprintln!("write: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("snapshot: {total_count} properties -> {}", path.display());
    ExitCode::SUCCESS
}

fn cmd_detect() -> ExitCode {
    let props = enumerate();
    let total = props.len();

    println!("=== propdetect-bionic (non-root, bionic FFI) ===");
    println!("properties enumerated: {total}\n");

    let mut warnings = 0u32;

    // count check
    if total < 300 {
        println!("[CRIT] count_anomaly: {total} properties (expected 300-800)");
        warnings += 1;
    }

    let known_prefixes: std::collections::HashSet<&str> = [
        "ro", "persist", "sys", "init", "net", "gsm", "ril", "dalvik", "hw",
        "wifi", "bluetooth", "dhcp", "service", "selinux", "debug", "log",
        "ctl", "vendor", "config", "security", "cache", "dev", "vold",
        "media", "audio", "camera", "pm", "am", "wm", "input",
        "telephony", "phone", "ims", "runtime", "libc", "wrap", "drm",
        "apex", "adb", "external_storage",
    ].into_iter().collect();

    let numeric_hints: &[&str] = &[
        "debuggable", "secure", "adb", "enabled", "connected", "locked",
        "booted", "ready", "completed", "running", "active", "supported",
        "present", "available", "configured", "mounted", "visible",
        "count", "size", "max", "min", "timeout", "delay", "interval",
        "level", "version", "index", "id", "port", "pid", "uid",
        "width", "height", "density", "dpi", "fps", "encrypted",
    ];

    for (name, pv) in &props {
        let prefix = name.split('.').next().unwrap_or("");

        if !known_prefixes.contains(prefix) && prefix.len() <= 3 {
            println!("[WARN] orphan_name: [{name}] unknown short prefix '{prefix}'");
            warnings += 1;
        }

        if pv.value == "0" {
            let name_lower = name.to_ascii_lowercase();
            let looks_numeric = numeric_hints.iter().any(|h| name_lower.contains(h));
            if !looks_numeric {
                println!("[WARN] value_anomaly: [{name}]=0 (non-numeric name context)");
                warnings += 1;
            }
        }

        // serial analysis: counter is bits 1-15 (lower half, excluding dirty bit 0)
        let counter = (pv.serial >> 1) & 0x7FFF;
        let is_init = name.starts_with("ro.") || name.starts_with("dalvik.") || name.starts_with("persist.");
        if !is_init && counter == 0 && pv.value == "0" {
            println!("[WARN] serial: [{name}]=0 serial=0 (possible hexpatch artifact)");
            warnings += 1;
        }
    }

    if warnings == 0 {
        println!("no anomalies detected");
    } else {
        println!("\n{warnings} findings total");
    }
    ExitCode::SUCCESS
}

fn cmd_diff(a: &Path, b: &Path) -> ExitCode {
    let load = |p: &Path| -> Result<Snapshot, String> {
        let data = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        serde_json::from_str(&data).map_err(|e| format!("{}: {e}", p.display()))
    };

    let before = match load(a) { Ok(s) => s, Err(e) => { eprintln!("{e}"); return ExitCode::FAILURE; } };
    let after = match load(b) { Ok(s) => s, Err(e) => { eprintln!("{e}"); return ExitCode::FAILURE; } };

    println!("=== property diff ({} -> {} props) ===\n", before.total_count, after.total_count);

    let mut added = 0u32;
    let mut removed = 0u32;
    let mut changed = 0u32;
    let mut serial_only = 0u32;

    for (name, old) in &before.props {
        match after.props.get(name) {
            None => { println!("- [{name}] = {}", old.value); removed += 1; }
            Some(new) if old.value != new.value => {
                println!("~ [{name}] {} -> {}", old.value, new.value);
                changed += 1;
            }
            Some(new) if old.serial != new.serial => {
                println!("s [{name}] serial {:#x} -> {:#x}", old.serial, new.serial);
                serial_only += 1;
            }
            _ => {}
        }
    }
    for (name, new) in &after.props {
        if !before.props.contains_key(name) {
            println!("+ [{name}] = {}", new.value);
            added += 1;
        }
    }

    println!("\nsummary: +{added} -{removed} ~{changed} s{serial_only}");
    ExitCode::SUCCESS
}

fn print_usage() {
    eprintln!(
"propdetect-bionic - non-root property detector (bionic FFI)

Uses __system_property_foreach, same API as any Android app.

  propdetect-bionic                    Run detection heuristics
  propdetect-bionic --snapshot FILE    Save snapshot
  propdetect-bionic --diff A B         Compare two snapshots"
    );
}
