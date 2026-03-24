mod heuristics;
mod snapshot;

use std::path::Path;
use std::process::ExitCode;

use resetprop::PropSystem;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("propdetect: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut dir: Option<String> = None;
    let mut snap_path: Option<String> = None;
    let mut diff_before: Option<String> = None;
    let mut diff_after: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                i += 1;
                dir = Some(arg_val(&args, i, "--dir")?);
            }
            "--snapshot" => {
                i += 1;
                snap_path = Some(arg_val(&args, i, "--snapshot")?);
            }
            "--diff" => {
                i += 1;
                diff_before = Some(arg_val(&args, i, "--diff")?);
                i += 1;
                diff_after = Some(arg_val(&args, i, "--diff")?);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            _ => return Err(format!("unexpected argument: {}", args[i])),
        }
        i += 1;
    }

    if let (Some(before), Some(after)) = (diff_before, diff_after) {
        return run_diff(Path::new(&before), Path::new(&after));
    }

    let sys = match &dir {
        Some(d) => PropSystem::open_dir(Path::new(d)),
        None => PropSystem::open(),
    }
    .map_err(|e| format!("failed to open property system: {e}"))?;

    if let Some(ref path) = snap_path {
        let snap = snapshot::capture(&sys);
        snapshot::save(&snap, Path::new(path))?;
        eprintln!("snapshot saved to {path} ({} properties)", snap.total_count);
        return Ok(());
    }

    run_detect(&sys)
}

fn run_detect(sys: &PropSystem) -> Result<(), String> {
    let mut all_props = Vec::new();
    for (_, area) in sys.areas() {
        all_props.extend(area.inspect_props());
    }

    let mut findings = Vec::new();

    findings.extend(heuristics::check_count(all_props.len()));
    findings.extend(heuristics::check_orphan_names(&all_props));
    findings.extend(heuristics::check_value_anomaly(&all_props));
    findings.extend(heuristics::check_serial(&all_props));
    findings.extend(heuristics::check_trie_structure(sys.areas()));
    findings.extend(heuristics::check_name_coherence(sys.areas()));

    if findings.is_empty() {
        println!("propdetect: no anomalies detected ({} properties scanned)", all_props.len());
        return Ok(());
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    println!("=== propdetect report ({} properties scanned) ===\n", all_props.len());

    let crit = findings.iter().filter(|f| f.severity == heuristics::Severity::Critical).count();
    let warn = findings.iter().filter(|f| f.severity == heuristics::Severity::Warn).count();
    let info = findings.iter().filter(|f| f.severity == heuristics::Severity::Info).count();

    for f in &findings {
        println!("[{}] {}: {}", f.severity, f.check, f.detail);
    }

    println!();
    println!("summary: {crit} critical, {warn} warnings, {info} info");

    Ok(())
}

fn run_diff(before: &Path, after: &Path) -> Result<(), String> {
    let snap_before = snapshot::load(before)?;
    let snap_after = snapshot::load(after)?;

    let entries = snapshot::diff(&snap_before, &snap_after);

    if entries.is_empty() {
        println!("no differences detected");
        return Ok(());
    }

    println!("=== property diff ({} -> {} properties) ===\n",
        snap_before.total_count, snap_after.total_count);

    for e in &entries {
        match &e.kind {
            snapshot::DiffKind::Added { value } => {
                println!("+ [{}] = [{value}]", e.name);
            }
            snapshot::DiffKind::Removed { value } => {
                println!("- [{}] = [{value}]", e.name);
            }
            snapshot::DiffKind::Changed { old, new } => {
                println!("~ [{}] [{old}] -> [{new}]", e.name);
            }
            snapshot::DiffKind::SerialChanged { old, new } => {
                println!("s [{}] serial {old:#x} -> {new:#x}", e.name);
            }
        }
    }

    println!();
    let added = entries.iter().filter(|e| matches!(e.kind, snapshot::DiffKind::Added { .. })).count();
    let removed = entries.iter().filter(|e| matches!(e.kind, snapshot::DiffKind::Removed { .. })).count();
    let changed = entries.iter().filter(|e| matches!(e.kind, snapshot::DiffKind::Changed { .. })).count();
    let serial = entries.iter().filter(|e| matches!(e.kind, snapshot::DiffKind::SerialChanged { .. })).count();

    println!("summary: +{added} added, -{removed} removed, ~{changed} changed, s{serial} serial-only");

    Ok(())
}

fn arg_val(args: &[String], i: usize, flag: &str) -> Result<String, String> {
    args.get(i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "propdetect - adversarial property manipulation detector

Usage:
  propdetect                           Run all detection heuristics
  propdetect --dir PATH                Use custom property directory
  propdetect --snapshot FILE           Save property snapshot to file
  propdetect --diff BEFORE AFTER       Diff two snapshots

Heuristics:
  count_anomaly     Property count vs expected baseline
  orphan_name       Names not matching known Android patterns
  value_anomaly     Suspicious value=0 on non-numeric names
  serial_counter    Serial counter vs expected init-time values
  trie_structure    Orphaned nodes and arena utilization
  name_coherence    Trie path vs prop_info name mismatch"
    );
}
