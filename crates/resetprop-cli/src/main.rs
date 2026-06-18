use std::path::Path;
use std::process::ExitCode;

use resetprop::{Error, PersistStore, PropSystem};

/// Default observe-init window when `--duration` is omitted.
const DEFAULT_OBSERVE_SECS: u64 = 5;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("resetprop: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut verbose = false;
    let mut init = false;
    let mut persist = false;
    let mut persist_read = false;
    let mut stealth = false;
    let mut quiet = false;
    let mut compact = false;
    let mut dir: Option<String> = None;
    let mut delete: Option<String> = None;
    let mut hexpatch: Option<String> = None;
    let mut nuke: Option<String> = None;
    let mut file: Option<String> = None;
    let mut wait_name: Option<String> = None;
    let mut wait_value: Option<String> = None;
    let mut timeout_secs: Option<u64> = None;
    let mut seals: Vec<(String, Option<String>)> = Vec::new();
    let mut check = false;
    let mut seal_arena: Option<String> = None;
    let mut unseal: Option<String> = None;
    let mut unseal_arena: Option<String> = None;
    let mut list_seals = false;
    let mut if_diff = false;
    let mut if_match: Option<String> = None;
    let mut delete_if_exist: Option<String> = None;
    let mut observe_init = false;
    let mut duration_secs: Option<u64> = None;
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "--init" => init = true,
            "-p" => persist = true,
            "-P" => persist_read = true,
            "-n" => quiet = true,
            "-d" | "--delete" => {
                i += 1;
                delete = Some(arg_val(&args, i, "-d")?);
            }
            "--hexpatch-delete" => {
                i += 1;
                hexpatch = Some(arg_val(&args, i, "--hexpatch-delete")?);
            }
            "--nuke" | "-nk" => {
                i += 1;
                nuke = Some(arg_val(&args, i, "--nuke")?);
            }
            "--stealth" | "-st" => stealth = true,
            "--seal" | "-sl" => {
                i += 1;
                let name = arg_val(&args, i, "--seal")?;
                // VALUE is the next arg unless it is another flag (e.g. --check,
                // a dry-run that takes only NAME). Repeating --seal builds a
                // multi-entry lock list under one process / one HookHandle.
                let value = if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    Some(args[i].clone())
                } else {
                    None
                };
                seals.push((name, value));
            }
            "--check" => check = true,
            "--seal-arena" | "-sla" => {
                i += 1;
                seal_arena = Some(arg_val(&args, i, "--seal-arena")?);
            }
            "--unseal" => {
                i += 1;
                unseal = Some(arg_val(&args, i, "--unseal")?);
            }
            "--unseal-arena" => {
                i += 1;
                unseal_arena = Some(arg_val(&args, i, "--unseal-arena")?);
            }
            "--seals" => list_seals = true,
            "--if-diff" => if_diff = true,
            "--if-match" => {
                i += 1;
                if_match = Some(arg_val(&args, i, "--if-match")?);
            }
            "--delete-if-exist" => {
                i += 1;
                delete_if_exist = Some(arg_val(&args, i, "--delete-if-exist")?);
            }
            "-c" | "--compact" => compact = true,
            "--dir" => {
                i += 1;
                dir = Some(arg_val(&args, i, "--dir")?);
            }
            "-f" => {
                i += 1;
                file = Some(arg_val(&args, i, "-f")?);
            }
            "-w" | "--wait" => {
                i += 1;
                wait_name = Some(arg_val(&args, i, "--wait")?);
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 1;
                    wait_value = Some(args[i].clone());
                }
            }
            "--timeout" => {
                i += 1;
                let s = arg_val(&args, i, "--timeout")?;
                timeout_secs = Some(
                    s.parse::<u64>()
                        .map_err(|_| "--timeout requires a number".to_string())?,
                );
            }
            "--observe-init" => observe_init = true,
            "--duration" => {
                i += 1;
                let s = arg_val(&args, i, "--duration")?;
                duration_secs = Some(
                    s.parse::<u64>()
                        .map_err(|_| "--duration requires a number".to_string())?,
                );
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            s if s.starts_with('-') => return Err(format!("unknown flag: {s}")),
            _ => positional.push(args[i].clone()),
        }
        i += 1;
    }

    let conditional_set = if_diff || if_match.is_some();
    let conditional_delete = delete_if_exist.is_some();
    let any_conditional = conditional_set || conditional_delete;
    let any_top_level_op = delete.is_some()
        || hexpatch.is_some()
        || nuke.is_some()
        || compact
        || file.is_some()
        || wait_name.is_some()
        || !seals.is_empty()
        || seal_arena.is_some()
        || unseal.is_some()
        || unseal_arena.is_some()
        || list_seals
        || observe_init;
    let any_mode_flag = init || persist || persist_read || stealth || quiet;

    if if_diff && if_match.is_some() {
        return Err("--if-diff and --if-match are mutually exclusive".to_string());
    }
    if conditional_set && conditional_delete {
        return Err("--if-diff/--if-match cannot be combined with --delete-if-exist".to_string());
    }
    if any_conditional && any_top_level_op {
        return Err(
            "conditional flags (--if-diff, --if-match, --delete-if-exist) cannot be combined with other top-level operations"
                .to_string(),
        );
    }
    if any_conditional && any_mode_flag {
        return Err(
            "conditional flags cannot be combined with mode flags (-p, -P, -n, --init, --stealth)"
                .to_string(),
        );
    }
    if conditional_delete && !positional.is_empty() {
        return Err(
            "--delete-if-exist takes NAME as its argument; no positional values".to_string(),
        );
    }
    if conditional_set && positional.len() != 2 {
        return Err("--if-diff and --if-match require NAME VALUE".to_string());
    }

    if persist_read {
        return persist_read_op(&positional);
    }

    let sys = match &dir {
        Some(d) => PropSystem::open_dir(Path::new(d)),
        None => PropSystem::open(),
    }
    .map_err(|e| format!("failed to open property system: {e}"))?;

    if observe_init {
        let duration = std::time::Duration::from_secs(duration_secs.unwrap_or(DEFAULT_OBSERVE_SECS));
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let count = sys
            .observe_init(duration, &mut out)
            .map_err(|e| format!("observe-init failed: {e}"))?;
        if verbose {
            eprintln!("observe-init: captured {count} kmsg line(s)");
        }
        return Ok(());
    }

    if let Some(name) = hexpatch {
        return bool_op(sys.hexpatch_delete(&name), &name, "hexpatch", verbose);
    }

    if let Some(name) = nuke {
        if persist {
            return bool_op(sys.nuke_persist(&name), &name, "nuked(persist)", verbose);
        }
        return bool_op(sys.nuke(&name), &name, "nuked", verbose);
    }

    if compact {
        let count = sys.compact().map_err(|e| format!("compact failed: {e}"))?;
        if verbose {
            eprintln!("compacted {count} area(s)");
        }
        return Ok(());
    }

    if let Some(ref name) = delete {
        if persist {
            return bool_op(sys.delete_persist(name), name, "deleted(persist)", verbose);
        }
        return bool_op(sys.delete(name), name, "deleted", verbose);
    }

    if let Some(ref name) = delete_if_exist {
        let acted = sys
            .delete(name)
            .map_err(|e| format!("delete-if-exist failed for {name}: {e}"))?;
        if verbose {
            eprintln!("delete-if-exist: [{name}] acted={acted}");
        }
        return Ok(());
    }

    if let Some(path) = file {
        return load_file(&sys, &path, init, verbose);
    }

    if let Some(ref name) = wait_name {
        let timeout = timeout_secs.map(std::time::Duration::from_secs);
        match sys.wait(name, wait_value.as_deref(), timeout) {
            Some(val) => {
                println!("{val}");
                return Ok(());
            }
            None => return Err(format!("timeout waiting for {name}")),
        }
    }

    let seal_flag_count = [
        !seals.is_empty(),
        seal_arena.is_some(),
        unseal.is_some(),
        unseal_arena.is_some(),
        list_seals,
    ]
    .iter()
    .filter(|&&flag| flag)
    .count();
    if seal_flag_count > 1 {
        return Err(
            "seal flags are mutually exclusive: pick one of --seal, --seal-arena, --unseal, --unseal-arena, --seals"
                .to_string(),
        );
    }

    if list_seals {
        let records = sys.seals().map_err(|e| format!("seals failed: {e}"))?;
        for r in records {
            println!("[{}]: [{:?}] {}", r.name, r.tier, r.arena_path.display());
        }
        return Ok(());
    }

    if let Some(ref name) = unseal {
        return bool_op(sys.unseal(name), name, "unsealed", verbose);
    }

    if let Some(ref name) = unseal_arena {
        return bool_op(sys.unseal_arena(name), name, "unsealed(arena)", verbose);
    }

    if !seals.is_empty() {
        if check {
            // Dry-run: resolve the Tier B facts in init without poking it. No
            // value is written and no trampoline is installed. Single-NAME only;
            // the resolution is name-independent. INIT_PID is `1`.
            if seals.len() != 1 {
                return Err(
                    "--seal --check is a single-NAME dry-run; pass exactly one --seal NAME"
                        .to_string(),
                );
            }
            let (name, _) = &seals[0];
            return match resetprop::seal::hook::check_init_hook(1) {
                Ok(r) => {
                    println!(
                        "check [{name}]: libc_base={:#x} libc_end={:#x} target_fn={:#x} scratch_pc={:#x}",
                        r.libc_base, r.libc_end, r.target_fn, r.scratch_pc
                    );
                    Ok(())
                }
                Err(
                    e @ (Error::HookInstallFailed(_)
                    | Error::ElfParse(_)
                    | Error::SymbolNotFound(_)),
                ) => Err(format!("Tier B dry-run failed: {e}")),
                Err(e) => Err(format!("check failed: {e}")),
            };
        }
        // Seal each prop under one process so the lazily-installed HookHandle is
        // shared: the first append installs the trampoline, the rest extend the
        // same lock list. The first hard install failure aborts the batch.
        for (name, value) in &seals {
            let value = value.as_deref().ok_or_else(|| {
                format!("--seal requires NAME VALUE (VALUE missing for {name})")
            })?;
            match sys.seal(name, value) {
                Ok(record) => {
                    if verbose {
                        eprintln!(
                            "sealed: [{}] tier={:?} arena={}",
                            record.name,
                            record.tier,
                            record.arena_path.display()
                        );
                    }
                }
                Err(
                    e @ (Error::HookInstallFailed(_)
                    | Error::ElfParse(_)
                    | Error::SymbolNotFound(_)),
                ) => {
                    return Err(format!(
                        "Tier B hook install failed for {name}: {e}. Try --seal-arena for Tier A fallback."
                    ))
                }
                Err(e) => return Err(format!("seal failed for {name}: {e}")),
            }
        }
        return Ok(());
    }

    if let Some(ref name) = seal_arena {
        let value = positional
            .first()
            .ok_or_else(|| "--seal-arena requires NAME VALUE (VALUE missing)".to_string())?;
        return match sys.seal_arena(name, value) {
            Ok(record) => {
                if verbose {
                    eprintln!(
                        "sealed(arena): [{}] tier={:?} arena={}",
                        record.name,
                        record.tier,
                        record.arena_path.display()
                    );
                }
                Ok(())
            }
            Err(e) => Err(format!("seal-arena failed: {e}")),
        };
    }

    match positional.len() {
        0 => {
            for (name, value) in sys.list() {
                println!("[{name}]: [{value}]");
            }
        }
        1 => match sys.get(&positional[0]) {
            Some(val) => println!("{val}"),
            None => return Err(format!("property not found: {}", positional[0])),
        },
        2 => {
            if let Some(ref needle) = if_match {
                let acted = sys
                    .set_if_match(&positional[0], needle, &positional[1])
                    .map_err(|e| format!("failed to set-if-match {}: {e}", positional[0]))?;
                if verbose {
                    eprintln!(
                        "set-if-match: [{}] needle=[{}] new=[{}] acted={}",
                        positional[0], needle, positional[1], acted
                    );
                }
                return Ok(());
            }
            if if_diff {
                let acted = sys
                    .set_if_diff(&positional[0], &positional[1])
                    .map_err(|e| format!("failed to set-if-diff {}: {e}", positional[0]))?;
                if verbose {
                    eprintln!(
                        "set-if-diff: [{}]=[{}] acted={}",
                        positional[0], positional[1], acted
                    );
                }
                return Ok(());
            }
            if persist && stealth {
                sys.set_stealth_persist(&positional[0], &positional[1])
            } else if persist {
                sys.set_persist(&positional[0], &positional[1])
            } else if stealth {
                sys.set_stealth(&positional[0], &positional[1])
            } else if init {
                sys.set_init(&positional[0], &positional[1])
            } else if quiet {
                sys.set_quiet(&positional[0], &positional[1])
            } else {
                sys.set(&positional[0], &positional[1])
            }
            .map_err(|e| format!("failed to set {}: {e}", positional[0]))?;
            if verbose {
                let mode = if persist && stealth {
                    "(stealth+persist)"
                } else if persist {
                    "(persist)"
                } else if stealth {
                    "(stealth)"
                } else if init {
                    "(init)"
                } else if quiet {
                    "(quiet)"
                } else {
                    ""
                };
                eprintln!("set{mode}: [{}]=[{}]", positional[0], positional[1]);
            }
        }
        _ => return Err("too many arguments".into()),
    }

    Ok(())
}

fn arg_val(args: &[String], i: usize, flag: &str) -> Result<String, String> {
    args.get(i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn bool_op(
    result: resetprop::Result<bool>,
    name: &str,
    label: &str,
    verbose: bool,
) -> Result<(), String> {
    match result {
        Ok(true) => {
            if verbose {
                eprintln!("{label}: {name}");
            }
            Ok(())
        }
        Ok(false) => Err(format!("property not found: {name}")),
        Err(e) => Err(format!("{label} failed: {e}")),
    }
}

fn persist_read_op(positional: &[String]) -> Result<(), String> {
    let store = PersistStore::load().map_err(|e| format!("failed to load persist store: {e}"))?;
    match positional.len() {
        0 => {
            for r in store.list() {
                println!("[{}]: [{}]", r.name, r.value);
            }
        }
        1 => match store.get(&positional[0]) {
            Some(val) => println!("{val}"),
            None => return Err(format!("persist property not found: {}", positional[0])),
        },
        _ => return Err("-P supports 0 args (list) or 1 arg (get)".into()),
    }
    Ok(())
}

fn load_file(sys: &PropSystem, path: &str, init: bool, verbose: bool) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;

    let mut count = 0u32;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| format!("bad line (no '='): {line}"))?;
        let name = name.trim();
        let value = value.trim();
        if init {
            sys.set_init(name, value)
        } else {
            sys.set(name, value)
        }
        .map_err(|e| format!("failed to set {name}: {e}"))?;
        count += 1;
        if verbose {
            eprintln!(
                "set{}: [{name}]=[{value}]",
                if init { "(init)" } else { "" }
            );
        }
    }

    eprintln!("{count} properties loaded from {path}");
    Ok(())
}

fn print_usage() {
    eprintln!(
        "resetprop - Android property manipulation tool

Usage:
  resetprop                          List all properties
  resetprop NAME                     Get property value
  resetprop NAME VALUE               Set property (triggers listeners)
  resetprop -n NAME VALUE            Set property without triggering listeners (no serial bump, no futex wake)
  resetprop --init NAME VALUE        Set property with bionic-correct serial (init-style)
  resetprop -p NAME VALUE            Set in both prop_area and persist file
  resetprop -d NAME                  Delete property
  resetprop -p -d NAME               Delete from both prop_area and persist file
  resetprop --if-diff NAME VALUE     Set only when current value differs (skip if absent)
  resetprop --if-match NEEDLE NAME VALUE  Set only when current value equals NEEDLE
  resetprop --delete-if-exist NAME   Delete only when NAME is currently present
  resetprop -P                       List persist properties from disk
  resetprop -P NAME                  Get persist property from disk
  resetprop --stealth|-st NAME VALUE     Set with zeroed serial, no wake signals
  resetprop --stealth|-st -p NAME VALUE  Set stealth + persist to disk
  resetprop --seal|-sl NAME VALUE    Stealth write + Tier B per-prop init hook (default seal)
  resetprop --seal A v1 --seal B v2  Seal several props in one run (one multi-entry lock list)
  resetprop --seal|-sl NAME --check  Dry-run: resolve Tier B in init, write nothing
  resetprop --seal-arena|-sla NAME VALUE  Stealth write + Tier A arena privatize (fallback)
  resetprop --unseal NAME            Remove NAME from the Tier B lock list
  resetprop --unseal-arena NAME      Revert Tier A arena privatization for NAME
  resetprop --seals                  List active seals (name, tier, arena)
  resetprop --hexpatch-delete NAME   Stealth delete (name destruction)
  resetprop --nuke|-nk NAME          Count-preserving stealth delete
  resetprop -p --nuke|-nk NAME       Nuke from both prop_area and persist file
  resetprop --compact                Defragment arenas after deletes
  resetprop -f FILE                  Load properties from file (name=value)
  resetprop --wait NAME [VALUE]      Wait for property to exist or equal VALUE
  resetprop --timeout SECS           Timeout for --wait (default: forever)
  resetprop --observe-init [--duration SECS]  Trace init's /dev/kmsg writes for a window (aarch64)
  resetprop --dir PATH               Use custom property directory

Options:
  -p          Persist mode (write to both prop_area and disk)
  -P          Disk-only read (read from persist file, not prop_area)
  -n          Quiet write: preserve serial, no futex wake, no global notify
  --init      Bionic-correct compose, init-style allocation path
  --if-diff   Conditional set: write NAME=VALUE only when current value differs (skips absent)
  --if-match NEEDLE  Conditional set: write NAME=VALUE only when current value equals NEEDLE
  --delete-if-exist NAME  Conditional delete: no-op when NAME is absent
  --stealth, -st  Stealth write: bionic compose, no futex wake, no global notify
  --seal, -sl     Tier B seal: stealth write + per-prop hook on __system_property_update in init (repeatable: one run, one multi-entry lock list)
  --check         With --seal: dry-run the Tier B install (resolve only, no ptrace write)
  --seal-arena, -sla  Tier A seal: stealth write + remap init's arena as MAP_PRIVATE|MAP_FIXED
  --unseal NAME   Remove NAME from the in-init Tier B lock list
  --unseal-arena NAME  Revert Tier A privatization for the arena holding NAME
  --seals         List currently active seals for this session
  --observe-init  Trace init (PID 1) writes to /dev/kmsg and print them (aarch64 only)
  --duration SECS With --observe-init: observe window in seconds (default: 5)
  --compact   Reclaim arena space left by deleted properties
  -v          Verbose output
  -h, --help  Show this help"
    );
}
