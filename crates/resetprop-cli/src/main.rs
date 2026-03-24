use std::path::Path;
use std::process::ExitCode;

use resetprop::{PropSystem, PersistStore};

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
    let mut compact = false;
    let mut dir: Option<String> = None;
    let mut delete: Option<String> = None;
    let mut hexpatch: Option<String> = None;
    let mut nuke: Option<String> = None;
    let mut file: Option<String> = None;
    let mut wait_name: Option<String> = None;
    let mut wait_value: Option<String> = None;
    let mut timeout_secs: Option<u64> = None;
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "--init" => init = true,
            "-p" => persist = true,
            "-P" => persist_read = true,
            "-n" => {}
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
            "--compact" => compact = true,
            "--dir" => {
                i += 1;
                dir = Some(arg_val(&args, i, "--dir")?);
            }
            "-f" => {
                i += 1;
                file = Some(arg_val(&args, i, "-f")?);
            }
            "--wait" => {
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
                timeout_secs = Some(s.parse::<u64>().map_err(|_| "--timeout requires a number".to_string())?);
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

    if persist_read {
        return persist_read_op(&positional);
    }

    let sys = match &dir {
        Some(d) => PropSystem::open_dir(Path::new(d)),
        None => PropSystem::open(),
    }
    .map_err(|e| format!("failed to open property system: {e}"))?;

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
            if persist && stealth {
                sys.set_stealth_persist(&positional[0], &positional[1])
            } else if persist {
                sys.set_persist(&positional[0], &positional[1])
            } else if stealth {
                sys.set_stealth(&positional[0], &positional[1])
            } else if init {
                sys.set_init(&positional[0], &positional[1])
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
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;

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
            eprintln!("set{}: [{name}]=[{value}]", if init { "(init)" } else { "" });
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
  resetprop [-n] NAME VALUE          Set property (direct mmap)
  resetprop --init NAME VALUE        Set property with zeroed serial counter
  resetprop -p NAME VALUE            Set in both prop_area and persist file
  resetprop -d NAME                  Delete property
  resetprop -p -d NAME               Delete from both prop_area and persist file
  resetprop -P                       List persist properties from disk
  resetprop -P NAME                  Get persist property from disk
  resetprop --stealth|-st NAME VALUE     Set with zeroed serial, no wake signals
  resetprop --stealth|-st -p NAME VALUE  Set stealth + persist to disk
  resetprop --hexpatch-delete NAME   Stealth delete (name destruction)
  resetprop --nuke|-nk NAME          Count-preserving stealth delete
  resetprop -p --nuke|-nk NAME       Nuke from both prop_area and persist file
  resetprop --compact                Defragment arenas after deletes
  resetprop -f FILE                  Load properties from file (name=value)
  resetprop --wait NAME [VALUE]      Wait for property to exist or equal VALUE
  resetprop --timeout SECS           Timeout for --wait (default: forever)
  resetprop --dir PATH               Use custom property directory

Options:
  -p          Persist mode (write to both prop_area and disk)
  -P          Disk-only read (read from persist file, not prop_area)
  --init      Zero the serial counter (mimics init for ro.* props)
  --stealth, -st  Suppress serial bump and futex wake (init-time appearance)
  --compact   Reclaim arena space left by deleted properties
  -v          Verbose output
  -h, --help  Show this help"
    );
}
