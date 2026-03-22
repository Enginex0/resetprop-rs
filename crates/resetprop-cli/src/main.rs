use std::path::Path;
use std::process::ExitCode;

use resetprop::PropSystem;

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
    let mut dir: Option<String> = None;
    let mut delete: Option<String> = None;
    let mut hexpatch: Option<String> = None;
    let mut file: Option<String> = None;
    let mut positional = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-v" => verbose = true,
            "--init" => init = true,
            "-n" => {}
            "-d" | "--delete" => {
                i += 1;
                delete = Some(arg_val(&args, i, "-d")?);
            }
            "--hexpatch-delete" => {
                i += 1;
                hexpatch = Some(arg_val(&args, i, "--hexpatch-delete")?);
            }
            "--dir" => {
                i += 1;
                dir = Some(arg_val(&args, i, "--dir")?);
            }
            "-f" => {
                i += 1;
                file = Some(arg_val(&args, i, "-f")?);
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

    let sys = match &dir {
        Some(d) => PropSystem::open_dir(Path::new(d)),
        None => PropSystem::open(),
    }
    .map_err(|e| format!("failed to open property system: {e}"))?;

    if let Some(name) = hexpatch {
        return bool_op(sys.hexpatch_delete(&name), &name, "hexpatch", verbose);
    }

    if let Some(name) = delete {
        return bool_op(sys.delete(&name), &name, "deleted", verbose);
    }

    if let Some(path) = file {
        return load_file(&sys, &path, verbose);
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
            if init {
                sys.set_init(&positional[0], &positional[1])
            } else {
                sys.set(&positional[0], &positional[1])
            }
            .map_err(|e| format!("failed to set {}: {e}", positional[0]))?;
            if verbose {
                eprintln!("set{}: [{}]=[{}]", if init { "(init)" } else { "" }, positional[0], positional[1]);
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

fn load_file(sys: &PropSystem, path: &str, verbose: bool) -> Result<(), String> {
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
        sys.set(name, value)
            .map_err(|e| format!("failed to set {name}: {e}"))?;
        count += 1;
        if verbose {
            eprintln!("set: [{name}]=[{value}]");
        }
    }

    eprintln!("{count} properties loaded from {path}");
    Ok(())
}

fn print_usage() {
    eprintln!(
        "resetprop — Android property manipulation tool

Usage:
  resetprop                          List all properties
  resetprop NAME                     Get property value
  resetprop [-n] NAME VALUE          Set property (direct mmap)
  resetprop --init NAME VALUE        Set property with zeroed serial counter
  resetprop -d NAME                  Delete property
  resetprop --hexpatch-delete NAME   Stealth delete (name destruction)
  resetprop -f FILE                  Load properties from file (name=value)
  resetprop --dir PATH               Use custom property directory

Options:
  --init      Zero the serial counter (mimics init for ro.* props)
  -v          Verbose output
  -h, --help  Show this help"
    );
}
