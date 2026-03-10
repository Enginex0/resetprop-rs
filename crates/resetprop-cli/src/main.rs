use anyhow::{bail, Context, Result};
use clap::Parser;
use resetprop::PropSystem;

#[derive(Parser)]
#[command(name = "resetprop", about = "Android system property manipulation tool")]
struct Cli {
    /// Bypass property_service, write directly to mmap
    #[arg(short = 'n')]
    skip_svc: bool,

    /// Verbose output
    #[arg(short = 'v')]
    verbose: bool,

    /// Delete property
    #[arg(short = 'd', long = "delete", value_name = "NAME")]
    delete: Option<String>,

    /// Hexpatch-delete property (stealth name destruction)
    #[arg(long = "hexpatch-delete", value_name = "NAME")]
    hexpatch_delete: Option<String>,

    /// Property directory (default: /dev/__properties__)
    #[arg(long = "dir", value_name = "PATH")]
    dir: Option<String>,

    /// Positional args: NAME [VALUE]
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let sys = match &cli.dir {
        Some(d) => PropSystem::open_dir(std::path::Path::new(d)),
        None => PropSystem::open(),
    }
    .context("failed to open property system")?;

    if let Some(name) = &cli.hexpatch_delete {
        let ok = sys
            .hexpatch_delete(name)
            .context("hexpatch-delete failed")?;
        if !ok {
            bail!("property not found: {name}");
        }
        if cli.verbose {
            eprintln!("hexpatch: {name}");
        }
        return Ok(());
    }

    if let Some(name) = &cli.delete {
        let ok = sys.delete(name).context("delete failed")?;
        if !ok {
            bail!("property not found: {name}");
        }
        if cli.verbose {
            eprintln!("deleted: {name}");
        }
        return Ok(());
    }

    match cli.args.len() {
        0 => {
            for (name, value) in sys.list() {
                println!("[{name}]: [{value}]");
            }
        }
        1 => {
            let name = &cli.args[0];
            match sys.get(name) {
                Some(val) => println!("{val}"),
                None => bail!("property not found: {name}"),
            }
        }
        2 => {
            let name = &cli.args[0];
            let value = &cli.args[1];
            sys.set(name, value)
                .context(format!("failed to set {name}"))?;
            if cli.verbose {
                eprintln!("set: [{name}]=[{value}]");
            }
        }
        _ => bail!("too many arguments"),
    }

    Ok(())
}
