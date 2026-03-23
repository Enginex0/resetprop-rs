# resetprop

Pure Rust library for Android system property manipulation. No Magisk, no forked bionic, no JNI.
Works with any root solution (KernelSU, Magisk, APatch, bare `su`).

## Usage

```toml
[dependencies]
resetprop = "0.3"
```

Or as a git dependency:

```toml
[dependencies]
resetprop = { git = "https://github.com/Enginex0/resetprop-rs" }
```

## Example

```rust,no_run
use resetprop::PropSystem;

fn main() -> resetprop::Result<()> {
    let sys = PropSystem::open()?;

    // read
    if let Some(val) = sys.get("ro.build.type") {
        println!("{val}");
    }

    // write (direct mmap, bypasses property_service)
    sys.set("ro.build.type", "user")?;

    // delete
    sys.delete("ro.debuggable")?;

    // stealth delete (name bytes replaced with dictionary words)
    sys.hexpatch_delete("ro.lineage.version")?;

    // enumerate
    for (name, value) in sys.list() {
        println!("[{name}]: [{value}]");
    }

    Ok(())
}
```

## API

**`PropSystem`** scans `/dev/__properties__/` and provides the high-level interface:
`get`, `set`, `set_init`, `delete`, `hexpatch_delete`, `set_persist`, `delete_persist`, `list`, `privatize`.

**`PropArea`** operates on a single property file for low-level control:
`open`, `open_ro`, `get`, `set`, `set_init`, `delete`, `hexpatch_delete`, `foreach`.

**`PersistStore`** reads and writes the persistent property store at `/data/property/`:
`load`, `get`, `set`, `delete`, `list`.

## Requirements

- Android 10+
- Root access for write operations (read is world-accessible)
- Only dependency: `libc`

## License

MIT
