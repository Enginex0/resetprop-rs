# Changelog

## v0.3.1

- Library crate now publishable to crates.io with full metadata (repository, keywords, categories)
- Crate-level README for the library, focused on API usage and dependency setup
- Public API doc comments on all exported types and methods for docs.rs
- Re-export `Record` from crate root so consumers can use `resetprop::Record` directly
- CLI crate also carries crates.io metadata for independent publishing
- Version bump from 0.2.0 to 0.3.1 to align Cargo.toml with tag history

## v0.3.0

- Persistent property support via `-p` and `-P` flags
- `-p` writes to both prop_area (memory) and `/data/property/persistent_properties` (disk)
- `-P` reads directly from the persist file without requiring prop_area access
- Hand-rolled proto2 encode/decode matching AOSP's `PersistentProperties` schema
- Atomic write with SELinux xattr preservation, matching AOSP's temp+rename+fsync pattern
- Legacy format read support for pre-Android 9 devices (one file per property)
- `PersistStore` public API: load, get, set, delete, list
- `PropSystem::set_persist()` and `PropSystem::delete_persist()` for dual memory+disk writes

## v0.2.1

- Add `set_init()` API for init-style serial writes on ro.* properties
- `write_value_init()` zeroes the low-24 counter bits instead of incrementing by 2
- Handles both short and long (kLongFlag) property values
- Exposed at `PropArea::set_init()` and `PropSystem::set_init()`
- CLI: `--init` flag for init-style writes (`resetprop --init ro.build.fingerprint "..."`)
- CLI: `--init` works with `-f` file load (`resetprop --init -f props.txt`)

## v0.2.0

- Stealth overhaul: runtime harvest, plausible hexpatch values, name consistency
- `privatize()` for per-process prop isolation via COW
- Harden prop area against corrupt data, add futex wake
- Protect intermediate trie nodes with own properties during hexpatch
- Randomize pool selection and add dot-split generation for harvest
- On-device stress test and stealth verification
- Manual build workflow for fork users

## v0.1.0

- Initial release: pure Rust property area manipulation
- Get, set, delete, list, foreach operations
- `hexpatch_delete` for stealth property removal
- Trie-based property lookup matching AOSP format
- Cross-compiled for arm64, arm, x86_64, x86
