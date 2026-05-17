# Changelog

## v0.5.0

### Seal (Two-Tier Property Locking)
- `--seal NAME VALUE` / `-sl`: Tier B per-prop hook installed in init via ptrace plus remote `mmap`. Only the named property freezes; neighbour properties keep updating normally.
- `--seal-arena NAME VALUE` / `-sla`: Tier A arena-level `MAP_PRIVATE|MAP_FIXED` remap in init. Broader blast radius, used as a manual fallback when Tier B refuses (`HookInstallFailed`, `ElfParse`, `SymbolNotFound`).
- `--unseal NAME` and `--unseal-arena NAME` revert a specific seal. `--seals` lists active seal records (name, tier, arena path).
- AArch64 only at runtime. Builds for other ABIs return `Error::Unsupported` rather than corrupting init's libc.text.
- File-backed hook page at `/data/adb/resetprop-rs/hook-<pid>-<nanos>.bin`, unlinked post-`mmap` so `process:execmem` SELinux class is never exercised.
- In-session only: seals do not persist across reboots, `SystemProperties::Reload`, or init restart. Re-apply on every boot.
- Library API: `PropSystem::seal`, `PropSystem::unseal`, `PropSystem::seal_arena`, `PropSystem::unseal_arena`, `PropSystem::seals`.

### Conditional Property Primitives
- `--if-diff` with positional NAME VALUE: write only when the property exists and the current value differs from VALUE.
- `--if-match NEEDLE` with positional NAME VALUE: write only when the current value equals NEEDLE and differs from VALUE.
- `--delete-if-exist NAME`: delete only when the property is present, exit 0 on absent.
- All three skip absent properties and short-circuit equal-value writes so the per-prop serial never bumps spuriously.
- Library API: `PropSystem::set_if_diff`, `PropSystem::set_if_match`.

### Wait For Value
- `--wait NAME [VALUE]` with optional `--timeout SECS` blocks until the property either exists (no VALUE) or equals VALUE.
- Library API: `PropSystem::wait(name, expected, timeout)` returns `Some(value)` on match, `None` on timeout.

### Bionic-Correct Serial Discipline
- `normalize_serial` API canonicalises the dirty bit and length field on an existing entry without bumping the serial counter. Mirrors the `fix_serials` step real init runs at boot.
- Seal write routes `ro.*` properties through `set_stealth` (no listeners, so a wake would be the detection signal) and everything else through `set_init` (real listeners present, so a missing wake would be the signal).
- Hybrid wake policy: `futex_wake` only fires when listeners exist on the prop. Tracer-busy errors now surface the holding pid for diagnosis.

### Build And CI Hardening
- New `Error::Unsupported(String)` variant for arch-gated features.
- Release matrix runs with `fail-fast: false`. One failed ABI no longer cancels the other three in flight.
- Release-artifact build scoped to `cargo build -p resetprop-cli`. Toolchain quirks in `propdetect-bionic` no longer block the shipping binary.
- Tagged releases auto-publish: `release.yml` extracts the matching `## vX.Y.Z` section from `CHANGELOG.md` via awk and feeds it to `softprops/action-gh-release` as the release body.
- Workspace lints clean under Rust 1.95.0 (`clippy::sort_by_key`, `clippy::collapsible_match`).

### Testing
- 133 library unit tests (up from 50 at v0.4.0). Five integration test binaries cover ptrace primitives, Tier A and Tier B child isolation, ELF fixture parsing, plus the existing doc tests.
- New seal coverage: A64 encoder vectors versus canonical opcodes, hook body splice equivalence, lock-list capacity envelope, PT_DYNAMIC duplicate-tolerant parsing.
- Device-side stress: Tests 21 and 22 exercise seal under SELinux denials and ksu_props bypass probes.

## v0.4.0

### Stealth Set
- `--stealth` / `-st` flag for detection-resistant property writes
- Suppresses all three detection vectors: per-property serial (zeroed), global serial bump (no `notify()`), and futex wake (skipped)
- Combine with `-p` for stealth persist: `resetprop -st -p persist.sys.timezone UTC`
- Library API: `PropSystem::set_stealth()`, `PropSystem::set_stealth_persist()`

### Nuke (Count-Preserving Delete)
- `--nuke` / `-nk` flag for atomic count-preserving stealth deletion
- Pipeline: delete target → generate plausible replacement (harvested from device vocabulary) → stealth-insert with value `"0"` → compact arena
- Property count stays identical after nuke; zero forensic traces
- Library API: `PropSystem::nuke()`, `PropArea::nuke()`

### Arena Compaction
- `--compact` flag to defragment arenas after deletes
- Slides live allocations forward to fill holes, rebuilding trie offsets in-place
- Library API: `PropSystem::compact()`, `PropArea::compact()`

### Trie Pruning
- `delete()` now prunes orphaned trie leaves after detaching the property
- Thorough `wipe()` zeroes the full prop_info record (header, long value, name)

### Detection Test Harness
- New `propdetect` crate: adversarial validation against real detection heuristics (serial anomalies, count drift, name entropy, enumeration gaps)
- `propdetect-bionic` variant for on-device validation against libc's `__system_property_*` API

### Testing
- 50 unit tests + 2 doc-tests (up from 29)
- On-device stress test script: 10 test cases covering stealth, nuke, rapid cycles, and neighbor preservation

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
