<p align="center">
  <h1 align="center">🔧 resetprop-rs</h1>
  <p align="center"><b>Pure Rust Android Property Manipulation</b></p>
  <p align="center">Get. Set. Delete. Stealth. Nuke. No Magisk required.</p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-v0.4.0-blue?style=for-the-badge" alt="v0.4.0">
    <img src="https://img.shields.io/badge/Android-10%2B-green?style=for-the-badge&logo=android" alt="Android 10+">
    <img src="https://img.shields.io/badge/Rust-stable-orange?style=for-the-badge&logo=rust" alt="Rust">
    <img src="https://img.shields.io/badge/Telegram-community-blue?style=for-the-badge&logo=telegram" alt="Telegram">
  </p>
</p>

---

> [!NOTE]
> **resetprop-rs is a standalone reimplementation** of Magisk's `resetprop` in pure Rust. It does not depend on Magisk, forked bionic, or any custom Android symbols. Works with any root solution — KSU, Magisk, APatch, or bare `su`.

---

## 🧬 What is resetprop-rs?

Android system properties live in mmap'd shared memory at `/dev/__properties__/`. Each file is a 128KB arena containing a prefix trie with BST siblings — the same data structure since Android 10.

Magisk's `resetprop` can manipulate these, but it's locked into Magisk's build system — it depends on a forked bionic with custom symbols (`__system_property_find2`, `__system_property_delete`, etc.) that don't exist in stock Android. You can't extract it as a standalone binary.

**resetprop-rs reimplements the entire property area format in pure Rust.** No bionic symbols. No Magisk dependency. Ships as a ~320KB static binary and an embeddable library crate.

It also introduces operations no existing tool provides: `--stealth` for detection-resistant writes, `--nuke` for count-preserving stealth deletes, `--hexpatch-delete` for dictionary-based name destruction, and `--wait` for blocking property watches. Under the hood, it parses the `property_info` binary trie for O(depth) area resolution and dual-writes to Android 14+ `appcompat_override` areas automatically.

---

## 🔥 Why resetprop-rs?

🔓 **Truly Standalone** — Zero runtime dependencies. No Magisk, no forked libc, no JNI. A single static binary that works on any rooted Android device.

🥷 **Stealth Set** — Writes property values with zeroed serial counter, no global serial bump, and no futex wake. To detection apps, the property looks like it was written by `init` at boot. Combine with `-p` for stealth persist to disk.

💀 **Nuke** — Count-preserving stealth delete. Removes the target property, inserts a plausible replacement (drawn from the device's own property vocabulary), and compacts the arena. Property count stays identical. Zero forensic traces.

🔮 **Hexpatch Delete** — Overwrites property name bytes with realistic dictionary words instead of detaching trie nodes. Trie structure stays intact. Serial counters preserved. Invisible to `__system_property_foreach`.

📦 **Embeddable Library** — `resetprop` crate with typed errors, no `anyhow`. Drop it into your Rust project and manipulate properties programmatically.

⚡ **Tiny Footprint** — ~320KB ARM64, ~240KB ARMv7. Hand-rolled CLI parser, `panic=abort`, LTO, single codegen unit. Only dependency: `libc`.

🧪 **Tested Off-Device** — 60 unit tests against synthetic property areas. Verified: get, set, overwrite, delete, hexpatch, stealth, nuke, compaction, context parsing, trie integrity, serial preservation, name consistency, boundary conditions.

---

## ✨ Features

**Property Operations**
- [x] **Get** — single property or list all
- [x] **Set** — direct mmap write, bypasses `property_service`
- [x] **Set (init-style)** — `--init` zeros the serial counter, mimicking how `init` writes `ro.*` props at boot
- [x] **Stealth Set** — `--stealth` / `-st` suppresses serial bump, global serial, and futex wake. Combine with `-p` for stealth persist
- [x] **Delete** — trie node detach + value/name wipe + orphan pruning
- [x] **Hexpatch Delete** — dictionary-based name destruction, serial-preserving
- [x] **Nuke** — `--nuke` / `-nk` count-preserving stealth delete (delete + replacement + compact in one atomic operation)
- [x] **Compact** — `--compact` defragments arenas after deletes, reclaiming space
- [x] **Persistent Properties** — `-p` writes to both memory and `/data/property/persistent_properties` on disk; `-P` reads directly from the persist file
- [x] **Batch Load** — `-f` flag loads `name=value` pairs from file
- [x] **Wait** — `--wait NAME [VALUE]` blocks until a property exists or matches, with optional `--timeout`
- [x] **Privatize** — remap areas as `MAP_PRIVATE` for per-process COW isolation

**Library API**
- [x] **`PropArea`** — single property file: open, get, set, set_stealth, delete, nuke, hexpatch, compact, foreach
- [x] **`PropSystem`** — multi-file scan across `/dev/__properties__/`
- [x] **`PersistStore`** — read/write the on-disk persistent property store (protobuf + legacy format)
- [x] **Typed errors** — `NotFound`, `AreaCorrupt`, `PermissionDenied`, `AreaFull`, `Io`, `ValueTooLong`, `PersistCorrupt`
- [x] **RO fallback** — automatically falls back to read-only when write access is denied
- [x] **Context-aware routing** — parses `property_info` binary trie for O(depth) area lookup instead of O(n) scan
- [x] **appcompat_override** — dual-writes to Android 14+ override areas, preserving write mode (stealth, init, etc.)
- [x] **Bionic fallback** — falls back to `__system_property_*` via dlsym when mmap reads are unavailable
- [x] **Wait** — `PropSystem::wait()` blocks on property changes via bionic or futex

**Format Support**
- [x] **Short values** — ≤91 bytes, inline in prop_info
- [x] **Long values** — Android 12+, >92 bytes via self-relative arena offset
- [x] **Serial protocol** — spin-wait on dirty bit, verification loop for concurrent reads
- [x] **Length-first comparison** — matches AOSP's `cmp_prop_name` exactly

**Stealth**
- [x] **Three-signal suppression** — stealth writes zero per-prop serial, skip global serial bump, and suppress futex wake
- [x] **Count-preserving nuke** — delete + plausible replacement + compaction in one operation; enumeration count unchanged
- [x] **Runtime harvest** — replacement names drawn from the device's own property vocabulary (unfingerprintable)
- [x] **Randomized selection** — OS-seeded entropy picks different names each run
- [x] **3-tier fallback** — harvest pool → static dictionary (~95 words) → dot-split compound generation
- [x] **Plausible value** — replaced/mangled properties show value `0` instead of empty string
- [x] **Name consistency** — trie segments and prop_info name written from same source (no cross-validation mismatch)
- [x] **Length-bucketed** — replacement is always exact same byte length as original
- [x] **Shared segment detection** — skips renaming prefixes used by other properties
- [x] **Arena compaction** — defragments holes left by deleted properties, eliminating forensic gaps

---

## 📋 Requirements

> [!IMPORTANT]
> Write operations (set, delete, hexpatch) require root access with appropriate SELinux context. Read operations (get, list) work for any user since property files are world-readable.

**You need:**
1. Android 10 or above
2. Root access (KernelSU, Magisk, APatch, or equivalent)
3. ARM64, ARMv7, x86_64, or x86 device/emulator

---

## 🚀 Quick Start

### Setup

1. **Download** the binary for your architecture from [Releases](https://github.com/Enginex0/resetprop-rs/releases)
2. **Push to device:**
   ```sh
   adb push resetprop-arm64-v8a /data/local/tmp/resetprop-rs
   adb shell chmod +x /data/local/tmp/resetprop-rs
   ```
3. **Run with root:**
   ```sh
   adb shell su -c /data/local/tmp/resetprop-rs
   ```

> [!WARNING]
> **Do NOT name the binary `resetprop`** if you're on KernelSU or Magisk. Both ship their own `resetprop` in `/data/adb/ksu/bin/` or `/sbin/`, and your shell will resolve to theirs instead of this one. Either:
> - Name it `resetprop-rs` (recommended)
> - Use the full path: `/data/local/tmp/resetprop-rs`
> - Place it earlier in `$PATH` than the KSU/Magisk binary

### For shell scripts and modules

If you bundle this binary in a KSU module or boot script, always call it by **full path**:

```sh
RESETPROP="/data/adb/modules/mymodule/resetprop-rs"
$RESETPROP -st ro.build.type user        # stealth set
$RESETPROP -nk ro.lineage.version        # count-preserving delete
$RESETPROP -st -p persist.sys.timezone UTC  # stealth + persist
```

Do **not** rely on bare `resetprop` in scripts. It will silently use KSU/Magisk's version, which lacks `--stealth`, `--nuke`, `--hexpatch-delete`, `--init`, `-p`, and `-P`.

---

## 📖 CLI Reference

```
resetprop-rs [OPTIONS] [NAME] [VALUE]
```

### Reading properties

```sh
# List all properties
resetprop-rs

# Get a single property
resetprop-rs ro.build.type

# List persistent properties from disk (/data/property/)
resetprop-rs -P

# Get a single persistent property from disk
resetprop-rs -P persist.sys.timezone
```

### Writing properties

```sh
# Set a property (direct mmap write, bypasses property_service)
resetprop-rs -n ro.build.type user

# Set with zeroed serial counter (mimics how init writes ro.* at boot)
resetprop-rs --init ro.build.fingerprint "google/raven/raven:14/..."

# Set and persist to disk (survives reboot)
resetprop-rs -p persist.sys.timezone UTC

# Stealth set (zeroed serial, no global serial bump, no futex wake)
resetprop-rs --stealth ro.build.type user
resetprop-rs -st ro.build.type user          # short alias

# Stealth set + persist to disk
resetprop-rs --stealth -p persist.sys.timezone UTC
resetprop-rs -st -p persist.sys.timezone UTC  # short alias

# Batch set from file (one name=value per line, # comments allowed)
resetprop-rs -f props.txt

# Batch set with init-style serial
resetprop-rs --init -f props.txt
```

### Deleting properties

```sh
# Delete (detaches trie node, zeroes value and name, prunes orphans)
resetprop-rs -d ro.debuggable

# Delete from both memory and persist file
resetprop-rs -p -d persist.sys.timezone

# Nuke: count-preserving stealth delete (delete + replacement + compact)
resetprop-rs --nuke ro.lineage.version
resetprop-rs -nk ro.lineage.version          # short alias

# Nuke from both memory and persist file
resetprop-rs -p --nuke persist.sys.timezone

# Hexpatch delete (replaces name with dictionary words, keeps trie intact)
resetprop-rs --hexpatch-delete ro.lineage.version

# Compact arenas (reclaim space from deleted properties)
resetprop-rs --compact
```

### Waiting for properties

```sh
# Wait for a property to exist (blocks until set by any process)
resetprop-rs --wait sys.boot_completed

# Wait for a property to equal a specific value
resetprop-rs --wait sys.boot_completed 1

# Wait with a timeout (exits with error if not met in time)
resetprop-rs --wait ro.crypto.state encrypted --timeout 30
```

### Options

| Flag | Description |
|------|-------------|
| `-n` | No-op (compatibility with Magisk's resetprop) |
| `--init` | Zero the serial counter when writing (mimics init for `ro.*` properties) |
| `--stealth`, `-st` | Stealth set: zeroed serial, no global serial bump, no futex wake |
| `-p` | Persist mode: write/delete affects both memory and `/data/property/` on disk |
| `-P` | Read from the persist file on disk, not from the mmap'd property area |
| `-d NAME` | Delete a property |
| `--nuke NAME`, `-nk NAME` | Count-preserving stealth delete (delete + replacement + compact). Combine with `-p` for persist |
| `--hexpatch-delete NAME` | Stealth delete with dictionary-based name replacement |
| `--compact` | Defragment arenas after deletes |
| `-f FILE` | Load `name=value` pairs from a file |
| `--wait NAME [VALUE]` | Wait for property to exist or equal VALUE. Prints the value on success |
| `--timeout SECS` | Timeout for `--wait` in seconds (default: no timeout, waits forever) |
| `--dir PATH` | Use a custom property directory instead of `/dev/__properties__/` |
| `-v` | Verbose output |
| `-h, --help` | Show help |

---

## 📚 Library Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
resetprop = "0.4"
```

Or from git:
```toml
[dependencies]
resetprop = { git = "https://github.com/Enginex0/resetprop-rs" }
```

```rust
use resetprop::{PropSystem, PersistStore};

let sys = PropSystem::open()?;

// read
if let Some(val) = sys.get("ro.build.type") {
    println!("{val}");
}

// write (direct mmap, bypasses property_service)
sys.set("ro.build.type", "user")?;

// write with zeroed serial (mimics init for ro.* props)
sys.set_init("ro.build.fingerprint", "google/raven/...")?;

// stealth write (zeroed serial, no global serial bump, no futex wake)
sys.set_stealth("ro.build.type", "user")?;

// stealth write + persist to disk
sys.set_stealth_persist("persist.sys.timezone", "UTC")?;

// write to both memory and disk
sys.set_persist("persist.sys.timezone", "UTC")?;

// delete
sys.delete("ro.debuggable")?;
sys.delete_persist("persist.sys.timezone")?;

// nuke: count-preserving stealth delete
sys.nuke("ro.lineage.version")?;
sys.nuke_persist("persist.sys.timezone")?;

// hexpatch delete (dictionary-based name destruction)
sys.hexpatch_delete("ro.custom.prop")?;

// compact arenas after deletes
sys.compact()?;

// wait for a property to equal a value (30s timeout)
use std::time::Duration;
if let Some(val) = sys.wait("sys.boot_completed", Some("1"), Some(Duration::from_secs(30))) {
    println!("boot completed: {val}");
}

// enumerate
for (name, value) in sys.list() {
    println!("[{name}]: [{value}]");
}

// read persist file directly
let store = PersistStore::load()?;
for record in store.list() {
    println!("{}: {}", record.name, record.value);
}
```

---

## 🏗️ Building

Requires Android NDK for cross-compilation:

```sh
export ANDROID_NDK_HOME=/path/to/ndk
./build.sh
```

Outputs stripped binaries to `out/`:

| ABI | Binary |
|-----|--------|
| arm64-v8a | `resetprop-arm64-v8a` |
| armeabi-v7a | `resetprop-armeabi-v7a` |
| x86_64 | `resetprop-x86_64` |
| x86 | `resetprop-x86` |

The build uses `opt-level=s`, LTO, `panic=abort`, strip, and single codegen unit for minimal binary size.

**No NDK?** Fork the repo and go to **Actions → Build → Run workflow** — GitHub builds all four ABIs for you. Download them from the workflow artifacts.

---

## 🧠 How It Works

### Property Area Format

Each file in `/dev/__properties__/` is a 128KB mmap'd arena:

```
┌─────────────────────────────────────┐
│ Header (128 bytes)                  │
│   [0x00] bytes_used: u32            │
│   [0x04] serial: AtomicU32          │
│   [0x08] magic: 0x504f5250 "PROP"   │
│   [0x0C] version: 0xfc6ed0ab        │
├─────────────────────────────────────┤
│ Arena (bump-allocated, append-only) │
│   ┌─ prop_trie_node ──────────┐    │
│   │ namelen(4) prop(4) left(4)│    │
│   │ right(4) children(4)      │    │
│   │ name[namelen+1] (aligned) │    │
│   └───────────────────────────┘    │
│   ┌─ prop_info ───────────────┐    │
│   │ serial(4) value[92]       │    │
│   │ name[] (full dotted name) │    │
│   └───────────────────────────┘    │
└─────────────────────────────────────┘
```

Property names split on dots into a prefix trie. Each trie level uses a BST for siblings, compared **length-first then lexicographically** (not standard strcmp).

### Stealth Set

Standard `set()` bumps three detection signals: per-property serial, global serial (via `notify()`), and futex wake. Any monitoring app can observe these. Stealth set suppresses all three:

```
resetprop-rs --stealth ro.build.type user
```

1. Write value with zeroed serial counter (`(value.len() << 24)`, same encoding as `init`)
2. Skip `notify()` entirely (no global serial bump via `bump_serial_and_wake`)
3. Skip `futex_wake()` on the property's serial address
4. New properties created via stealth are already silent (the allocation path never wakes)

The result is indistinguishable from a property written by `init` at boot. Combine with `-p` to also persist to `/data/property/persistent_properties`.

### Nuke (Count-Preserving Delete)

Standard delete leaves a gap in the enumeration count. Hexpatch preserves count but leaves renamed trie segments. Nuke achieves both: zero artifacts AND preserved count.

```
Before: ro.lineage.version = "18.1"  (2389 props total)
After:  (original gone, plausible replacement added, 2389 props total)
```

1. Delete the target property (detach trie node, wipe prop_info, prune orphans)
2. Scan the area for existing property prefixes, pick the busiest prefix (most natural to add a sibling)
3. Generate a plausible leaf segment (harvest pool → dictionary → compound generation)
4. Insert the replacement via stealth write with value `"0"` (zeroed serial, no wake)
5. Compact the arena to eliminate holes from the deletion
6. Net result: target gone, replacement blends in, count unchanged, no detection signals fired

### Hexpatch Delete

An alternative stealth delete that keeps the trie structure intact by overwriting name bytes in-place:

```
Before: ro.lineage.version = "18.1"
After:  ro.codec.charger = "0"
```

1. Harvest all property segments from the device into a length-bucketed pool
2. Walk the trie path, collecting each segment's node offset
3. For each non-shared segment, pick a same-length replacement (harvest → dict → dot-split compound)
4. Overwrite name bytes in-place, randomized selection each run
5. Write mangled name to prop_info from the same chosen segments (single source of truth)
6. Set value to `0` with correct serial encoding
7. No serial bump, no futex wake

### Context-Aware Area Resolution

Android stores properties across multiple files in `/dev/__properties__/`, one per SELinux context. The file `property_info` is a binary trie that maps property name prefixes to the correct area file.

resetprop-rs parses this trie on startup, enabling O(depth) lookup by property name instead of scanning every area file linearly. The algorithm walks the trie segment-by-segment (split on `.`), checking node contexts, prefix entries, child nodes, and exact matches at each level.

On Android 8-9 (pre-serialized format), it falls back to parsing text `property_contexts` files. If neither is available, it falls back to the original linear scan.

### appcompat_override (Android 14+)

Android 14 introduced `/dev/__properties__/appcompat_override/`, a mirror directory containing duplicate property areas for app compatibility. When a property is set or deleted, the system writes to both the main area and the corresponding override file.

resetprop-rs detects this directory and automatically dual-writes to the mirror when performing `set`, `set_init`, `set_stealth`, or `delete` operations. The override write uses the same mode as the main write (stealth for stealth, init for init). Override failures are silently ignored.

### Bionic Fallback

On Android, if a property can't be found via direct mmap (e.g., areas not directly accessible), resetprop-rs falls back to bionic's `__system_property_find` and `__system_property_read_callback` loaded via `dlsym` at runtime. This is a secondary path; the primary pure mmap path is always tried first.

The `--wait` command also uses bionic's `__system_property_wait` when available, falling back to `futex_wait` on the property's serial address (or the global serial for properties that don't exist yet).

---

## 📱 Compatibility

| | Status |
|---|---|
| **Android** | 10 – 15 |
| **Architecture** | ARM64, ARMv7, x86_64, x86 |
| **Value format** | Short (≤91B) + Long (Android 12+, >92B) |
| **Root** | KernelSU, Magisk, APatch, any `su` |

---

## 💬 Community

<p align="center">
  <a href="https://t.me/superpowers9">
    <img src="https://img.shields.io/badge/⚡_JOIN_THE_GRID-SuperPowers_Telegram-black?style=for-the-badge&logo=telegram&logoColor=cyan&labelColor=0d1117&color=00d4ff" alt="Telegram">
  </a>
</p>

---

## 🙏 Credits

- **[hiking90/rsproperties](https://github.com/nicetynio/rsproperties)** — Rust property area parser that proved the approach viable (Apache-2.0)
- **[topjohnwu/Magisk](https://github.com/topjohnwu/Magisk)** — original `resetprop` and the forked bionic approach
- **[Pixel-Props/sensitive-props](https://github.com/Pixel-Props/sensitive-props?tab=readme-ov-file)** — property spoofing reference that informed the target property list
- **[AOSP bionic](https://android.googlesource.com/platform/bionic/)** — canonical property area format specification
- **[frknkrc44](https://github.com/frknkrc44)** — aspiration, proposed building this project

### Contributors

- **[fatalcoder524](https://github.com/fatalcoder524)** — stealth strategy design and testing

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <b>🔧 Because the best property manipulation is the one init never noticed.</b>
</p>
