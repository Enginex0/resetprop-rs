<p align="center">
  <h1 align="center">🔧 resetprop-rs</h1>
  <p align="center"><b>Pure Rust Android Property Manipulation</b></p>
  <p align="center">Get. Set. Delete. Hexpatch. No Magisk required.</p>
  <p align="center">
    <img src="https://img.shields.io/badge/version-v0.2.0-blue?style=for-the-badge" alt="v0.2.0">
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

It also introduces `--hexpatch-delete` — a stealth operation that no existing tool provides.

---

## 🔥 Why resetprop-rs?

🔓 **Truly Standalone** — Zero runtime dependencies. No Magisk, no forked libc, no JNI. A single static binary that works on any rooted Android device.

🥷 **Hexpatch Delete** — Instead of detaching trie nodes (detectable by enumeration gaps), overwrites property name bytes with realistic dictionary words. Trie structure stays intact. Serial counters preserved. Invisible to `__system_property_foreach`.

📦 **Embeddable Library** — `resetprop` crate with typed errors, no `anyhow`. Drop it into your Rust project and manipulate properties programmatically.

⚡ **Tiny Footprint** — ~320KB ARM64, ~240KB ARMv7. Hand-rolled CLI parser, `panic=abort`, LTO, single codegen unit. Only dependency: `libc`.

🧪 **Tested Off-Device** — 29 unit tests against synthetic property areas. Verified: get, set, overwrite, delete, hexpatch, trie integrity, serial preservation, name consistency, boundary conditions.

---

## ✨ Features

**Property Operations**
- [x] **Get** — single property or list all
- [x] **Set** — direct mmap write, bypasses `property_service`
- [x] **Delete** — trie node detach + value/name wipe
- [x] **Hexpatch Delete** — dictionary-based name destruction, serial-preserving
- [x] **Batch Load** — `-f` flag loads `name=value` pairs from file

**Library API**
- [x] **`PropArea`** — single property file: open, get, set, delete, hexpatch, foreach
- [x] **`PropSystem`** — multi-file scan across `/dev/__properties__/`
- [x] **Typed errors** — `NotFound`, `AreaCorrupt`, `PermissionDenied`, `AreaFull`, `Io`, `ValueTooLong`
- [x] **RO fallback** — automatically falls back to read-only when write access is denied

**Format Support**
- [x] **Short values** — ≤91 bytes, inline in prop_info
- [x] **Long values** — Android 12+, >92 bytes via self-relative arena offset
- [x] **Serial protocol** — spin-wait on dirty bit, verification loop for concurrent reads
- [x] **Length-first comparison** — matches AOSP's `cmp_prop_name` exactly

**Stealth**
- [x] **Runtime harvest** — replacement segments drawn from the device's own property vocabulary (unfingerprintable)
- [x] **Randomized selection** — OS-seeded entropy picks different names each run
- [x] **3-tier fallback** — harvest pool → static dictionary (~95 words) → dot-split compound generation
- [x] **Plausible value** — mangled properties show value `0` instead of empty string
- [x] **Name consistency** — trie segments and prop_info name written from same source (no cross-validation mismatch)
- [x] **Length-bucketed** — replacement is always exact same byte length as original
- [x] **Shared segment detection** — skips renaming prefixes used by other properties
- [x] **No serial bump** — preserves counter bits, avoiding NativeTest detection

---

## 📋 Requirements

> [!IMPORTANT]
> Write operations (set, delete, hexpatch) require root access with appropriate SELinux context. Read operations (get, list) work for any user since property files are world-readable.

**You need:**
1. Android 10 or above
2. Root access (KernelSU, Magisk, APatch, or equivalent)
3. ARM64 or ARMv7 device

---

## 🚀 Quick Start

1. **Download** the latest binary from [Releases](https://github.com/Enginex0/resetprop-rs/releases)
2. **Push to device** — `adb push resetprop-arm64-v8a /data/local/tmp/resetprop`
3. **Set executable** — `adb shell chmod +x /data/local/tmp/resetprop`
4. **Run with root** — `adb shell su -c /data/local/tmp/resetprop`

```sh
# List all properties
resetprop

# Get a single property
resetprop ro.build.type

# Set a property (direct mmap, no init notification)
resetprop -n ro.build.type user

# Delete a property
resetprop -d ro.debuggable

# Stealth delete — name bytes replaced with dictionary words
resetprop --hexpatch-delete ro.lineage.version

# Batch set from file
resetprop -f props.txt
```

---

## 📚 Library Usage

Add to your `Cargo.toml`:
```toml
[dependencies]
resetprop = { git = "https://github.com/Enginex0/resetprop-rs" }
```

```rust
use resetprop::PropSystem;

let sys = PropSystem::open()?;

if let Some(val) = sys.get("ro.build.type") {
    println!("{val}");
}

sys.set("ro.build.type", "user")?;
sys.delete("ro.debuggable")?;
sys.hexpatch_delete("ro.lineage.version")?;

for (name, value) in sys.list() {
    println!("[{name}]: [{value}]");
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

| ABI | Binary | Size |
|-----|--------|------|
| arm64-v8a | `resetprop-arm64-v8a` | ~320KB |
| armeabi-v7a | `resetprop-armeabi-v7a` | ~240KB |

The build uses `opt-level=s`, LTO, `panic=abort`, strip, and single codegen unit for minimal binary size.

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

### Hexpatch Delete

Standard delete detaches the trie node — but apps enumerating properties can detect the gap. Hexpatch delete takes a different approach:

```
Before: ro.lineage.version = "18.1"
After:  ro.codec.charger = "0"
```

1. Harvest all property segments from the device into a length-bucketed pool
2. Walk the trie path, collecting each segment's node offset
3. For each non-shared segment, pick a same-length replacement (harvest → dict → dot-split compound)
4. Overwrite name bytes in-place, randomized selection each run
5. Write mangled name to prop_info from the same chosen segments (single source of truth)
6. Set value to `0` with correct serial encoding — indistinguishable from a boot-time property
7. **Do not bump the serial counter** — avoids NativeTest serial-monitoring detection

---

## 📱 Compatibility

| | Status |
|---|---|
| **Android** | 10 – 15 |
| **Architecture** | ARM64, ARMv7 |
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
