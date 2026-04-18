# Rust ptrace Integration Test Harness Patterns

Reference for writing `tests/tier_a_child_smoke.rs` and `tests/tier_b_child_smoke.rs` in the resetprop-rs workspace. The crate exposes only `libc` as a runtime dependency and `tempfile = "3"` as a dev-dependency (`crates/resetprop/Cargo.toml:13-17`). No `nix`. No shell-outs. Fork, ptrace, mmap, `process_vm_readv` all go through raw `libc::*` FFI.

---

## 1. Why integration tests, not unit tests

The seal module's ptrace/arena code manipulates another Linux process's address space. A unit test running inside a single `cargo test` binary cannot ptrace itself (`PTRACE_ATTACH` on the tracer's own thread fails with `EPERM`; per `man 2 ptrace`: "A tracer cannot attach to itself"). Only a separately-forked child can be the tracee, which mandates an integration test with its own process lifecycle. Unit tests under `#[cfg(test)] mod tests` (see `crates/resetprop/src/mock.rs:48`) stay in-process and cannot exercise the remote-address-space paths.

---

## 2. CAP_SYS_PTRACE / yama gating

Modern Linux distros ship with Yama LSM enabled, which restricts ptrace to descendants by default (Debian/Ubuntu default is `/proc/sys/kernel/yama/ptrace_scope = 1`, per <https://www.kernel.org/doc/Documentation/admin-guide/LSM/Yama.rst>). Child processes of the tracer are still ptraceable under `ptrace_scope=1` because fork-descendants are exempt, so the tests in this suite (which always ptrace their own `fork()` child) work under the default policy. Fail-fast check: read `/proc/sys/kernel/yama/ptrace_scope`; if it is `2` or `3`, skip with a clear message.

Gate ptrace-dependent tests with `#[ignore]` (per <https://doc.rust-lang.org/book/ch11-02-running-tests.html#ignoring-some-tests-unless-specifically-requested>) so default `cargo test` stays green on hosts without kernel.yama.ptrace_scope = 0 or CAP_SYS_PTRACE:

```rust
#[test]
#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]
fn seal_arena_blocks_child_writes_from_reaching_file() { /* ... */ }
```

Invocation (documented at top of each test file):

```text
cargo test --test tier_a_child_smoke -- --ignored --test-threads=1
cargo test --test tier_b_child_smoke -- --ignored --test-threads=1
```

`--test-threads=1` is mandatory. Parallel forks from a shared Rust test harness race on signal delivery, zombie reaping, and `PTRACE_ATTACH` ordering; this is the standard workaround documented across the Rust ecosystem (e.g., nix's own ptrace tests use `serial_test`, see <https://github.com/nix-rust/nix/blob/master/test/sys/test_ptrace.rs>).

---

## 3. Sacrificial child pattern

Minimal fork helper and a `Drop` guard that guarantees the child is reaped even on panic. Goes at the top of both test files:

```rust
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Fork a child running `child_body`; return the child pid to the parent.
/// Safety: `child_body` must not return (it should `_exit`, `loop`, or `panic!`).
unsafe fn fork_child<F: FnOnce() -> !>(child_body: F) -> libc::pid_t {
    let pid = libc::fork();
    assert!(pid >= 0, "fork() failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        child_body();
    }
    pid
}

/// RAII guard: SIGKILL + waitpid the child in Drop so a panicking test
/// never leaves a zombie or a running tracee.
struct ChildGuard(libc::pid_t);

impl ChildGuard {
    fn pid(&self) -> libc::pid_t { self.0 }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        unsafe {
            // Best effort; ESRCH if already gone is fine.
            libc::kill(self.0, libc::SIGKILL);
            let mut status: libc::c_int = 0;
            // WNOHANG first in case the child is already reaped; then blocking wait
            // to guarantee zombie drain before the test harness returns.
            libc::waitpid(self.0, &mut status, libc::WNOHANG);
            libc::waitpid(self.0, &mut status, 0);
        }
    }
}

fn sleep_ms(ms: u64) { std::thread::sleep(Duration::from_millis(ms)); }
```

---

## 4. Tier A test skeleton — `tests/tier_a_child_smoke.rs`

Full file. The child mmaps a `tempfile::NamedTempFile` as `MAP_SHARED` and loops writing a sentinel byte. The parent ptrace-remaps the child's mapping to `MAP_PRIVATE|MAP_FIXED` via `seal::arena::seal_arena(pid, path)`, then asserts that subsequent child writes no longer propagate to the file.

```rust
//! Tier A: arena-wide seal via remote MAP_PRIVATE|MAP_FIXED remap.
//!
//! Runner: `cargo test --test tier_a_child_smoke -- --ignored --test-threads=1`
//! Requires: /proc/sys/kernel/yama/ptrace_scope <= 1 OR CAP_SYS_PTRACE.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PAGE_SIZE: usize = 4096;
const ARENA_PAGES: usize = 4;
const ARENA_SIZE: usize = PAGE_SIZE * ARENA_PAGES;
const SENTINEL_OFFSET: usize = 128;
const SENTINEL_PRE: u8 = 0xAA;
const SENTINEL_POST: u8 = 0xBB;

// [fork_child, ChildGuard, sleep_ms — reproduced from §3]

fn child_body_mmap_loop(path: PathBuf) -> ! {
    unsafe {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let fd = libc::open(c_path.as_ptr(), libc::O_RDWR);
        assert!(fd >= 0);
        let addr = libc::mmap(
            std::ptr::null_mut(),
            ARENA_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        assert_ne!(addr, libc::MAP_FAILED);
        let base = addr as *mut u8;

        // Phase 1: write SENTINEL_PRE until parent seals.
        // Phase 2: flip to SENTINEL_POST and keep writing; parent will assert
        // the file NEVER sees SENTINEL_POST because the arena is now MAP_PRIVATE.
        let byte_ptr = base.add(SENTINEL_OFFSET);
        loop {
            std::ptr::write_volatile(byte_ptr, SENTINEL_POST);
            libc::usleep(10_000);
        }
    }
}

fn read_file_byte(path: &Path, offset: usize) -> u8 {
    let mut f = OpenOptions::new().read(true).open(path).unwrap();
    f.seek(SeekFrom::Start(offset as u64)).unwrap();
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).unwrap();
    buf[0]
}

#[test]
#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]
fn seal_arena_blocks_child_writes_from_reaching_file() {
    // --- Setup: backing file with SENTINEL_PRE pre-written so we can detect regression.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    {
        let mut f = OpenOptions::new().write(true).open(tmp.path()).unwrap();
        f.set_len(ARENA_SIZE as u64).unwrap();
        f.seek(SeekFrom::Start(SENTINEL_OFFSET as u64)).unwrap();
        f.write_all(&[SENTINEL_PRE]).unwrap();
        f.sync_all().unwrap();
    }
    let path = tmp.path().to_path_buf();

    // --- Fork child and track with ChildGuard so panic paths still reap it.
    let child_pid = unsafe { fork_child(|| child_body_mmap_loop(path.clone())) };
    let guard = ChildGuard(child_pid);

    // Let the child install its mapping and start its write loop.
    sleep_ms(100);

    // Baseline: child has already been writing SENTINEL_POST; file should reflect it.
    let before = read_file_byte(&path, SENTINEL_OFFSET);
    assert_eq!(before, SENTINEL_POST,
        "pre-seal: file must see child writes through MAP_SHARED");

    // --- Install the seal: remap child's arena MAP_PRIVATE|MAP_FIXED.
    resetprop::seal::arena::seal_arena(guard.pid(), &path)
        .expect("seal_arena should succeed under ptrace_scope<=1");

    // Overwrite the sentinel on disk to a known marker that the child's
    // future writes must NOT clobber (they're COW'd away from the file now).
    {
        let mut f = OpenOptions::new().write(true).open(&path).unwrap();
        f.seek(SeekFrom::Start(SENTINEL_OFFSET as u64)).unwrap();
        f.write_all(&[SENTINEL_PRE]).unwrap();
        f.sync_all().unwrap();
    }

    // Give the child plenty of time to keep writing SENTINEL_POST to its
    // now-private mapping. If seal worked, the file stays SENTINEL_PRE.
    sleep_ms(200);

    let after = read_file_byte(&path, SENTINEL_OFFSET);
    assert_eq!(after, SENTINEL_PRE,
        "post-seal: child writes must NOT propagate to the file (MAP_PRIVATE COW)");

    // guard drops -> SIGKILL + waitpid; tmp drops -> file unlinked.
}
```

---

## 5. Tier B test skeleton — `tests/tier_b_child_smoke.rs`

Child owns a fake `__system_property_update`. Parent installs the hook and verifies writes to `locked.prop` are dropped while `free.prop` writes land. Inline symbol is the MVP choice (see §9); cdylib variant is sketched in §8.

```rust
//! Tier B: per-prop hook via __system_property_update trampoline rewrite.
//!
//! Build with `rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]` in
//! `.cargo/config.toml` so the test binary's own __system_property_update is
//! visible in its dynsym table for remote GNU_HASH lookup. (Per
//! <https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002dexport_002ddynamic>.)

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

// --- Fake prop_info layout exactly matches bionic:
// serial:u32 (offset 0) + value[92] (offset 4..96) + name[] (offset 96..)
// Ref: crates/resetprop/src/info.rs:6 (PROP_INFO_FIXED = 96)
const PI_FIXED: usize = 96;

#[repr(C)]
struct FakePropInfoHeader {
    serial: AtomicU32,
    value: [u8; 92],
    // name[] follows at byte offset 96 in the backing buffer.
}
const _: () = assert!(std::mem::size_of::<FakePropInfoHeader>() == PI_FIXED);

/// Heap-pinned prop_info: the bytes live in a Box<[u8]> that we never reallocate,
/// so its address is stable across ptrace reads from the parent.
struct PinnedPi {
    buf: Box<[u8]>,  // length = PI_FIXED + name.len() + 1
}

impl PinnedPi {
    fn new(name: &str) -> Self {
        let mut v = vec![0u8; PI_FIXED + name.len() + 1];
        v[PI_FIXED..PI_FIXED + name.len()].copy_from_slice(name.as_bytes());
        Self { buf: v.into_boxed_slice() }
    }
    fn as_ptr(&self) -> *const u8 { self.buf.as_ptr() }
    fn value_bytes(&self) -> &[u8; 92] {
        // Safety: header is the first PI_FIXED bytes, value starts at offset 4.
        unsafe { &*(self.buf.as_ptr().add(4) as *const [u8; 92]) }
    }
}

// --- The symbol the hook will rewrite. `#[no_mangle]` + `extern "C"` puts it
// in .dynsym when the binary is built with --export-dynamic (see .cargo/config.toml).
#[no_mangle]
pub extern "C" fn __system_property_update(
    pi: *mut u8,
    value: *const u8,
    len: u32,
) -> libc::c_int {
    // Real implementation: bump serial, memcpy value into pi+4.
    unsafe {
        if pi.is_null() || value.is_null() { return -1; }
        let serial_atomic = &*(pi as *const AtomicU32);
        let s = serial_atomic.fetch_add(1, Ordering::AcqRel);
        // Write new length into the high byte, flip dirty bit, etc.
        // For the test it's enough to copy `len` bytes.
        let dst = pi.add(4);
        let n = (len as usize).min(91);
        std::ptr::copy_nonoverlapping(value, dst, n);
        *dst.add(n) = 0;
        serial_atomic.store(s.wrapping_add(2), Ordering::Release);
        0
    }
}

// [fork_child, ChildGuard, sleep_ms — reproduced from §3]

static CHILD_RUN: AtomicBool = AtomicBool::new(true);

fn child_body_update_loop(locked_pi: *const u8, free_pi: *const u8) -> ! {
    // Child alternates updates between the two pi*s.
    let mut tick: u32 = 0;
    loop {
        let pi = if tick & 1 == 0 { locked_pi } else { free_pi };
        let val = format!("v{tick}");
        unsafe {
            let _ = __system_property_update(
                pi as *mut u8,
                val.as_ptr(),
                val.len() as u32,
            );
        }
        tick = tick.wrapping_add(1);
        unsafe { libc::usleep(5_000); }
    }
}

/// Remote read via libc::process_vm_readv. Returns value bytes at pi+4..pi+96.
fn read_remote_value(pid: libc::pid_t, pi: *const u8) -> [u8; 92] {
    let mut out = [0u8; 92];
    let local = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut _,
        iov_len: 92,
    };
    let remote = libc::iovec {
        iov_base: unsafe { pi.add(4) } as *mut _,
        iov_len: 92,
    };
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    assert_eq!(n, 92, "process_vm_readv: {}", std::io::Error::last_os_error());
    out
}

#[test]
#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]
fn hook_blocks_locked_prop_writes_and_permits_free_prop_writes() {
    // PinnedPi must outlive the child fork for its address to be meaningful;
    // after fork() the child inherits the same VA layout via COW.
    let locked = PinnedPi::new("locked.prop");
    let free   = PinnedPi::new("free.prop");
    let locked_ptr = locked.as_ptr();
    let free_ptr   = free.as_ptr();

    let child_pid = unsafe { fork_child(move || child_body_update_loop(locked_ptr, free_ptr)) };
    let guard = ChildGuard(child_pid);

    sleep_ms(100);

    // Snapshot initial value bytes from the child via process_vm_readv.
    let locked_before = read_remote_value(guard.pid(), locked_ptr);
    let free_before   = read_remote_value(guard.pid(), free_ptr);

    // --- Install hook and seal "locked.prop".
    let handle = resetprop::seal::hook::install_init_hook(guard.pid())
        .expect("install_init_hook");
    resetprop::seal::hook::seal_prop(&handle, "locked.prop")
        .expect("seal_prop");

    sleep_ms(200);

    let locked_after = read_remote_value(guard.pid(), locked_ptr);
    let free_after   = read_remote_value(guard.pid(), free_ptr);

    assert_eq!(locked_before, locked_after,
        "locked.prop: hook must prevent child from mutating value bytes");
    assert_ne!(free_before, free_after,
        "free.prop: non-sealed name must continue updating");
}
```

---

## 6. Building a fake prop_info in test code

The `PinnedPi` struct in §5 is the ready-to-paste version. It matches the layout asserted at `crates/resetprop/src/info.rs:6` (`PROP_INFO_FIXED = 96`, `value[92]`) and the name-at-offset-96 convention at `crates/resetprop/src/info.rs:90`. Key guarantees:

- `Box<[u8]>` keeps the address stable across the test's lifetime (no reallocation, unlike `Vec::push`).
- Child inherits the same virtual address via `fork()` COW — the parent's `locked_ptr` is valid in the child's address space for both `process_vm_readv` and ptrace pokes.
- `#[repr(C)]` guarantees no Rust-inserted padding; the `const _: () = assert!` line is a compile-time layout check.

---

## 7. Why not mock via `mockall`

`mockall` (<https://docs.rs/mockall>) generates substitute impls at the Rust trait/function boundary. The seal hook works by rewriting the first bytes of the callee's machine code — it needs a real `(void*, void*, u32) -> int` entry point with a stable load address in the tracee's memory, resolved via the ELF dynsym/GNU_HASH chain. A mock object lives inside the Rust test process as a generic parameter with no fixed address; ptrace has nothing to attach to. Inline `#[no_mangle] pub extern "C" fn __system_property_update` gives us both a predictable symbol name and a real VA.

---

## 8. cdylib fixture location

Stretch-goal variant: ship a tiny shared object so the test exercises GNU_HASH resolution across multiple `.so`s (the same path real Android processes use). Recommended layout:

```text
crates/resetprop/tests/fixtures/fake_libc/
├── Cargo.toml
└── src/lib.rs
```

`crates/resetprop/tests/fixtures/fake_libc/Cargo.toml`:

```toml
[package]
name = "fake_libc"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]
path = "src/lib.rs"

[dependencies]
libc = "0.2"
```

`crates/resetprop/tests/fixtures/fake_libc/src/lib.rs`:

```rust
use std::sync::atomic::{AtomicU32, Ordering};

#[no_mangle]
pub extern "C" fn __system_property_update(
    pi: *mut u8,
    value: *const u8,
    len: u32,
) -> libc::c_int {
    unsafe {
        if pi.is_null() || value.is_null() { return -1; }
        let serial = &*(pi as *const AtomicU32);
        let s = serial.fetch_add(1, Ordering::AcqRel);
        let dst = pi.add(4);
        let n = (len as usize).min(91);
        std::ptr::copy_nonoverlapping(value, dst, n);
        *dst.add(n) = 0;
        serial.store(s.wrapping_add(2), Ordering::Release);
        0
    }
}
```

Build + load:

```rust
// build.rs-style one-shot compile inside a #[ctor]-free helper:
let status = std::process::Command::new(env!("CARGO"))
    .args(["build", "--manifest-path",
           "crates/resetprop/tests/fixtures/fake_libc/Cargo.toml",
           "--release"])
    .status().expect("cargo build");
assert!(status.success());

let so = "target/release/libfake_libc.so";
let c = std::ffi::CString::new(so).unwrap();
let handle = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW) };
assert!(!handle.is_null(), "dlopen");
```

---

## 9. Inline vs external fixture

| Dimension | Inline `#[no_mangle] extern "C"` | External cdylib via `dlopen` |
|---|---|---|
| Setup cost | Zero; symbol lives in the test binary | Extra `Cargo.toml`, extra `cargo build` step |
| Symbol lookup path | One ELF (the test binary itself) | Multiple ELFs; exercises real GNU_HASH chain walking |
| Production fidelity | Lower — single .so vs real Android's multi-so layout | Higher |
| Flakiness surface | Small | Larger (build path, LD_LIBRARY_PATH, relative manifest paths) |
| Required linker arg | `-Wl,--export-dynamic` in `.cargo/config.toml` so test binary exposes the symbol in its dynsym | None beyond cdylib default |

**Recommendation**: ship inline for MVP (both Tier A and Tier B land with a single file each). Add cdylib in a later phase when the hook's GNU_HASH walker needs multi-so regression coverage.

`.cargo/config.toml` addition for the inline path (the crate's existing `.cargo/` dir is at `/home/president/Git-repo-success/resetprop-rs/.cargo/`):

```toml
[build]
rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]
```

(Per `ld(1)` `--export-dynamic`: "When creating a dynamically linked executable, add all symbols to the dynamic symbol table.")

---

## 10. Temp file + signal-safe cleanup

`tempfile::NamedTempFile` (already in `dev-dependencies`) auto-unlinks on Drop. The hazard is the child outliving the parent on panic: a running tracee holding an mmap of the temp file will keep the inode pinned and may race with test-harness teardown. `ChildGuard` from §3 solves this by SIGKILL + `waitpid` in `Drop`, which runs during unwind. Key properties:

- `libc::kill(pid, SIGKILL)` cannot be caught by the child, so it is guaranteed to terminate even if the child body installed a `SIGSEGV` handler.
- `waitpid(pid, _, 0)` is blocking — we call it after `WNOHANG` to cover both "already-a-zombie" and "still-running" states without leaking the kernel task_struct.
- `Drop` is invoked on the panic unwind path (the tests use the default `unwind` panic strategy despite `panic = "abort"` being set in `[profile.release]` at `Cargo.toml:6-11`; `cargo test` uses the `dev` profile).

---

## 11. Assertions

**Tier A** (§4):

```rust
assert_eq!(before, SENTINEL_POST,
    "pre-seal: file must see child writes through MAP_SHARED");
assert_eq!(after, SENTINEL_PRE,
    "post-seal: child writes must NOT propagate to the file (MAP_PRIVATE COW)");
```

**Tier B** (§5):

```rust
assert_eq!(locked_before, locked_after,
    "locked.prop: hook must prevent child from mutating value bytes");
assert_ne!(free_before, free_after,
    "free.prop: non-sealed name must continue updating");
```

Each assertion names the invariant so a CI failure log tells the reader which seal property broke.

---

## 12. Test runner invocation

Documented at the top of every ptrace-gated test file:

```text
cargo test --test tier_a_child_smoke -- --ignored --test-threads=1
cargo test --test tier_b_child_smoke -- --ignored --test-threads=1
```

Why `--test-threads=1`: each test forks a child and attaches ptrace. Two parallel tests mean two tracers competing for signal delivery, overlapping `SIGCHLD` reaping, and mutual `PTRACE_ATTACH` failures when a test's child ends up in another test's process group. The Rust test runner supports thread control per <https://doc.rust-lang.org/book/ch11-02-running-tests.html#running-tests-in-parallel-or-consecutively>. This is the same discipline `nix`'s ptrace test suite follows (`serial_test` usage in <https://github.com/nix-rust/nix/blob/master/test/sys/test_ptrace.rs>).

Why `--ignored`: tests are marked `#[ignore]` so routine `cargo test` on a laptop without CAP_SYS_PTRACE stays green. CI opts in explicitly.

---

## Source citations

- Layout constants: `crates/resetprop/src/info.rs:6-7` (`PROP_INFO_FIXED = 96`, `PROP_VALUE_MAX = 92`)
- Existing mock pattern: `crates/resetprop/src/mock.rs:1-46`
- Dependency surface: `crates/resetprop/Cargo.toml:13-17`
- MAP_PRIVATE|MAP_FIXED precedent: `crates/resetprop/src/area.rs:247` (referenced by `phases/seal/references/resetprop-rs-integration.md:353`)
- Rust `#[ignore]`: <https://doc.rust-lang.org/book/ch11-02-running-tests.html#ignoring-some-tests-unless-specifically-requested>
- Yama ptrace_scope: <https://www.kernel.org/doc/Documentation/admin-guide/LSM/Yama.rst>
- `nix` serial ptrace tests: <https://github.com/nix-rust/nix/blob/master/test/sys/test_ptrace.rs>
- `ld --export-dynamic`: <https://sourceware.org/binutils/docs/ld/Options.html#index-_002d_002dexport_002ddynamic>
- `process_vm_readv(2)`: <https://man7.org/linux/man-pages/man2/process_vm_readv.2.html>
- `ptrace(2)` self-attach restriction: <https://man7.org/linux/man-pages/man2/ptrace.2.html>
