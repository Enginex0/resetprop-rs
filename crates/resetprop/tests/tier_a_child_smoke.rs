//! Tier A arena-seal child isolation smoke test.
//!
//! Proves that `resetprop::seal::arena::seal_arena(pid, path)` remaps a
//! forked child's `MAP_SHARED` view of a tempfile to `MAP_PRIVATE|MAP_FIXED`.
//! After the seal, subsequent writes in the child's mapping are COW'd into
//! a private page and no longer propagate to the backing inode — which the
//! parent verifies through an independent "third observer" file-read path.
//!
//! Test shape (verbatim from
//! `phases/seal/references/test-harness-patterns.md` §4):
//!   1. Parent creates a `tempfile::NamedTempFile`, sizes it to
//!      `4 * 4096` bytes, pre-writes `SENTINEL_PRE = 0xAA` at offset 128.
//!   2. Child forks, opens the tempfile `O_RDWR`, mmaps it
//!      `MAP_SHARED | PROT_READ|PROT_WRITE`, and loops writing
//!      `SENTINEL_POST = 0xBB` at offset 128 via `std::ptr::write_volatile`.
//!   3. Parent reads the file through an independent `OpenOptions::read(true)`
//!      handle — baseline asserts the byte is `SENTINEL_POST` (MAP_SHARED
//!      propagation working).
//!   4. Parent calls `resetprop::seal::arena::seal_arena(guard.pid(), &path)`.
//!   5. Parent overwrites the on-disk byte back to `SENTINEL_PRE`.
//!   6. After a 200 ms settle, parent re-reads through a fresh file handle
//!      and asserts the byte is still `SENTINEL_PRE` — the child's
//!      now-private mapping writes never reached the inode.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "aarch64")]` because `seal::arena::seal_arena`
//! transitively calls `seal::ptrace::remote_syscall`, whose `UserPtRegs`
//! struct is declared `#[cfg(target_arch = "aarch64")]` at
//! `crates/resetprop/src/seal/ptrace.rs:125`. On this non-aarch64 dev host
//! the file compiles to an empty test binary that reports
//! `0 passed; 0 failed; 0 ignored` for both default and `--ignored`
//! invocations. This matches the gate pattern already used by
//! `crates/resetprop/tests/ptrace_core_smoke.rs`.
//!
//! Preconditions (aarch64 hosts only):
//!   - /proc/sys/kernel/yama/ptrace_scope <= 1, OR CAP_SYS_PTRACE.
//!   - Linux with process_vm_readv/writev (kernel 3.2+).
//!
//! Runner invocation (the test is `#[ignore]`'d by default):
//!   cargo test -p resetprop --test tier_a_child_smoke -- \
//!       --ignored --test-threads=1
//!
//! On aarch64, the default `cargo test -p resetprop --test
//! tier_a_child_smoke` reports `0 passed; 1 ignored`.

#![cfg(target_arch = "aarch64")]

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;
const ARENA_PAGES: usize = 4;
const ARENA_SIZE: usize = PAGE_SIZE * ARENA_PAGES;
const SENTINEL_OFFSET: usize = 128;
const SENTINEL_PRE: u8 = 0xAA;
const SENTINEL_POST: u8 = 0xBB;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (verbatim from phases/seal/references/test-harness-patterns.md §3)
// ─────────────────────────────────────────────────────────────────────────────

/// Fork a child running `child_body`; return the child pid to the parent.
/// Safety: `child_body` must not return (it should `_exit`, `loop`, or `panic!`).
///
/// The bound is `fn() -> !` rather than the `FnOnce() -> !` in
/// test-harness-patterns.md §3 because the `!` (never) type is stable only
/// in function-pointer position, not as a generic closure return type on
/// stable Rust 2021 (tracked by rust-lang/rust#35121). This matches the
/// identical bound used by `tests/ptrace_core_smoke.rs:55`. The child body
/// reaches its per-test PathBuf through the COW-inherited `CHILD_PATH`
/// static initialized by the parent immediately before `fork()`.
unsafe fn fork_child(child_body: fn() -> !) -> libc::pid_t {
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
    fn pid(&self) -> libc::pid_t {
        self.0
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // SAFETY: libc::kill/waitpid FFI. SIGKILL cannot be caught so the
        // tracee is guaranteed to terminate; WNOHANG followed by blocking
        // waitpid drains both already-zombie and still-running states; ESRCH
        // (child already reaped) is benign and ignored.
        unsafe {
            // Best effort; ESRCH if already gone is fine.
            libc::kill(self.0, libc::SIGKILL);
            let mut status: libc::c_int = 0;
            // WNOHANG first in case the child is already reaped; then blocking
            // wait to guarantee zombie drain before the test harness returns.
            libc::waitpid(self.0, &mut status, libc::WNOHANG);
            libc::waitpid(self.0, &mut status, 0);
        }
    }
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

// ─────────────────────────────────────────────────────────────────────────────
// Child path propagation
//
// The `fn() -> !` fork bound precludes closure captures, so the child body
// receives its tempfile path through a process-wide `OnceLock<PathBuf>` set
// by the parent immediately before `fork()`. After `fork()`, the child
// inherits the same virtual-memory image via COW page tables, so the value
// stored in `CHILD_PATH` is visible to the child without any IPC.
// ─────────────────────────────────────────────────────────────────────────────

static CHILD_PATH: OnceLock<PathBuf> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// Child body — mmaps the tempfile MAP_SHARED and write-loops a sentinel
// ─────────────────────────────────────────────────────────────────────────────

fn child_body_mmap_loop() -> ! {
    // SAFETY: All libc calls below are the standard open/mmap/usleep FFI
    // triad. Pointers are either NULL (mmap hint), from the validated
    // CString buffer (open path), or derived from the mmap return address
    // inside its own ARENA_SIZE region (write_volatile). The child is
    // single-threaded, so `write_volatile` has no concurrent aliases.
    unsafe {
        let path = CHILD_PATH
            .get()
            .expect("parent must set CHILD_PATH before fork");
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .expect("tempfile path must be nul-free");
        let fd = libc::open(c_path.as_ptr(), libc::O_RDWR);
        assert!(
            fd >= 0,
            "child: open({}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        );

        let addr = libc::mmap(
            std::ptr::null_mut(),
            ARENA_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        assert_ne!(
            addr,
            libc::MAP_FAILED,
            "child: mmap failed: {}",
            std::io::Error::last_os_error()
        );
        let base = addr as *mut u8;
        let byte_ptr = base.add(SENTINEL_OFFSET);

        // Write SENTINEL_POST forever. Pre-seal, MAP_SHARED propagates each
        // write to the inode. Post-seal (parent remaps this VMA to
        // MAP_PRIVATE|MAP_FIXED), the same writes are COW'd into a private
        // page and the inode no longer observes them.
        loop {
            std::ptr::write_volatile(byte_ptr, SENTINEL_POST);
            libc::usleep(10_000);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Third-observer read path — independent file handle, never aliases the
// child's mapping. Demonstrates the inode's ground-truth state.
// ─────────────────────────────────────────────────────────────────────────────

fn read_file_byte(path: &Path, offset: usize) -> u8 {
    let mut f = OpenOptions::new()
        .read(true)
        .open(path)
        .expect("third observer: open(read)");
    f.seek(SeekFrom::Start(offset as u64))
        .expect("third observer: seek");
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).expect("third observer: read_exact");
    buf[0]
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1"]
fn seal_arena_blocks_child_writes_from_reaching_file() {
    // (1) Backing file: 4 × 4 KiB, with SENTINEL_PRE pre-written at offset 128.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(tmp.path())
            .expect("open tempfile for initial write");
        f.set_len(ARENA_SIZE as u64).expect("set_len ARENA_SIZE");
        f.seek(SeekFrom::Start(SENTINEL_OFFSET as u64))
            .expect("seek SENTINEL_OFFSET");
        f.write_all(&[SENTINEL_PRE]).expect("write SENTINEL_PRE");
        f.sync_all().expect("sync_all pre-fork");
    }
    let path = tmp.path().to_path_buf();

    // (2) Publish the path to the COW-inherited child slot *before* fork,
    //     so `child_body_mmap_loop` can read it without IPC.
    CHILD_PATH
        .set(path.clone())
        .expect("CHILD_PATH must be empty on test entry");

    // (3) Fork the child and immediately wrap its pid in ChildGuard — any
    //     panic or `?` from this point on is guaranteed to SIGKILL+reap.
    //
    // SAFETY: fork() is async-signal-safe. `child_body_mmap_loop` has return
    // type `!` (infinite write loop), so the child cannot fall out of
    // `fork_child` and execute post-fork parent code.
    let child_pid = unsafe { fork_child(child_body_mmap_loop) };
    let guard = ChildGuard(child_pid);

    // (4) Let the child install its mapping and complete at least one write
    //     (the child loops at ~10 ms intervals).
    sleep_ms(100);

    // (5) Baseline: third-observer read must see SENTINEL_POST — proves that
    //     the child's MAP_SHARED view is propagating writes to the inode
    //     *before* we seal.
    let before = read_file_byte(&path, SENTINEL_OFFSET);
    assert_eq!(
        before, SENTINEL_POST,
        "pre-seal: file must see child writes through MAP_SHARED"
    );

    // (6) Install the seal: remap the child's arena VMA to
    //     MAP_PRIVATE|MAP_FIXED via resetprop's Tier A entry point.
    resetprop::seal::arena::seal_arena(guard.pid(), &path)
        .expect("seal_arena should succeed under ptrace_scope<=1");

    // (7) Parent resets the on-disk byte to a distinct marker. If the seal
    //     worked, the child's ongoing SENTINEL_POST writes cannot reach the
    //     inode, so this marker survives the rest of the test.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open tempfile for post-seal reset");
        f.seek(SeekFrom::Start(SENTINEL_OFFSET as u64))
            .expect("seek SENTINEL_OFFSET post-seal");
        f.write_all(&[SENTINEL_PRE]).expect("write SENTINEL_PRE post-seal");
        f.sync_all().expect("sync_all post-seal");
    }

    // (8) Give the child plenty of time to fire several write_volatile
    //     iterations into its now-private mapping.
    sleep_ms(200);

    // (9) Third-observer re-read: must still be SENTINEL_PRE. If the seal
    //     failed, the child's MAP_SHARED writes would have clobbered the
    //     byte back to SENTINEL_POST by now.
    let after = read_file_byte(&path, SENTINEL_OFFSET);
    assert_eq!(
        after, SENTINEL_PRE,
        "post-seal: child writes must NOT propagate to the file (MAP_PRIVATE COW)"
    );

    // guard drops -> SIGKILL + waitpid; tmp drops -> file unlinked.
}
