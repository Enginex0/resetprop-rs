//! Tier B per-prop hook integration smoke test.
//!
//! Runner: `cargo test --test tier_b_child_smoke -- --ignored --test-threads=1`
//! Requires: aarch64-linux target with
//!   `/proc/sys/kernel/yama/ptrace_scope <= 1` OR CAP_SYS_PTRACE.
//!   On-device: adbd root (`u:r:su:s0`).
//!
//! Build requirement: `.cargo/config.toml` contains
//! `rustflags = ["-C", "link-arg=-Wl,--export-dynamic"]` so the test
//! binary's own `__system_property_update` is visible in its `.dynsym`
//! table — the hook's GNU_HASH lookup needs it. Per
//! `phases/seal/references/test-harness-patterns.md §5`.
//!
//! The test forks a sacrificial child that alternates updates between
//! `locked.prop` and `free.prop`. The parent installs the hook, seals
//! `locked.prop`, then reads the remote value bytes via
//! `process_vm_readv` and asserts the locked name's bytes are frozen
//! while the free name keeps advancing.
#![cfg(target_arch = "aarch64")]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Matches bionic `sizeof(prop_info) == 96` at prop_info.h:89.
const PI_FIXED: usize = 96;

#[repr(C)]
struct FakePropInfoHeader {
    serial: AtomicU32,
    value: [u8; 92],
}
const _: () = assert!(core::mem::size_of::<FakePropInfoHeader>() == PI_FIXED);

/// Heap-pinned prop_info: the bytes live in a `Box<[u8]>` that is
/// never reallocated, so its address is stable across ptrace reads
/// from the parent and across `fork()` COW into the child.
struct PinnedPi {
    buf: Box<[u8]>,
}

impl PinnedPi {
    fn new(name: &str) -> Self {
        let mut v = vec![0u8; PI_FIXED + name.len() + 1];
        v[PI_FIXED..PI_FIXED + name.len()].copy_from_slice(name.as_bytes());
        Self {
            buf: v.into_boxed_slice(),
        }
    }

    fn as_ptr(&self) -> *const u8 {
        self.buf.as_ptr()
    }
}

/// Hook target the tracer rewrites. `#[no_mangle]` + `extern "C"` plus
/// the `--export-dynamic` rustflag place the symbol in the test
/// binary's `.dynsym`, which is where the hook's GNU_HASH lookup
/// resolves it.
#[no_mangle]
pub extern "C" fn __system_property_update(
    pi: *mut u8,
    value: *const u8,
    len: u32,
) -> libc::c_int {
    // SAFETY: the parent allocates each `PinnedPi` as a 96+N-byte
    // `Box<[u8]>` which survives the child's lifetime via fork COW,
    // so `pi` is non-null, aligned, and at least 96 bytes long; the
    // child's caller passes `value` as a pointer into its own
    // `format!` buffer of exactly `len` live bytes.
    unsafe {
        if pi.is_null() || value.is_null() {
            return -1;
        }
        let serial_atomic = &*(pi as *const AtomicU32);
        let s = serial_atomic.fetch_add(1, Ordering::AcqRel);
        let dst = pi.add(4);
        let n = (len as usize).min(91);
        std::ptr::copy_nonoverlapping(value, dst, n);
        *dst.add(n) = 0;
        serial_atomic.store(s.wrapping_add(2), Ordering::Release);
        0
    }
}

/// Fork a child running `child_body`; return the child pid to the parent.
/// The closure must never return (it should `_exit`, `loop`, or `panic!`).
///
/// # Safety
///
/// Post-fork, the child inherits the parent's address space but not its
/// threads; callers must keep the child body async-signal-safe and must
/// not rely on any Rust runtime state that was mid-mutation at fork time.
unsafe fn fork_child<F: FnOnce() -> !>(child_body: F) -> libc::pid_t {
    // SAFETY: libc::fork is a direct syscall wrapper; the caller
    // upholds the async-signal-safety contract for `child_body`.
    let pid = unsafe { libc::fork() };
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
        // SAFETY: SIGKILL cannot be caught by the child, so the kill+wait
        // pair is guaranteed to drain the zombie. ESRCH from an
        // already-reaped child is acceptable here.
        unsafe {
            libc::kill(self.0, libc::SIGKILL);
            let mut status: libc::c_int = 0;
            libc::waitpid(self.0, &mut status, libc::WNOHANG);
            libc::waitpid(self.0, &mut status, 0);
        }
    }
}

fn sleep_ms(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn child_body_update_loop(locked_pi: *const u8, free_pi: *const u8) -> ! {
    let mut tick: u32 = 0;
    loop {
        let pi = if tick & 1 == 0 { locked_pi } else { free_pi };
        let val = format!("v{tick}");
        // SAFETY: both `locked_pi` and `free_pi` are stable pointers to
        // parent-allocated `Box<[u8]>` buffers inherited via fork COW;
        // `val.as_ptr()` / `val.len()` describe a live slice for the
        // call duration.
        unsafe {
            let _ = __system_property_update(
                pi as *mut u8,
                val.as_ptr(),
                val.len() as u32,
            );
        }
        tick = tick.wrapping_add(1);
        // SAFETY: libc::usleep is a thin syscall wrapper; 5 ms is well
        // inside the u32 microsecond domain.
        unsafe {
            libc::usleep(5_000);
        }
    }
}

fn read_remote_value(pid: libc::pid_t, pi: *const u8) -> [u8; 92] {
    let mut out = [0u8; 92];
    let local = libc::iovec {
        iov_base: out.as_mut_ptr() as *mut _,
        iov_len: 92,
    };
    // SAFETY: `pi` points to a 96-byte-prefix buffer in the child; the
    // offset `+4` addresses the 92-byte value region per bionic layout.
    let remote = libc::iovec {
        iov_base: unsafe { pi.add(4) } as *mut _,
        iov_len: 92,
    };
    // SAFETY: `out` lives on the caller's stack for the full syscall;
    // `remote` addresses memory inherited by `pid` via fork COW, so the
    // kernel can read through the destination pid's mm unconditionally.
    let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    assert_eq!(
        n, 92,
        "process_vm_readv: {}",
        std::io::Error::last_os_error()
    );
    out
}

#[test]
#[ignore = "requires ptrace_scope<=1; run with --ignored --test-threads=1 on aarch64 device"]
fn hook_blocks_locked_prop_writes_and_permits_free_prop_writes() {
    let locked = PinnedPi::new("locked.prop");
    let free = PinnedPi::new("free.prop");
    let locked_ptr = locked.as_ptr();
    let free_ptr = free.as_ptr();

    // SAFETY: the two `PinnedPi` pointers remain valid for the parent's
    // lifetime, and fork COW gives the child identical virtual addresses.
    let child_pid = unsafe { fork_child(move || child_body_update_loop(locked_ptr, free_ptr)) };
    let guard = ChildGuard(child_pid);

    sleep_ms(100);

    let locked_before = read_remote_value(guard.pid(), locked_ptr);
    let free_before = read_remote_value(guard.pid(), free_ptr);

    let mut handle = resetprop::seal::hook::install_init_hook(guard.pid())
        .expect("install_init_hook");
    resetprop::seal::hook::install_trampoline(&mut handle)
        .expect("install_trampoline");
    resetprop::seal::hook::seal_prop(&mut handle, "locked.prop")
        .expect("seal_prop");

    sleep_ms(200);

    let locked_after = read_remote_value(guard.pid(), locked_ptr);
    let free_after = read_remote_value(guard.pid(), free_ptr);

    assert_eq!(
        locked_before, locked_after,
        "locked.prop: hook must prevent child from mutating value bytes"
    );
    assert_ne!(
        free_before, free_after,
        "free.prop: non-sealed name must continue updating"
    );
}
