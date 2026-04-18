//! Integration smoke test for the T4 remote_syscall injector.
//!
//! Forks a child that installs an anonymous RWX scratch page and
//! enters `libc::pause()`, then the parent seizes + interrupts the
//! child and round-trips `remote_syscall(NR_GETPID, [0; 6])`. Asserts
//! the returned `x0` equals the child's PID.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "aarch64")]` because `remote_syscall` stages the
//! ARM64 byte sequence `svc #0 ; brk #0`, expects the AArch64 syscall
//! calling convention (`x8` = syscall number, `x0..x5` = args), and reads
//! results through a 272-byte `UserPtRegs` whose layout is aarch64-only
//! (see `crates/resetprop/src/seal/ptrace.rs` T3 self-audit Gate 3 note
//! (8) — the size assert is already `#[cfg(target_arch = "aarch64")]`).
//! On non-aarch64 hosts this file compiles to an empty test binary,
//! reporting `0 passed; 0 failed; 0 ignored` for both default and
//! `--ignored` invocations.
//!
//! Preconditions (aarch64 hosts only):
//!   - /proc/sys/kernel/yama/ptrace_scope <= 1, OR CAP_SYS_PTRACE.
//!   - Linux with process_vm_readv/writev (kernel 3.2+).
//!
//! Runner invocation (the test is #[ignore]'d by default):
//!   cargo test -p resetprop --test ptrace_core_smoke -- \
//!       --ignored --test-threads=1
//!
//! On aarch64, the default `cargo test -p resetprop --test
//! ptrace_core_smoke` reports `0 passed; 1 ignored`.

#![cfg(target_arch = "aarch64")]

use resetprop::seal::ptrace::NR_GETPID;
use resetprop::seal::{
    ptrace_detach, ptrace_interrupt, ptrace_seize, remote_syscall, wait_stop,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers (verbatim from phases/seal/references/test-harness-patterns.md §3)
// ─────────────────────────────────────────────────────────────────────────────

/// Fork a child running `child_body`; return the child pid to the parent.
/// Safety: `child_body` must not return (it should `_exit`, `loop`, or `panic!`).
///
/// The bound is `fn() -> !` rather than the `FnOnce() -> !` in
/// test-harness-patterns.md §3 because the `!` (never) type is stable only
/// in function-pointer position, not as a generic closure return type on
/// stable Rust 2021 (tracked by rust-lang/rust#35121). This smoke test
/// passes a plain `fn` pointer (`child_body`) with no captures, so the
/// narrower bound is strictly sufficient.
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

// ─────────────────────────────────────────────────────────────────────────────
// Child body — inherits the pre-fork RWX scratch page via COW and blocks
// ─────────────────────────────────────────────────────────────────────────────

fn child_body() -> ! {
    loop {
        // SAFETY: libc::pause is async-signal-safe and takes no pointers;
        // it blocks this (single-threaded) child until a signal arrives.
        // The parent's PTRACE_INTERRUPT wakes it into a ptrace group-stop.
        unsafe {
            libc::pause();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test — round-trip getpid() through remote_syscall
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires ptrace_scope<=1 or CAP_SYS_PTRACE; run with: cargo test -p resetprop --test ptrace_core_smoke -- --ignored --test-threads=1"]
fn remote_getpid_returns_child_pid() {
    // (1) Pre-fork: parent mmaps an anonymous RWX page. The page is inherited
    // by the child via fork COW page tables, so `scratch_pc` names the same
    // virtual address in both processes. 4 KiB is page-aligned, which
    // satisfies remote_syscall's 4-byte-alignment contract trivially.
    //
    // SAFETY: libc::mmap FFI. NULL hint is permitted; PROT_READ|WRITE|EXEC
    // with MAP_PRIVATE|MAP_ANONYMOUS, fd=-1, offset=0 is a well-formed
    // anonymous-mapping request. We only materialize the returned address as
    // a u64 — never as a `&mut T` — so Rust aliasing rules are untouched.
    let scratch_pc: u64 = unsafe {
        let addr = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(
            addr,
            libc::MAP_FAILED,
            "mmap: {}",
            std::io::Error::last_os_error()
        );
        addr as u64
    };

    // (2) Fork. Child enters pause(); parent continues.
    //
    // SAFETY: fork() is async-signal-safe. `child_body` has return type `!`
    // (infinite pause loop), so the child cannot fall out of `fork_child`
    // and execute post-fork parent code.
    let child_pid = unsafe { fork_child(child_body) };
    let guard = ChildGuard(child_pid);

    // (3) Brief settle so the child reaches pause() before we SEIZE.
    // Convention per test-harness-patterns.md §3 for single-shot smoke tests
    // under yama=0 localhost.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // (4) SEIZE + INTERRUPT + wait_stop consumes the initial group-stop
    // (event byte = 128). wait_stop only enforces WIFSTOPPED && WSTOPSIG ==
    // SIGTRAP; remote_syscall adds the event-byte=0 check on its own
    // waitpid to reject anything other than the brk trap.
    ptrace_seize(guard.pid()).expect("ptrace_seize");
    ptrace_interrupt(guard.pid()).expect("ptrace_interrupt");
    wait_stop(guard.pid()).expect("wait_stop (initial SEIZE stop)");

    // (5) Round-trip getpid() inside the child via the remote-syscall
    // injector. Expected return: the child's own PID as i64.
    //
    // SAFETY: child is ptrace-stopped (steps 4 above). `scratch_pc` is
    // page-aligned via mmap (well within the 4-byte-alignment contract) and
    // names an RWX page with 4096 bytes of room — far more than the 8 bytes
    // the injector stages at `scratch_pc`. The child is single-threaded and
    // blocked in pause(), so no other thread races on those 8 bytes.
    let ret = unsafe {
        remote_syscall(guard.pid(), scratch_pc, NR_GETPID, [0; 6])
    }
    .expect("remote_syscall");

    assert_eq!(
        ret, child_pid as i64,
        "remote getpid must return the child's PID (ret={ret}, child={child_pid})"
    );

    // (6) Detach. ChildGuard::drop handles SIGKILL + waitpid on scope exit,
    // so even if a subsequent assertion or panic fires we never leak a
    // tracee or zombie.
    ptrace_detach(guard.pid()).expect("ptrace_detach");
}
