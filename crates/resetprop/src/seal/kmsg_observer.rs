//! In-init kmsg observability (Port 2).
//!
//! Discovers the `/dev/kmsg` file descriptors init holds open, then snoops
//! init's `write(kmsg_fd, …)` syscalls for a bounded window so the kernel-log
//! lines init emits become visible without touching its memory. Ported from
//! injectrc `init_injector/injector.cpp:213-232` (kmsg fd discovery) and
//! `:254-310` (the syscall-trace loop).

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use libc::c_int;

use super::ptrace::{
    detach_thread_group, getregset, is_thread_gone, nth_syscall_arg, ptrace_interrupt,
    ptrace_syscall, read_remote, seize_thread_group, syscall_nr, syscall_stop_op,
    PTRACE_EVENT_STOP, PTRACE_SYSCALL_INFO_ENTRY,
};
use super::Pid;
use crate::error::{Error, Result};

/// The symlink target every `/dev/kmsg` fd resolves to under `/proc/<pid>/fd`.
const KMSG_DEVICE: &str = "/dev/kmsg";

/// Discover the `/dev/kmsg` file descriptors open in `pid` by resolving every
/// symlink under `/proc/<pid>/fd`.
pub(crate) fn discover_kmsg_fds(pid: Pid) -> Vec<u64> {
    let fd_dir = format!("/proc/{pid}/fd");
    discover_kmsg_fds_in(Path::new(&fd_dir))
}

/// Testable core of [`discover_kmsg_fds`]: collect the fd numbers in `fd_dir`
/// whose symlink resolves to `/dev/kmsg`, sorted ascending.
///
/// An unreadable directory yields an empty list — init with no kmsg fd is an
/// unusual but valid state, not an error to propagate. Non-symlink entries and
/// links to other targets are skipped, mirroring injectrc's `DT_LNK` +
/// target-equality filter.
pub(crate) fn discover_kmsg_fds_in(fd_dir: &Path) -> Vec<u64> {
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return Vec::new();
    };
    let mut fds: Vec<u64> = entries
        .flatten()
        .filter(|entry| {
            fs::read_link(entry.path()).is_ok_and(|target| target == Path::new(KMSG_DEVICE))
        })
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u64>().ok())
        })
        .collect();
    fds.sort_unstable();
    fds
}

/// AArch64 `__NR_write` (asm-generic syscall table). The snoop is gated to
/// aarch64 at the `lib.rs` boundary (`require_aarch64`), matching the rest of
/// the seal subsystem's aarch64 syscall-number convention.
const NR_WRITE: u64 = 64;

/// Upper bound on a single kmsg write the snoop mirrors. Kernel log lines sit
/// well under this; the cap stops a pathological length argument from forcing
/// an unbounded allocation.
const MAX_KMSG_WRITE: usize = 8192;

/// Decide whether a syscall-entry register read is a `write` to one of
/// `kmsg_fds`, returning the `(buf, capped_len)` to mirror. Pure over the
/// extracted register values so the fd-match and length-cap logic is unit
/// testable without a live tracee.
fn write_target(nr: u64, fd: u64, buf: u64, len: u64, kmsg_fds: &[u64]) -> Option<(u64, usize)> {
    if nr != NR_WRITE || !kmsg_fds.contains(&fd) {
        return None;
    }
    Some((buf, (len as usize).min(MAX_KMSG_WRITE)))
}

/// On a syscall-entry stop, mirror a `write(kmsg_fd, buf, len)` from the
/// tracee: read its buffer through the size-asserted register facade and
/// return the line with a single trailing newline stripped. `None` when the
/// stopped syscall is not a write to one of `kmsg_fds`.
fn capture_kmsg_write(pid: Pid, kmsg_fds: &[u64]) -> Result<Option<String>> {
    let regs = getregset(pid)?;
    let Some((buf, len)) = write_target(
        syscall_nr(&regs),
        nth_syscall_arg(&regs, 0),
        nth_syscall_arg(&regs, 1),
        nth_syscall_arg(&regs, 2),
        kmsg_fds,
    ) else {
        return Ok(None);
    };
    if len == 0 {
        return Ok(Some(String::new()));
    }
    let mut bytes = vec![0u8; len];
    // SAFETY: the tracee is ptrace-stopped at a syscall-entry stop; `buf..buf +
    // len` is the userspace buffer init passed to write(2), readable in its
    // address space.
    unsafe { read_remote(pid, buf, &mut bytes)? };
    let text = String::from_utf8_lossy(&bytes);
    Ok(Some(text.strip_suffix('\n').unwrap_or(&text).to_string()))
}

/// RAII whole-thread-group ptrace attach for the snoop: freezes every thread in
/// `pid`'s group (SEIZE + INTERRUPT + wait per tid, re-scanned to a fixpoint),
/// then the snoop single-steps each across syscalls. Detaches the whole group on
/// drop. Tracing every thread, not just the leader, is required because Android
/// writes persistent properties on a non-leader init thread, so a leader-only
/// trace misses their kmsg lines. Unlike [`super::arena::RemoteAttach`] the group
/// is resumed (`PTRACE_SYSCALL`) rather than held frozen for an atomic poke.
struct GroupTracer {
    tids: Vec<Pid>,
    detached: bool,
}

impl GroupTracer {
    fn seize(pid: Pid) -> Result<Self> {
        let tids = seize_thread_group(pid)?;
        Ok(Self {
            tids,
            detached: false,
        })
    }

    fn detach(mut self) -> Result<()> {
        self.detached = true;
        detach_thread_group(&self.tids)
    }
}

impl Drop for GroupTracer {
    fn drop(&mut self) {
        if !self.detached {
            // Best-effort resume on the error path; the kernel also auto-
            // detaches every tracee when this short-lived CLI exits.
            if let Err(e) = detach_thread_group(&self.tids) {
                eprintln!("resetprop: observe-init group detach during unwind failed: {e}");
            }
        }
    }
}

/// Stop every thread in `running` (each was resumed with `PTRACE_SYSCALL`, so it
/// owes exactly one stop) so the group detach acts on a fully-stopped group.
/// Interrupts each, then reaps one status per interrupted thread; a thread that
/// exits in the window is dropped from `tids`. Threads already held at a stop
/// are not in `running` and need no action.
fn settle_running(tids: &mut Vec<Pid>, running: &[Pid]) -> Result<()> {
    let mut pending: Vec<Pid> = Vec::with_capacity(running.len());
    for &tid in running {
        match ptrace_interrupt(tid) {
            Ok(()) => pending.push(tid),
            Err(e) if is_thread_gone(&e) => tids.retain(|&t| t != tid),
            Err(e) => return Err(e),
        }
    }
    while !pending.is_empty() {
        let mut status: c_int = 0;
        // SAFETY: `status` is stack-local; `-1` + `__WALL` reaps a stop from any
        // interrupted init thread.
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if rc == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(Error::PtraceOp(err));
        }
        pending.retain(|&t| t != rc);
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            tids.retain(|&t| t != rc);
        }
    }
    Ok(())
}

extern "C" fn handle_alarm(_signum: c_int) {}

/// RAII SIGALRM arming so a blocking `waitpid` cannot outlast the observe
/// window when init idles in a long syscall. Installs a no-op handler WITHOUT
/// `SA_RESTART` (so the wait returns `EINTR` rather than auto-restarting),
/// restores the previous disposition and cancels the timer on drop.
struct AlarmGuard {
    previous: libc::sigaction,
}

impl AlarmGuard {
    fn arm(seconds: u32) -> Result<Self> {
        // SAFETY: `sigaction` is a C struct that is valid all-zero (empty mask,
        // no flags); `mem::zeroed` is the standard way to stage it.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = handle_alarm as *const () as libc::sighandler_t;
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: `action`/`previous` are valid sigaction storage for the
        // duration of the call; sa_flags is 0 (no SA_RESTART) so the handler
        // interrupts a blocked waitpid.
        let rc = unsafe { libc::sigaction(libc::SIGALRM, &action, &mut previous) };
        if rc == -1 {
            return Err(Error::Io(io::Error::last_os_error()));
        }
        // SAFETY: arms a one-shot process timer; no memory effect.
        unsafe { libc::alarm(seconds) };
        Ok(Self { previous })
    }
}

impl Drop for AlarmGuard {
    fn drop(&mut self) {
        // SAFETY: cancel the pending timer and restore the saved disposition.
        unsafe {
            libc::alarm(0);
            libc::sigaction(libc::SIGALRM, &self.previous, std::ptr::null_mut());
        }
    }
}

/// Trace init (`pid`) for `duration`, mirroring every `write(2)` it makes to a
/// `/dev/kmsg` fd in `kmsg_fds` to `sink`. Returns the number of kmsg lines
/// captured.
///
/// Single-steps each thread across syscall boundaries with `PTRACE_SYSCALL`,
/// dispatching `waitpid(-1, __WALL)` stops by the thread id they report, and
/// uses [`syscall_stop_op`] to act only on entry stops. The entry/exit toggle
/// the injectrc reference uses is unreliable here: the attach interrupts each
/// thread wherever it idles (often inside a blocking syscall), so the first stop
/// is an exit and a toggle would stay inverted for the whole window. A SIGALRM
/// bounds the wait when every thread idles. Ported from injectrc
/// `init_injector/injector.cpp:254-310`.
pub(crate) fn snoop_kmsg_writes_for_duration(
    pid: Pid,
    kmsg_fds: &[u64],
    duration: Duration,
    sink: &mut dyn Write,
) -> Result<usize> {
    if kmsg_fds.is_empty() || duration.is_zero() {
        return Ok(0);
    }

    let mut tracer = GroupTracer::seize(pid)?;
    // Round the alarm up to whole seconds so it never fires before the
    // Instant-based deadline, which would risk a wedged wait on an idle init.
    let alarm_secs = (duration.as_secs() + u64::from(duration.subsec_nanos() > 0))
        .clamp(1, u64::from(u32::MAX)) as u32;
    let _alarm = AlarmGuard::arm(alarm_secs)?;
    let deadline = Instant::now() + duration;
    let mut captured = 0usize;

    // Begin syscall-stepping every frozen thread; `running` holds the tids we
    // have resumed (each owes exactly one stop), which the deadline path settles
    // before detaching. A thread that exits between the group-stop and this
    // resume is dropped, not an error.
    let mut running: Vec<Pid> = Vec::with_capacity(tracer.tids.len());
    for &tid in &tracer.tids {
        match ptrace_syscall(tid, 0) {
            Ok(()) => running.push(tid),
            Err(e) if is_thread_gone(&e) => {}
            Err(e) => return Err(e),
        }
    }
    tracer.tids.retain(|tid| running.contains(tid));

    while !running.is_empty() {
        let mut status: c_int = 0;
        // SAFETY: `status` is stack-local; waitpid writes through it only while
        // blocked. `-1` + `__WALL` reaps a stop from any seized init thread.
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if rc == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                if Instant::now() >= deadline {
                    break;
                }
                continue;
            }
            return Err(Error::PtraceOp(err));
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            running.retain(|&t| t != rc);
            tracer.tids.retain(|&t| t != rc);
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            // Not a stop we can resume from (no WCONTINUED requested, so this is
            // unreachable in practice). Re-wait rather than poke a thread whose
            // stop we did not confirm; its `running` membership is unchanged.
            continue;
        }
        // The thread is held at this stop until we resume it below.
        running.retain(|&t| t != rc);
        let sig = libc::WSTOPSIG(status);
        let is_group_stop = ((status >> 16) & 0xff) as u32 == PTRACE_EVENT_STOP;
        if sig == (libc::SIGTRAP | 0x80) {
            if syscall_stop_op(rc)? == PTRACE_SYSCALL_INFO_ENTRY {
                if let Some(line) = capture_kmsg_write(rc, kmsg_fds)? {
                    writeln!(sink, "{line}").map_err(Error::Io)?;
                    captured += 1;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            ptrace_syscall(rc, 0)?;
            running.push(rc);
        } else {
            // Signal-delivery stop: forward the signal so init's own handling is
            // preserved. A group-stop event carries a stop signal that must NOT
            // be re-injected, only resumed past.
            let inject = if is_group_stop { 0 } else { sig };
            ptrace_syscall(rc, inject)?;
            running.push(rc);
        }
    }

    settle_running(&mut tracer.tids, &running)?;
    sink.flush().map_err(Error::Io)?;
    tracer.detach()?;
    Ok(captured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// Only `/dev/kmsg` links are collected; other devices, regular-file links,
    /// and the fd numbers are returned sorted. The link targets need not exist:
    /// `read_link` reads the link body, not the destination.
    #[test]
    fn discover_picks_only_kmsg_links_sorted() {
        let fd_dir = tempfile::tempdir().expect("tempdir");
        symlink("/dev/kmsg", fd_dir.path().join("7")).unwrap();
        symlink("/dev/null", fd_dir.path().join("4")).unwrap();
        symlink("/dev/kmsg", fd_dir.path().join("3")).unwrap();
        symlink("/data/local/tmp/init.log", fd_dir.path().join("9")).unwrap();

        assert_eq!(discover_kmsg_fds_in(fd_dir.path()), vec![3, 7]);
    }

    /// init holding no kmsg fd yields an empty list rather than an error.
    #[test]
    fn discover_no_kmsg_links_is_empty() {
        let fd_dir = tempfile::tempdir().expect("tempdir");
        symlink("/dev/null", fd_dir.path().join("1")).unwrap();

        assert!(discover_kmsg_fds_in(fd_dir.path()).is_empty());
    }

    /// A missing fd directory is the empty case, not a panic.
    #[test]
    fn discover_missing_dir_is_empty() {
        assert!(discover_kmsg_fds_in(Path::new("/proc/nonexistent-pid/fd")).is_empty());
    }

    /// A `write` to a tracked kmsg fd yields its `(buf, len)`.
    #[test]
    fn write_target_matches_kmsg_write() {
        assert_eq!(
            write_target(NR_WRITE, 7, 0xdead_0000, 64, &[3, 7]),
            Some((0xdead_0000, 64)),
        );
    }

    /// A non-`write` syscall, or a write to an untracked fd, is ignored.
    #[test]
    fn write_target_rejects_non_kmsg() {
        assert_eq!(write_target(NR_WRITE, 9, 0x1000, 16, &[3, 7]), None);
        assert_eq!(write_target(NR_WRITE + 1, 7, 0x1000, 16, &[3, 7]), None);
    }

    /// An oversized length argument is capped so the read cannot allocate
    /// unboundedly.
    #[test]
    fn write_target_caps_length() {
        assert_eq!(
            write_target(NR_WRITE, 3, 0x2000, u64::MAX, &[3]),
            Some((0x2000, MAX_KMSG_WRITE)),
        );
    }
}
