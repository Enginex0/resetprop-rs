# Linux ARM64 ptrace + Syscall ABI — Rust Reference

Target: remote-syscall injector attaching to PID 1 on Android (AArch64),
staging `svc #0`, running `openat`/`mmap`/`close`, detaching. Pure Rust,
`libc` only.

Sources: AOSP bionic `uapi/asm-arm64/asm/{unistd,ptrace}.h`,
`uapi/linux/{ptrace,elf}.h`, `asm-generic/unistd.h`.

---

## 1. ARM64 Syscall Numbers

AArch64 uses the `asm-generic` table unchanged. Lines cite
`asm-generic/unistd.h`.

```rust
// source: asm-generic/unistd.h
pub const __NR_openat:           u64 =  56; // line 158: #define __NR_openat 56
pub const __NR_close:            u64 =  57; // line 160: #define __NR_close 57
pub const __NR_exit:             u64 =  93; // line 258: #define __NR_exit 93
pub const __NR_rt_sigreturn:     u64 = 139; // line 386: #define __NR_rt_sigreturn 139
pub const __NR_getpid:           u64 = 172; // line 461: #define __NR_getpid 172
pub const __NR_munmap:           u64 = 215; // line 556: #define __NR_munmap 215
pub const __NR_mmap:             u64 = 222; // line 570/886: __NR3264_mmap, aliased to __NR_mmap on 64-bit
pub const __NR_mprotect:         u64 = 226; // line 581: #define __NR_mprotect 226
pub const __NR_process_vm_readv: u64 = 270; // line 657
pub const __NR_process_vm_writev:u64 = 271; // line 659
pub const __NR_membarrier:       u64 = 283; // line 683
```

`__NR_mmap = 222`: generic unistd defines `__NR3264_mmap 222`; lines
874-886 alias `__NR_mmap → __NR3264_mmap` under `__BITS_PER_LONG == 64`
(the AArch64 LP64 case).

## 2. ARM64 Syscall Calling Convention

Per AArch64 PCS and `arch/arm64/kernel/entry.S`:

- Args 1..6: `x0, x1, x2, x3, x4, x5`.
- Syscall number: `x8`.
- Entry: `svc #0` (encoding `0xD4000001` little-endian).
- Return: `x0`. Error band is `[-4095, -1]` (= `-errno`).
- Kernel preserves `x19..x30`, `sp`, `pc` (resumes after `svc`); x0..x18
  volatile per AAPCS64.
- `x7` is not a syscall arg on AArch64 (generic ABI caps at 6).

Stager instruction encodings:

```rust
pub const ARM64_SVC_0: u32 = 0xD4000001; // svc #0
pub const ARM64_BRK_0: u32 = 0xD4200000; // brk #0 — delivers SIGTRAP
```

## 3. `struct user_pt_regs` (AArch64)

Source: `uapi/asm-arm64/asm/ptrace.h` lines 49-54:
```c
struct user_pt_regs {
  __u64 regs[31];   // x0..x30
  __u64 sp;
  __u64 pc;
  __u64 pstate;
};
```

Rust:
```rust
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub regs:   [u64; 31], // x0..x30 (x30 == lr)
    pub sp:     u64,
    pub pc:     u64,
    pub pstate: u64,
}
// size = (31 + 3) * 8 = 272 bytes, alignment = 8
const _: () = assert!(core::mem::size_of::<UserPtRegs>() == 272);
```

`regs[8]` is `x8`, `regs[0..=5]` hold args 1..6, `regs[30]` is `lr`.

## 4. PTRACE Request Numbers

From `uapi/linux/ptrace.h` (lines cited) and `uapi/linux/elf.h`:

```rust
pub const PTRACE_CONT:        libc::c_int = 7;      // line 17
pub const PTRACE_DETACH:      libc::c_int = 17;     // line 21
pub const PTRACE_GETREGSET:   libc::c_int = 0x4204; // line 27
pub const PTRACE_SETREGSET:   libc::c_int = 0x4205; // line 28
pub const PTRACE_SEIZE:       libc::c_int = 0x4206; // line 29
pub const PTRACE_INTERRUPT:   libc::c_int = 0x4207; // line 30
pub const PTRACE_LISTEN:      libc::c_int = 0x4208; // line 31
pub const PTRACE_O_TRACESYSGOOD: libc::c_int = 1;   // line 100
pub const PTRACE_EVENT_STOP:  libc::c_int = 128;    // line 99 (upper bits of wait status)

// NT_PRSTATUS: iovec addr for general-purpose regs via GETREGSET/SETREGSET
pub const NT_PRSTATUS:        libc::c_int = 1;      // uapi/linux/elf.h line 301
```

Also useful:
```rust
pub const PTRACE_GETSIGINFO:  libc::c_int = 0x4202; // line 25
pub const PTRACE_SETOPTIONS:  libc::c_int = 0x4200; // line 23
```

## 5. GETREGSET / SETREGSET iovec Pattern

`ptrace(PTRACE_GETREGSET, pid, addr, data)` — `addr` is the note type
(`NT_PRSTATUS`), `data` is a pointer to `struct iovec`. Kernel writes
bytes-actually-transferred back into `iov.iov_len`. Provide a
272-byte buffer for `UserPtRegs`.

```rust
use libc::{iovec, c_long, c_void, pid_t};

unsafe fn get_regs(pid: pid_t) -> Result<UserPtRegs, i32> {
    let mut regs = UserPtRegs::default();
    let mut iov = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len:  core::mem::size_of::<UserPtRegs>(),
    };
    let rc = libc::ptrace(
        PTRACE_GETREGSET as _, pid,
        NT_PRSTATUS as *mut c_void,
        &mut iov as *mut _ as *mut c_void,
    );
    if rc == -1 { return Err(*libc::__errno_location()); }
    // On return iov.iov_len holds the true length; expect 272.
    Ok(regs)
}

unsafe fn set_regs(pid: pid_t, regs: &UserPtRegs) -> Result<(), i32> {
    let mut iov = iovec {
        iov_base: regs as *const _ as *mut c_void,
        iov_len:  core::mem::size_of::<UserPtRegs>(),
    };
    let rc = libc::ptrace(
        PTRACE_SETREGSET as _, pid,
        NT_PRSTATUS as *mut c_void,
        &mut iov as *mut _ as *mut c_void,
    );
    if rc == -1 { return Err(*libc::__errno_location()); }
    Ok(())
}
```

## 6. Attach / Detach Lifecycle

Attach (non-destructive, via `PTRACE_SEIZE`):

1. `ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD)` — attaches
   without stopping the tracee; sets options atomically.
2. `ptrace(PTRACE_INTERRUPT, pid, 0, 0)` — request a synchronous stop.
3. `waitpid(pid, &mut status, __WALL)` with `__WALL = 0x40000000` (needed
   on threads outside the default waitset).
4. Expect `WIFSTOPPED(status)` true, `(status >> 16) == PTRACE_EVENT_STOP`
   (128), `WSTOPSIG(status) == SIGTRAP`.

Detach:

1. `PTRACE_SETREGSET` with saved `UserPtRegs` (restores `pc`).
2. `process_vm_writev` to restore the bytes at `scratch_pc`.
3. `ptrace(PTRACE_DETACH, pid, 0, 0)`.

## 7. Staging `svc #0` Execution

Algorithm for one remote syscall round-trip:

1. Pick `scratch_pc`: 4-byte-aligned, inside an executable mapping of
   the tracee (selection per section 8).
2. `process_vm_readv` 8 bytes from `scratch_pc` and save.
3. Write an 8-byte payload (`svc #0; brk #0`) via `process_vm_writev`:
   `[0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x20, 0xd4]`. The `brk` traps
   deterministically post-syscall, avoiding signal races.
4. `PTRACE_GETREGSET` → save `UserPtRegs` as `saved`.
5. Build `work = saved` with `pc = scratch_pc`, `regs[8] = syscall_no`,
   `regs[0..6] = args`. Leave `sp`, `pstate`, `regs[29]` (fp), `regs[30]`
   (lr) alone — kernel entry uses its own stack.
6. `PTRACE_SETREGSET(work)` → `PTRACE_CONT`.
7. `waitpid(pid, &status, __WALL)`: expect `WIFSTOPPED` with
   `WSTOPSIG == SIGTRAP` and event byte 0.
8. `PTRACE_GETREGSET` → `ret = regs[0] as i64`. Values in `-4095..=-1`
   are `-errno`.
9. `PTRACE_SETREGSET(saved)`; restore the 8 saved bytes at `scratch_pc`.

Save/restore 8 bytes (not 4) because the stager writes `svc + brk`.

I-cache coherence: `process_vm_writev` hits the D-side only. The I-side
can see stale instructions. Mitigations:

- Allocate a fresh `PROT_READ|PROT_WRITE|PROT_EXEC` page via a bootstrap
  remote `mmap` (see section 8) and execute from there.
- Use `membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE)` remotely
  (requires prior registration in the tracee).
- Call a remote libc `__clear_cache` equivalent after overwrite.

Do not rely on implicit D-to-I snooping.

## 8. Tail-of-libc Padding (Safer Scratch)

Overwriting live libc code races concurrent threads. Two safer options:

1. `mmap` first, execute second (preferred). Bootstrap via a one-shot
   `svc` inside padding you can safely find (zero-padded tail of
   `libc.so` `.text`, located via `/proc/<pid>/maps` + ELF parsing).
   Issue `mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`. Stage in the returned page; only
   the first shot touches live libc.
2. Nop-slide hunting. Scan rx regions of `libc.so` (or `[vdso]`) for a
   4-byte-aligned run of `0xD503201F` (AArch64 `nop`). `process_vm_writev`
   respects VMA write permissions (per `man 2 process_vm_writev`:
   returns `EFAULT` on non-writable pages), so callers staging into rx
   regions must either `mprotect` them writable remotely first or use
   `PTRACE_POKEDATA`/`/proc/<pid>/mem` instead. I-cache staleness
   still applies regardless of the transport chosen.

## 9. SIGTRAP vs Group-stop vs Syscall-stop

`waitpid` returns a 32-bit status; decode:

```rust
let wifstopped = libc::WIFSTOPPED(status);
let stopsig    = libc::WSTOPSIG(status);     // low 8 of (status>>8)
let event      = (status >> 16) & 0xffff;    // ptrace event byte
```

Taxonomy:

- SIGTRAP from `brk #0` (wanted): `wifstopped`, `stopsig == SIGTRAP` (5),
  `event == 0`.
- Syscall-stop: `stopsig == SIGTRAP | 0x80` (0x85). Only with
  `PTRACE_SYSCALL`; unexpected in this flow.
- Group-stop (SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU): `event ==
  PTRACE_EVENT_STOP` (128). Initial SEIZE+INTERRUPT stop also reports
  `event == 128` with `stopsig == SIGTRAP` — that one is expected.
- Other `PTRACE_EVENT_*` values (1..=7): fork/exec during injection.

```rust
fn is_brk_trap(status: i32) -> bool {
    libc::WIFSTOPPED(status)
        && libc::WSTOPSIG(status) == libc::SIGTRAP
        && ((status >> 16) & 0xffff) == 0
}
```

## 10. `process_vm_readv` / `process_vm_writev`

Signatures (Linux man pages, confirmed in libc crate):
```rust
extern "C" {
    fn process_vm_readv(
        pid: libc::pid_t,
        local_iov: *const libc::iovec,
        liovcnt:   libc::c_ulong,
        remote_iov:*const libc::iovec,
        riovcnt:   libc::c_ulong,
        flags:     libc::c_ulong,
    ) -> libc::ssize_t;
    fn process_vm_writev(
        pid: libc::pid_t,
        local_iov: *const libc::iovec,
        liovcnt:   libc::c_ulong,
        remote_iov:*const libc::iovec,
        riovcnt:   libc::c_ulong,
        flags:     libc::c_ulong,
    ) -> libc::ssize_t;
}
```
- Return: bytes transferred, or `-1` with `errno`. Partial transfers
  possible; loop until complete.
- `flags` must be `0`.
- `UIO_MAXIOV` = 1024 (man: max 1016 usable). One iovec per call
  suffices here.
- Gated by `PTRACE_MODE_ATTACH_REALCREDS` (same rules as ptrace).

## 11. Failure Modes

`/proc/sys/kernel/yama/ptrace_scope`:

- `0` — any same-uid process may attach.
- `1` — only descendants (or with `prctl(PR_SET_PTRACER, ...)`).
- `2` — only `CAP_SYS_PTRACE` holders.
- `3` — attach disabled system-wide (no runtime reversal).

Android: typically `0` on userdebug, `1` on user. PID 1 always requires
effective `CAP_SYS_PTRACE`.

Errno values:

- `EPERM` — yama scope or SELinux denied (separate gates).
- `ESRCH` — tracee died, reaped, or not stopped when a stop was required.
- `EIO` — unknown request, or bad `addr`/`data` for PEEK/POKE.
- `EFAULT` — iovec outside tracer's AS (REGSET) or tracee's
  (`process_vm_*`).
- `EINVAL` — e.g. `NT_PRSTATUS` buffer smaller than 272 bytes.

SELinux gates PID 1 (`init_t`): a domain needs
`allow <src> init_t:process ptrace;`. `u:r:su:s0` (Magisk/KernelSU)
typically has it; a plain shell does not.

## 12. Minimal Rust Skeleton

Single-shot remote syscall. No `nix`. Assumes the tracee is already
seized and stopped.

```rust
use libc::{c_long, c_void, iovec, pid_t, ptrace, waitpid, __WALL, SIGTRAP};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UserPtRegs {
    pub regs: [u64; 31], pub sp: u64, pub pc: u64, pub pstate: u64,
}

const PTRACE_GETREGSET: c_long = 0x4204;
const PTRACE_SETREGSET: c_long = 0x4205;
const PTRACE_CONT:      c_long = 7;
const NT_PRSTATUS:      c_long = 1;

unsafe fn regset(pid: pid_t, req: c_long, r: *mut UserPtRegs) -> i32 {
    let mut iov = iovec { iov_base: r as *mut c_void, iov_len: 272 };
    if ptrace(req as _, pid, NT_PRSTATUS as *mut c_void,
              &mut iov as *mut _ as *mut c_void) == -1 {
        return *libc::__errno_location();
    }
    0
}

/// Execute `syscall_no(args...)` inside `pid`. Caller must have staged
/// `svc #0; brk #0` at `scratch_pc` and ensured the tracee is
/// ptrace-stopped at the point of this call. Returns the raw `x0` as i64;
/// values in -4095..=-1 are -errno.
pub unsafe fn remote_syscall(
    pid: pid_t, scratch_pc: u64, syscall_no: u64, args: [u64; 6],
) -> Result<i64, i32> {
    let mut saved = UserPtRegs::default();
    let e = regset(pid, PTRACE_GETREGSET, &mut saved);
    if e != 0 { return Err(e); }

    let mut work = saved;
    work.pc = scratch_pc;
    work.regs[8] = syscall_no;
    work.regs[0..6].copy_from_slice(&args);

    let e = regset(pid, PTRACE_SETREGSET, &mut work);
    if e != 0 { return Err(e); }

    if ptrace(PTRACE_CONT as _, pid, 0 as *mut c_void, 0 as *mut c_void) == -1 {
        return Err(*libc::__errno_location());
    }

    let mut status: i32 = 0;
    if waitpid(pid, &mut status, __WALL) == -1 {
        return Err(*libc::__errno_location());
    }
    let wifstopped = libc::WIFSTOPPED(status);
    let stopsig    = libc::WSTOPSIG(status);
    let event      = (status >> 16) & 0xffff;
    if !(wifstopped && stopsig == SIGTRAP && event == 0) {
        return Err(libc::EPROTO); // wrong kind of stop
    }

    let mut out = UserPtRegs::default();
    let e = regset(pid, PTRACE_GETREGSET, &mut out);
    if e != 0 { return Err(e); }

    let ret = out.regs[0] as i64;

    // restore original regs so caller can re-enter or detach cleanly
    let e = regset(pid, PTRACE_SETREGSET, &mut (saved.clone()));
    if e != 0 { return Err(e); }

    Ok(ret)
}
```

Caller responsibilities (not shown): `PTRACE_SEIZE` + `INTERRUPT`,
`process_vm_readv`/`writev` to save and stage the 8-byte `svc; brk` blob
at `scratch_pc`, restore the blob, then `PTRACE_DETACH`. Pick
`scratch_pc` per section 8 — bootstrap via `mmap` is the clean path for
PID 1.

---

## Citations

Paths rooted at AOSP bionic `libc/kernel/uapi/` (or matching generic
kernel UAPI).

| Constant | Value | File:line |
|---|---|---|
| `__NR_openat` | 56 | asm-generic/unistd.h:158 |
| `__NR_close` | 57 | asm-generic/unistd.h:160 |
| `__NR_exit` | 93 | asm-generic/unistd.h:258 |
| `__NR_rt_sigreturn` | 139 | asm-generic/unistd.h:386 |
| `__NR_getpid` | 172 | asm-generic/unistd.h:461 |
| `__NR_munmap` | 215 | asm-generic/unistd.h:556 |
| `__NR_mmap` | 222 | asm-generic/unistd.h:570,886 |
| `__NR_mprotect` | 226 | asm-generic/unistd.h:581 |
| `__NR_process_vm_readv` | 270 | asm-generic/unistd.h:657 |
| `__NR_process_vm_writev` | 271 | asm-generic/unistd.h:659 |
| `__NR_membarrier` | 283 | asm-generic/unistd.h:683 |
| `PTRACE_CONT` | 7 | linux/ptrace.h:17 |
| `PTRACE_DETACH` | 17 | linux/ptrace.h:21 |
| `PTRACE_GETREGSET` | 0x4204 | linux/ptrace.h:27 |
| `PTRACE_SETREGSET` | 0x4205 | linux/ptrace.h:28 |
| `PTRACE_SEIZE` | 0x4206 | linux/ptrace.h:29 |
| `PTRACE_INTERRUPT` | 0x4207 | linux/ptrace.h:30 |
| `PTRACE_EVENT_STOP` | 128 | linux/ptrace.h:99 |
| `PTRACE_O_TRACESYSGOOD` | 1 | linux/ptrace.h:100 |
| `NT_PRSTATUS` | 1 | linux/elf.h:301 |
| `user_pt_regs` | 272 B | asm-arm64/asm/ptrace.h:49-54 |
| `svc #0` | 0xD4000001 | ARM ARM C6.2.304 |
| `brk #0` | 0xD4200000 | ARM ARM C6.2.41 |
