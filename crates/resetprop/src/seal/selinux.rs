//! Relabel the in-memory hook fd to the on-device libc.so security context so
//! init can map it `PROT_READ | PROT_EXEC` without an SELinux `execute` denial.
//!
//! Ports injectrc's `set_system_con` (init_injector/ptrace_utils.cpp): take the
//! context of the system libc.so and `setfilecon` it onto the staged fd path.
//!
//! Single-dep law: no `selinux-sys` crate. The Android NDK ships no libselinux
//! to link against, so the Android path resolves `getfilecon` / `setfilecon` /
//! `freecon` at runtime via `dlopen`; on-device the loader always finds
//! `/system/lib*/libselinux.so`. Off-device the relabel is meaningless (there
//! is no real init to satisfy), so the host build compiles a shim that reports
//! the operation unsupported.

use crate::error::{Error, Result};
use std::ffi::CStr;

/// Relabel `path` to the SELinux context init is permitted to execute.
#[cfg(not(target_os = "android"))]
pub(crate) fn relabel_to_libc_context(_path: &CStr) -> Result<()> {
    Err(Error::Unsupported(
        "SELinux relabel only applies against on-device init".into(),
    ))
}

/// Relabel `path` to the SELinux context init is permitted to execute.
#[cfg(target_os = "android")]
pub(crate) fn relabel_to_libc_context(path: &CStr) -> Result<()> {
    android::relabel(path)
}

#[cfg(target_os = "android")]
mod android {
    use super::{CStr, Error, Result};
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_void};

    type GetFileCon = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> c_int;
    type SetFileCon = unsafe extern "C" fn(*const c_char, *const c_char) -> c_int;
    type FreeCon = unsafe extern "C" fn(*mut c_char);

    struct Libselinux {
        getfilecon: GetFileCon,
        setfilecon: SetFileCon,
        freecon: FreeCon,
    }

    /// libc.so always carries a context init may execute; mirror injectrc's
    /// fixed-path probe rather than re-deriving init's exact maps row.
    const LIBC_PATH: &CStr = c"/system/lib64/libc.so";

    /// Used when `getfilecon` on libc.so fails (matches injectrc's fallback).
    const FALLBACK_CON: &CStr = c"u:object_r:system_file:s0";

    pub(super) fn relabel(path: &CStr) -> Result<()> {
        let lib = load()?;
        let con = libc_context(&lib);
        // SAFETY: `path` and `con` are valid NUL-terminated C strings; the fn
        // pointer was resolved from libselinux by name.
        let rc = unsafe { (lib.setfilecon)(path.as_ptr(), con.as_ptr()) };
        if rc != 0 {
            return Err(Error::HookInstallFailed(format!(
                "setfilecon({}) failed",
                path.to_string_lossy()
            )));
        }
        Ok(())
    }

    fn load() -> Result<Libselinux> {
        let name = c"libselinux.so";
        // SAFETY: opening a system library by literal name; RTLD_NOW resolves
        // every symbol eagerly so a missing export fails here, not mid-call.
        let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            return Err(Error::HookInstallFailed("dlopen libselinux.so failed".into()));
        }
        // The handle is intentionally never `dlclose`d: libselinux stays
        // resident for the single per-boot install and the process is short.
        // SAFETY: each symbol is resolved by name then transmuted to its
        // libselinux ABI; a null lookup is rejected before transmute.
        unsafe {
            Ok(Libselinux {
                getfilecon: std::mem::transmute::<*mut c_void, GetFileCon>(sym(handle, c"getfilecon")?),
                setfilecon: std::mem::transmute::<*mut c_void, SetFileCon>(sym(handle, c"setfilecon")?),
                freecon: std::mem::transmute::<*mut c_void, FreeCon>(sym(handle, c"freecon")?),
            })
        }
    }

    /// SAFETY: `handle` is a live `dlopen` handle.
    unsafe fn sym(handle: *mut c_void, name: &CStr) -> Result<*mut c_void> {
        let ptr = libc::dlsym(handle, name.as_ptr());
        if ptr.is_null() {
            return Err(Error::HookInstallFailed(format!(
                "dlsym {} failed",
                name.to_string_lossy()
            )));
        }
        Ok(ptr)
    }

    fn libc_context(lib: &Libselinux) -> CString {
        let mut con: *mut c_char = std::ptr::null_mut();
        // SAFETY: getfilecon allocates `*con` on success; freed below.
        let rc = unsafe { (lib.getfilecon)(LIBC_PATH.as_ptr(), &mut con) };
        if rc < 0 || con.is_null() {
            return FALLBACK_CON.to_owned();
        }
        // SAFETY: `con` is a NUL-terminated context string owned by libselinux.
        let owned = unsafe { CStr::from_ptr(con) }.to_owned();
        // SAFETY: release the libselinux-allocated context.
        unsafe { (lib.freecon)(con) };
        owned
    }
}
