use std::ffi::CString;
use std::path::Path;

use crate::{Error, Result};

const PERSIST_FILE: &str = "persistent_properties";
const PERSIST_TMP: &str = "persistent_properties.tmp";
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

pub(crate) fn is_protobuf(dir: &Path) -> bool {
    dir.join(PERSIST_FILE).is_file()
}

pub(crate) fn read_file(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join(PERSIST_FILE);
    std::fs::read(&path).map_err(Error::from)
}

pub(crate) fn atomic_write(dir: &Path, data: &[u8]) -> Result<()> {
    let actual = dir.join(PERSIST_FILE);
    let tmp = dir.join(PERSIST_TMP);

    let selinux_ctx = get_selinux_context(&actual);

    let tmp_c = path_to_cstring(&tmp)?;
    let fd = unsafe {
        libc::open(
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let result = write_and_sync(fd, data, &selinux_ctx);

    unsafe { libc::close(fd); }

    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    let old_c = path_to_cstring(&tmp)?;
    let new_c = path_to_cstring(&actual)?;
    if unsafe { libc::rename(old_c.as_ptr(), new_c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    fsync_dir(dir)?;
    Ok(())
}

fn write_and_sync(fd: i32, data: &[u8], selinux_ctx: &Option<Vec<u8>>) -> Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let n = unsafe {
            libc::write(fd, data[written..].as_ptr() as *const libc::c_void, data.len() - written)
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        written += n as usize;
    }

    if let Some(ctx) = selinux_ctx {
        unsafe {
            libc::fsetxattr(
                fd,
                SELINUX_XATTR.as_ptr() as *const libc::c_char,
                ctx.as_ptr() as *const libc::c_void,
                ctx.len(),
                0,
            );
        }
    }

    unsafe {
        libc::fchown(fd, 0, 0);
        if libc::fsync(fd) != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

fn get_selinux_context(path: &Path) -> Option<Vec<u8>> {
    let c_path = path_to_cstring(path).ok()?;
    let mut buf = vec![0u8; 256];
    let len = unsafe {
        libc::lgetxattr(
            c_path.as_ptr(),
            SELINUX_XATTR.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

fn fsync_dir(dir: &Path) -> Result<()> {
    let c_path = path_to_cstring(dir)?;
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let rc = unsafe { libc::fsync(fd) };
    unsafe { libc::close(fd); }
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::PersistCorrupt("path contains null byte".into()))
}
