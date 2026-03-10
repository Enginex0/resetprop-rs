use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{Error, Result};

const PROP_AREA_MAGIC: u32 = 0x504f5250;
const PROP_AREA_VERSION: u32 = 0xfc6ed0ab;
pub(crate) const HEADER_SIZE: usize = 128;

pub struct PropArea {
    base: *mut u8,
    len: usize,
    writable: bool,
}

unsafe impl Send for PropArea {}
unsafe impl Sync for PropArea {}

impl PropArea {
    pub fn open(path: &Path) -> Result<Self> {
        Self::mmap(path, true)
    }

    pub fn open_ro(path: &Path) -> Result<Self> {
        Self::mmap(path, false)
    }

    fn mmap(path: &Path, writable: bool) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")))?;

        let flags = if writable { libc::O_RDWR } else { libc::O_RDONLY };
        let fd = unsafe { libc::open(c_path.as_ptr(), flags | libc::O_NOFOLLOW) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err.into());
        }

        let file_size = stat.st_size as usize;
        if file_size < HEADER_SIZE {
            unsafe { libc::close(fd) };
            return Err(Error::AreaCorrupt(format!("file too small: {file_size} bytes")));
        }

        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let ptr = unsafe {
            libc::mmap(std::ptr::null_mut(), file_size, prot, libc::MAP_SHARED, fd, 0)
        };
        unsafe { libc::close(fd) };

        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().into());
        }

        let area = Self {
            base: ptr as *mut u8,
            len: file_size,
            writable,
        };

        area.validate_header()?;
        Ok(area)
    }

    fn validate_header(&self) -> Result<()> {
        let magic = self.read_u32(8);
        let version = self.read_u32(12);

        if magic != PROP_AREA_MAGIC {
            return Err(Error::AreaCorrupt(format!("bad magic: {magic:#x}")));
        }
        if version != PROP_AREA_VERSION {
            return Err(Error::AreaCorrupt(format!("bad version: {version:#x}")));
        }
        Ok(())
    }

    pub(crate) fn base(&self) -> *mut u8 {
        self.base
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn data_offset(&self) -> usize {
        HEADER_SIZE
    }

    pub(crate) fn read_u32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.len);
        unsafe { (self.base.add(offset) as *const u32).read_unaligned() }
    }

    pub(crate) fn atomic_u32(&self, offset: usize) -> &AtomicU32 {
        assert!(offset + 4 <= self.len);
        // prop_area is always 4-byte aligned
        unsafe { AtomicU32::from_ptr(self.base.add(offset) as *mut u32) }
    }

    pub(crate) fn bytes_used(&self) -> &AtomicU32 {
        self.atomic_u32(0)
    }

    #[allow(dead_code)]
    pub(crate) fn serial(&self) -> &AtomicU32 {
        self.atomic_u32(4)
    }

    pub(crate) fn ptr_at(&self, offset: usize) -> Option<*mut u8> {
        if offset < self.len {
            Some(unsafe { self.base.add(offset) })
        } else {
            None
        }
    }

    /// Bump-allocate `size` bytes in the arena. Returns offset from base.
    pub(crate) fn alloc(&self, size: usize) -> Result<usize> {
        if !self.writable {
            return Err(Error::PermissionDenied(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "area opened read-only",
            )));
        }

        let aligned = (size + 3) & !3;
        let bu = self.bytes_used();
        loop {
            let current = bu.load(Ordering::Acquire);
            let new_offset = HEADER_SIZE + current as usize + aligned;
            if new_offset > self.len {
                return Err(Error::AreaFull);
            }
            if bu
                .compare_exchange_weak(current, current + aligned as u32, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(HEADER_SIZE + current as usize);
            }
        }
    }
}

impl Drop for PropArea {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.base as *mut libc::c_void, self.len);
        }
    }
}
