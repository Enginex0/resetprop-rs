use std::sync::atomic::Ordering;

use crate::area::PropArea;
use crate::error::{Error, Result};

const PROP_INFO_FIXED: usize = 96; // serial(4) + value[92]
pub(crate) const PROP_VALUE_MAX: usize = 92;
const LONG_FLAG: u32 = 1 << 16;
const LONG_PROP_ERROR_SIZE: usize = 56;

pub(crate) struct PropInfo<'a> {
    area: &'a PropArea,
    offset: usize,
}

impl<'a> PropInfo<'a> {
    pub(crate) fn at(area: &'a PropArea, offset: usize) -> Result<Self> {
        if offset + PROP_INFO_FIXED > area.len() {
            return Err(Error::AreaCorrupt("prop_info OOB".into()));
        }
        Ok(Self { area, offset })
    }

    fn serial_atomic(&self) -> &std::sync::atomic::AtomicU32 {
        self.area.atomic_u32(self.offset)
    }

    fn read_serial_stable(&self) -> u32 {
        loop {
            let s = self.serial_atomic().load(Ordering::Acquire);
            if s & 1 == 0 {
                return s;
            }
            std::hint::spin_loop();
        }
    }

    fn is_long(&self, serial: u32) -> bool {
        serial & LONG_FLAG != 0
    }

    fn value_len(&self, serial: u32) -> usize {
        ((serial >> 24) & 0xFF) as usize
    }

    pub(crate) fn read_value(&self) -> String {
        loop {
            let serial = self.read_serial_stable();
            let val = if self.is_long(serial) {
                self.read_long_value()
            } else {
                self.read_short_value(serial)
            };

            // verify serial didn't change during read
            std::sync::atomic::fence(Ordering::Acquire);
            let after = self.serial_atomic().load(Ordering::Relaxed);
            if after == serial {
                return val;
            }
        }
    }

    fn read_short_value(&self, serial: u32) -> String {
        let len = self.value_len(serial).min(PROP_VALUE_MAX - 1);
        let value_start = self.offset + 4;
        if value_start + len > self.area.len() {
            return String::new();
        }
        unsafe {
            let ptr = self.area.base().add(value_start);
            let bytes = std::slice::from_raw_parts(ptr, len);
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    fn read_long_value(&self) -> String {
        let long_offset_pos = self.offset + 4 + LONG_PROP_ERROR_SIZE;
        let rel_offset = match self.area.try_read_u32(long_offset_pos) {
            Some(v) => v as usize,
            None => return String::new(),
        };

        let abs = match self.offset.checked_add(rel_offset) {
            Some(v) => v,
            None => return String::new(),
        };

        // must point past the prop_info record to avoid reading header bytes as value
        let name_start = self.offset + PROP_INFO_FIXED;
        let name_len = {
            let mut n = 0usize;
            if name_start < self.area.len() {
                unsafe {
                    let ptr = self.area.base().add(name_start);
                    let max = self.area.len() - name_start;
                    while n < max && *ptr.add(n) != 0 {
                        n += 1;
                    }
                }
            }
            n
        };
        let min_abs = (self.offset + PROP_INFO_FIXED + name_len + 1 + 3) & !3;
        if abs < min_abs {
            return String::new();
        }

        if abs >= self.area.len() {
            return String::new();
        }

        unsafe {
            let ptr = self.area.base().add(abs);
            let max_scan = self.area.len() - abs;
            let mut len = 0;
            while len < max_scan && *ptr.add(len) != 0 {
                len += 1;
            }
            let bytes = std::slice::from_raw_parts(ptr, len);
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    pub(crate) fn read_name(&self) -> String {
        let name_start = self.offset + PROP_INFO_FIXED;
        if name_start >= self.area.len() {
            return String::new();
        }
        unsafe {
            let ptr = self.area.base().add(name_start);
            let max_scan = self.area.len() - name_start;
            let mut len = 0;
            while len < max_scan && *ptr.add(len) != 0 {
                len += 1;
            }
            let bytes = std::slice::from_raw_parts(ptr, len);
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    pub(crate) fn write_value(&self, value: &str) -> Result<()> {
        if !self.area.writable() {
            return Err(Error::PermissionDenied(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "area opened read-only",
            )));
        }

        let serial = self.read_serial_stable();
        if self.is_long(serial) {
            return self.write_long_value(value, serial);
        }

        if value.len() >= PROP_VALUE_MAX {
            return Err(Error::ValueTooLong { len: value.len() });
        }

        let sa = self.serial_atomic();
        // set dirty bit
        sa.store(serial | 1, Ordering::Release);
        std::sync::atomic::fence(Ordering::Release);

        unsafe {
            let ptr = self.area.base().add(self.offset + 4);
            std::ptr::copy_nonoverlapping(value.as_ptr(), ptr, value.len());
            *ptr.add(value.len()) = 0;
        }

        let new_serial = (serial + 2) & 0x00FFFFFF | ((value.len() as u32) << 24);
        std::sync::atomic::fence(Ordering::Release);
        sa.store(new_serial, Ordering::Release);
        self.area.futex_wake(self.offset);

        Ok(())
    }

    fn write_long_value(&self, value: &str, serial: u32) -> Result<()> {
        let long_offset_pos = self.offset + 4 + LONG_PROP_ERROR_SIZE;
        let rel_offset = self.area.read_u32(long_offset_pos) as usize;
        let abs = self.offset + rel_offset;

        if abs + value.len() + 1 > self.area.len() {
            return Err(Error::ValueTooLong { len: value.len() });
        }

        let sa = self.serial_atomic();
        sa.store(serial | 1, Ordering::Release);
        std::sync::atomic::fence(Ordering::Release);

        unsafe {
            let ptr = self.area.base().add(abs);
            std::ptr::copy_nonoverlapping(value.as_ptr(), ptr, value.len());
            *ptr.add(value.len()) = 0;
        }

        let new_serial = ((serial + 2) & 0x00FFFFFF) | LONG_FLAG | ((value.len() as u32 & 0xFF) << 24);
        std::sync::atomic::fence(Ordering::Release);
        sa.store(new_serial, Ordering::Release);
        self.area.futex_wake(self.offset);

        Ok(())
    }

    pub(crate) fn zero_value(&self) -> Result<()> {
        if !self.area.writable() {
            return Err(Error::PermissionDenied(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "area opened read-only",
            )));
        }

        let serial = self.read_serial_stable();

        if self.is_long(serial) {
            let long_offset_pos = self.offset + 4 + LONG_PROP_ERROR_SIZE;
            let rel_offset = self.area.read_u32(long_offset_pos) as usize;
            let abs = self.offset + rel_offset;
            if abs < self.area.len() {
                unsafe {
                    let ptr = self.area.base().add(abs);
                    *ptr = 0;
                }
            }
        } else {
            unsafe {
                let ptr = self.area.base().add(self.offset + 4);
                std::ptr::write_bytes(ptr, 0, PROP_VALUE_MAX);
            }
        }

        // zero length byte, preserve counter + flags (stealth: no serial bump)
        let new_serial = serial & 0x00FFFFFE;
        self.serial_atomic().store(new_serial, Ordering::Release);

        Ok(())
    }

    pub(crate) fn stealth_write_value(&self) -> Result<()> {
        if !self.area.writable() {
            return Err(Error::PermissionDenied(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "area opened read-only",
            )));
        }

        let serial = self.read_serial_stable();

        if self.is_long(serial) {
            let long_offset_pos = self.offset + 4 + LONG_PROP_ERROR_SIZE;
            let rel_offset = self.area.read_u32(long_offset_pos) as usize;
            let abs = self.offset + rel_offset;
            if abs < self.area.len() {
                unsafe {
                    let ptr = self.area.base().add(abs);
                    *ptr = 0;
                }
            }
        }

        unsafe {
            let ptr = self.area.base().add(self.offset + 4);
            std::ptr::write_bytes(ptr, 0, PROP_VALUE_MAX);
            *ptr = b'0';
        }

        // length=1 in top byte, clear dirty (bit 0) + kLongFlag (bit 16), preserve counter
        let new_serial = (1u32 << 24) | (serial & 0x00FE_FFFE);
        self.serial_atomic().store(new_serial, Ordering::Release);

        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
}

pub(crate) fn alloc_prop_info(area: &PropArea, name: &str, value: &str) -> Result<usize> {
    if value.len() >= PROP_VALUE_MAX {
        return Err(Error::ValueTooLong { len: value.len() });
    }

    let name_bytes = name.as_bytes();
    let total = (PROP_INFO_FIXED + name_bytes.len() + 1 + 3) & !3;
    let offset = area.alloc(total)?;

    unsafe {
        let base = area.base().add(offset);
        std::ptr::write_bytes(base, 0, total);

        // write value
        let val_ptr = base.add(4);
        std::ptr::copy_nonoverlapping(value.as_ptr(), val_ptr, value.len());

        // write name after fixed portion
        let name_ptr = base.add(PROP_INFO_FIXED);
        std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_ptr, name_bytes.len());

        // set serial: length in top byte, even (clean)
        let serial = (value.len() as u32) << 24;
        (base as *mut u32).write(serial);
    }

    Ok(offset)
}
