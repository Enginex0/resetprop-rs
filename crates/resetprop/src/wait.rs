use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::{bionic, info, trie, PropSystem};

impl PropSystem {
    /// Blocks until a property meets the expected condition.
    ///
    /// If `expected` is `None`, waits for the property to exist (any value).
    /// If `expected` is `Some(val)`, waits for the property to equal `val`.
    /// Returns `Some(value)` when the condition is met, `None` on timeout.
    pub fn wait(
        &self,
        name: &str,
        expected: Option<&str>,
        timeout: Option<Duration>,
    ) -> Option<String> {
        if let Some(val) = self.try_bionic_wait(name, expected, timeout) {
            return Some(val);
        }
        self.mmap_wait(name, expected, timeout)
    }

    fn check_condition(&self, name: &str, expected: Option<&str>) -> Option<String> {
        let val = self.get(name)?;
        match expected {
            Some(exp) if val != exp => None,
            _ => Some(val),
        }
    }

    fn try_bionic_wait(
        &self,
        name: &str,
        expected: Option<&str>,
        timeout: Option<Duration>,
    ) -> Option<String> {
        if !bionic::available() {
            return None;
        }

        let deadline = timeout.map(|d| Instant::now() + d);
        let mut serial: u32 = 0;

        loop {
            if let Some(val) = self.check_condition(name, expected) {
                return Some(val);
            }

            let remaining = remaining_timeout(deadline)?;
            match bionic::wait_prop(name, serial, remaining) {
                Some(new_serial) => serial = new_serial,
                None => return None,
            }
        }
    }

    fn mmap_wait(
        &self,
        name: &str,
        expected: Option<&str>,
        timeout: Option<Duration>,
    ) -> Option<String> {
        let deadline = timeout.map(|d| Instant::now() + d);

        loop {
            if let Some(val) = self.check_condition(name, expected) {
                return Some(val);
            }

            let remaining = remaining_timeout(deadline)?;
            let ts = remaining.map(|d| libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            });

            if let Some((area, pi_off)) = self.find_prop_info(name) {
                // Property exists: wait on its serial to change
                let serial = area.read_u32(pi_off) & !1u32;
                area.futex_wait(pi_off, serial, ts.as_ref());
            } else if let Some((_, ref sa)) = self.serial_area {
                // Property doesn't exist yet: wait on global serial
                let serial = sa.serial().load(Ordering::Acquire);
                sa.futex_wait(4, serial, ts.as_ref());
            } else {
                return None;
            }
        }
    }

    fn find_prop_info(&self, name: &str) -> Option<(&crate::area::PropArea, usize)> {
        for (_, area) in &self.areas {
            if let Ok((pi_off, _)) = trie::find(area, name) {
                if info::PropInfo::at(area, pi_off).is_ok() {
                    return Some((area, pi_off));
                }
            }
        }
        None
    }
}

fn remaining_timeout(deadline: Option<Instant>) -> Option<Option<Duration>> {
    match deadline {
        None => Some(None),
        Some(dl) => {
            let now = Instant::now();
            if now >= dl {
                None
            } else {
                Some(Some(dl - now))
            }
        }
    }
}
