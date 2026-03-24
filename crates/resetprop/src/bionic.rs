#[cfg(target_os = "android")]
mod inner {
    use std::ffi::{c_char, c_int, c_void, CStr, CString};
    use std::sync::OnceLock;
    use std::time::Duration;

    type FindFn = unsafe extern "C" fn(*const c_char) -> *const c_void;
    type ReadCallbackFn = unsafe extern "C" fn(
        *const c_void,
        Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, u32)>,
        *mut c_void,
    );
    type ForeachFn = unsafe extern "C" fn(
        Option<unsafe extern "C" fn(*const c_void, *mut c_void)>,
        *mut c_void,
    ) -> c_int;
    type WaitFn =
        unsafe extern "C" fn(*const c_void, u32, *mut u32, *const libc::timespec) -> bool;

    struct BionicFns {
        find: FindFn,
        read_callback: ReadCallbackFn,
        foreach: ForeachFn,
        wait: Option<WaitFn>,
    }

    static BIONIC: OnceLock<Option<BionicFns>> = OnceLock::new();

    #[allow(clippy::missing_transmute_annotations)]
    fn init() -> Option<BionicFns> {
        unsafe {
            let handle = libc::dlopen(b"libc.so\0".as_ptr().cast(), libc::RTLD_NOLOAD);
            if handle.is_null() {
                return None;
            }

            let find_ptr = libc::dlsym(handle, b"__system_property_find\0".as_ptr().cast());
            let read_cb_ptr =
                libc::dlsym(handle, b"__system_property_read_callback\0".as_ptr().cast());
            let foreach_ptr =
                libc::dlsym(handle, b"__system_property_foreach\0".as_ptr().cast());

            // All three required symbols must exist
            if find_ptr.is_null() || read_cb_ptr.is_null() || foreach_ptr.is_null() {
                libc::dlclose(handle);
                return None;
            }

            let find: FindFn = std::mem::transmute(find_ptr);
            let read_callback: ReadCallbackFn = std::mem::transmute(read_cb_ptr);
            let foreach: ForeachFn = std::mem::transmute(foreach_ptr);

            let wait_ptr = libc::dlsym(handle, b"__system_property_wait\0".as_ptr().cast());
            let wait: Option<WaitFn> = if wait_ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute(wait_ptr))
            };

            libc::dlclose(handle);

            Some(BionicFns {
                find,
                read_callback,
                foreach,
                wait,
            })
        }
    }

    fn fns() -> Option<&'static BionicFns> {
        BIONIC.get_or_init(init).as_ref()
    }

    pub(crate) fn available() -> bool {
        fns().is_some()
    }

    unsafe extern "C" fn read_cb(
        cookie: *mut c_void,
        name: *const c_char,
        value: *const c_char,
        _serial: u32,
    ) {
        let pair = &mut *(cookie as *mut (String, String));
        if !name.is_null() {
            pair.0 = CStr::from_ptr(name).to_string_lossy().into_owned();
        }
        if !value.is_null() {
            pair.1 = CStr::from_ptr(value).to_string_lossy().into_owned();
        }
    }

    pub(crate) fn get(name: &str) -> Option<String> {
        let fns = fns()?;
        let cname = CString::new(name).ok()?;

        unsafe {
            let pi = (fns.find)(cname.as_ptr());
            if pi.is_null() {
                return None;
            }

            let mut pair = (String::new(), String::new());
            let cookie = &mut pair as *mut (String, String) as *mut c_void;
            (fns.read_callback)(pi, Some(read_cb), cookie);

            Some(pair.1)
        }
    }

    unsafe extern "C" fn foreach_cb(pi: *const c_void, cookie: *mut c_void) {
        let ctx = &mut *(cookie as *mut ForeachCtx);
        let mut pair = (String::new(), String::new());
        let pair_ptr = &mut pair as *mut (String, String) as *mut c_void;
        (ctx.read_callback)(pi, Some(read_cb), pair_ptr);
        if !pair.0.is_empty() {
            ctx.results.push(pair);
        }
    }

    struct ForeachCtx {
        read_callback: ReadCallbackFn,
        results: Vec<(String, String)>,
    }

    pub(crate) fn foreach() -> Vec<(String, String)> {
        let Some(fns) = fns() else {
            return Vec::new();
        };

        let mut ctx = ForeachCtx {
            read_callback: fns.read_callback,
            results: Vec::new(),
        };

        unsafe {
            let cookie = &mut ctx as *mut ForeachCtx as *mut c_void;
            (fns.foreach)(Some(foreach_cb), cookie);
        }

        ctx.results
    }

    pub(crate) fn wait_prop(
        name: &str,
        old_serial: u32,
        timeout: Option<Duration>,
    ) -> Option<u32> {
        let fns = fns()?;
        let wait = fns.wait?;

        let pi = CString::new(name).ok().and_then(|cname| unsafe {
            let p = (fns.find)(cname.as_ptr());
            if p.is_null() { None } else { Some(p) }
        });

        // null pi = wait on global serial (prop doesn't exist yet)
        let pi_ptr = pi.unwrap_or(std::ptr::null());

        let ts = timeout.map(|d| libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        });

        let ts_ptr = match ts.as_ref() {
            Some(t) => t as *const libc::timespec,
            None => std::ptr::null(),
        };

        let mut new_serial: u32 = 0;
        let ok = unsafe { (wait)(pi_ptr, old_serial, &mut new_serial, ts_ptr) };
        if ok { Some(new_serial) } else { None }
    }
}

#[cfg(not(target_os = "android"))]
mod inner {
    use std::time::Duration;

    pub(crate) fn available() -> bool {
        false
    }

    pub(crate) fn get(_name: &str) -> Option<String> {
        None
    }

    pub(crate) fn foreach() -> Vec<(String, String)> {
        Vec::new()
    }

    pub(crate) fn wait_prop(
        _name: &str,
        _old_serial: u32,
        _timeout: Option<Duration>,
    ) -> Option<u32> {
        None
    }
}

pub(crate) use inner::*;
