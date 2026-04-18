//! T3 fixture cdylib.
//!
//! Emits three `no_mangle` / `extern "C"` stubs so the built `.so` has a
//! deterministic `.dynsym` for the `elf_fixture_smoke` integration test.
//! The symbol names intentionally overlap bionic's real
//! `__system_property_update` so the same lookup path that T4 will drive
//! on-device can be exercised against the fixture.

#[no_mangle]
pub extern "C" fn __system_property_update() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn seal_fixture_probe_a() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn seal_fixture_probe_b() -> i32 {
    0
}
