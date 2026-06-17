//! T3 fixture-driven symbol-resolution smoke test.
//!
//! Builds the sibling `elf_fixture` cdylib, loads the resulting `.so` with
//! [`resetprop::seal::elf::parse_libc_elf`], and asserts that the T3
//! dispatcher [`resetprop::seal::elf::resolve_symbol`] locates
//! `__system_property_update` (one of the stubs the fixture exports). When
//! the fixture carries a `.gnu.hash` section, the test additionally asserts
//! that [`resetprop::seal::elf::gnu_lookup`] and
//! [`resetprop::seal::elf::linear_lookup`] return the same `st_value` — the
//! cross-check guarantees the two resolution paths agree.
//!
//! Architecture gate: the entire file is gated behind
//! `#[cfg(target_arch = "aarch64")]`. `parse_libc_elf` rejects anything
//! whose `e_machine != EM_AARCH64`, and `cargo build -p elf_fixture`
//! produces a host-target cdylib, so the test can only succeed on an
//! aarch64 host. On non-aarch64 dev hosts the file compiles to an empty
//! test binary, matching the pattern used by `tier_a_child_smoke.rs`.
//!
//! Runner invocation (the test is `#[ignore]`'d by default because it
//! shells out to `cargo build`):
//!   cargo test -p resetprop --test elf_fixture_smoke -- \
//!       --ignored --test-threads=1

#![cfg(target_arch = "aarch64")]

use std::fs::File;
use std::path::PathBuf;
use std::process::Command;

use resetprop::seal::elf::{gnu_lookup, linear_lookup, parse_libc_elf, resolve_symbol};

/// Resolve the cargo binary that invoked us, falling back to PATH lookup.
///
/// `CARGO` is set by cargo whenever it spawns a test binary, so reusing it
/// keeps nested builds on the same toolchain (important when developers
/// run under `rustup run <channel> cargo test`).
fn cargo_bin() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// Workspace root = `CARGO_MANIFEST_DIR` + `../..`.
///
/// `CARGO_MANIFEST_DIR` for this integration test resolves to
/// `crates/resetprop/`, so two `..` segments reach the workspace root.
fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p
}

const FIXTURE_SYMBOL: &str = "__system_property_update";

#[test]
#[ignore = "shells out to cargo build -p elf_fixture; run with --ignored --test-threads=1"]
fn fixture_symbol_resolves() {
    // Device-run path: when ELF_FIXTURE_PATH is set, skip the cargo-build
    // subprocess and use the pre-built cdylib the operator pushed alongside
    // the test binary. Build-host path: spawn cargo build as before.
    let so_path = match std::env::var("ELF_FIXTURE_PATH") {
        Ok(p) => PathBuf::from(p),
        Err(_) => {
            let status = Command::new(cargo_bin())
                .args(["build", "-p", "elf_fixture", "--release"])
                .status()
                .expect("spawn cargo build for elf_fixture");
            assert!(
                status.success(),
                "cargo build -p elf_fixture --release failed (status={status:?})"
            );
            workspace_root().join("target/release/libelf_fixture.so")
        }
    };
    assert!(so_path.exists(), "cdylib missing at {}", so_path.display());

    let file = File::open(&so_path).unwrap_or_else(|e| panic!("open {}: {e}", so_path.display()));
    let view = parse_libc_elf(&file).expect("parse_libc_elf on elf_fixture");

    let resolved = resolve_symbol(&view, FIXTURE_SYMBOL)
        .unwrap_or_else(|e| panic!("resolve_symbol({FIXTURE_SYMBOL}) failed: {e}"));
    assert!(
        resolved > 0,
        "resolve_symbol returned st_value=0 for {FIXTURE_SYMBOL}"
    );

    let linear_hit = linear_lookup(&view, FIXTURE_SYMBOL)
        .unwrap_or_else(|| panic!("linear_lookup missed {FIXTURE_SYMBOL}"));
    assert_eq!(
        linear_hit, resolved,
        "resolve_symbol must agree with linear_lookup for {FIXTURE_SYMBOL}"
    );

    // If the linker emitted `.gnu.hash` (default for modern rustc/lld on
    // Linux cdylibs), the fast path must agree with the linear fallback;
    // when absent, `gnu_lookup` returns `None` and `resolve_symbol` has
    // already fallen through to linear, which the assertion above covers.
    if let Some(gnu_hit) = gnu_lookup(&view, FIXTURE_SYMBOL) {
        assert_eq!(
            gnu_hit, linear_hit,
            "gnu_lookup and linear_lookup disagree on st_value for {FIXTURE_SYMBOL}"
        );
    }
}
