# resetprop-rs

Userspace property-seal engine for Android — the Tier A/B `seal/` subsystem
(`crates/resetprop`) and the `resetprop-cli` front end. Rust, std-only userspace,
**single runtime dependency by law** (`libc`; `tempfile` is dev-only). Adding a
crate is a deliberate, justified exception, never a default.

## Read-path — open in this order, stop when you have enough

```
1. .context/AGENT-START.md   live orders: branch, last commit, active unit, next
2. bucket/<slug>/            the work. Active: bucket/resetprop-rs-injectrc-ports/
                             → read progress.yml, claim a `ready` task, then read
                               THAT one task file + the refs it licenses. Nothing else.
3. planning/SOURCES.md       consumed-source provenance, reference-only
4. README.md                 human/GitHub project overview
```

Nothing else is a "read first". A `ready` task plus the pointers it cites is the
whole pre-work read; wanting more context means the task was cut wrong — report it.

## Standing doctrine

- **One tracker per bucket:** `bucket/<slug>/progress.yml`, flags only. History is
  git; trackers never narrate.
- **The `seal/` engine patches PID 1 (init).** Correctness and safety on that
  target outrank features. Tier A = `MAP_FIXED` arena remap (atomic); Tier B =
  trampoline text patch (the hazardous path).
- **Single-dep minimalism** (`crates/resetprop/Cargo.toml`): a new crate needs a
  written justification in the task that adds it.
- **Commits:** Conventional Commits, imperative, subject ≤50. This repo's commit
  hook **rejects AI-attribution trailers** — no `Co-Authored-By` AI lines.
- **Storage:** build output (`target/`, `out/`) and agent scratch (`.analysis/`,
  `.omc/`, `vectors.db*`) are gitignored; never commit them.

This file is the standing entry. It points at the live orders; it does not
duplicate them.
