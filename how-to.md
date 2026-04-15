# QSSM Developer How-To

This guide is a command-first reference for common developer tasks in this workspace.

## Prerequisites

- Rust toolchain installed (`cargo`, `rustc`)
- Node.js + npm installed (required for `qssm-desktop`)
- Run all commands from repo root unless otherwise noted: `C:/rust/qssm-rs`

## Run All Tests (Workspace)

Run every test in every workspace crate in release mode:

```bash
cargo test --release --workspace
```

Run tests for one crate only:

```bash
cargo test -p mssq-batcher
```

Run a specific integration test target:

```bash
cargo test -p qssm-examples --test millionaires_duel
```

## Build All Crates or One Crate

Build the entire workspace:

```bash
cargo build --workspace
```

Release build for entire workspace:

```bash
cargo build --release --workspace
```

Build only one crate:

```bash
cargo build -p qssm-le
```

Release build for one crate:

```bash
cargo build --release -p qssm-le
```

## Run qssm-desktop (Dev and Release)

`qssm-desktop` is a Tauri app with frontend assets in `crates/qssm-desktop`.

1) Install frontend dependencies (first time, or after dependency changes):

```bash
cd crates/qssm-desktop
npm install
```

2) Run desktop app in dev mode (hot reload):

```bash
npx --prefix crates/qssm-desktop tauri dev
```

3) Build desktop app in release mode:

```bash
npx --prefix crates/qssm-desktop tauri build
```

Optional: run only the web frontend dev server (without Tauri shell):

```bash
npm --prefix crates/qssm-desktop run dev
```

Equivalent commands if you prefer to `cd` first:

```bash
cd crates/qssm-desktop
npx tauri dev
npx tauri build
```

## Run Millionaires Duel

The Millionaires Duel binary lives in `qssm-examples`.

Run in debug mode:

```bash
cargo run -p qssm-examples --bin millionaires_duel
```

Run in release mode:

```bash
cargo run --release -p qssm-examples --bin millionaires_duel
```

Run its integration test suite:

```bash
cargo test -p qssm-examples --test millionaires_duel
```

## Useful Verification Commands

Check all crates compile without running tests:

```bash
cargo check --workspace
```

Format check:

```bash
cargo fmt --all -- --check
```

Lint check (Clippy):

```bash
cargo clippy --workspace --all-targets -- -D warnings
```
