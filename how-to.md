# QSSM Developer How-To

This is the detailed command reference for working in this repository.

Use it as the "what do I actually run from the repo root?" document.

Related guide: [CONTRIBUTING.md](CONTRIBUTING.md)

## Scope

This file covers:

- exact package names in the current workspace
- how to run all tests
- how to run one crate's tests
- how to run one named test target
- how to run the dedicated cross-crate integration test package
- how to build and run the desktop app
- how to run the example binaries that actually exist today
- how to run common verification gates

Repository root for all commands unless noted otherwise:

```powershell
Set-Location C:\rust\qssm-rs
```

## Current workspace members

These are the workspace packages defined in the root `Cargo.toml` right now:

- `qssm-utils`
- `qssm-entropy`
- `qssm-gadget`
- `qssm-le`
- `qssm-ms`
- `qssm-proofs`
- `qssm-local-prover`
- `qssm-templates`
- `qssm-local-verifier`
- `qssm-api`
- `zk-examples`
- `qssm-integration`
- `qssm-desktop`

Important naming reminders:

- the examples package name is `zk-examples`, not `qssm-examples`
- the desktop frontend lives in `desktop/`
- the desktop Rust/Tauri backend lives in `desktop/src-tauri/`
- the dedicated cross-crate integration package is `qssm-integration`

## Prerequisites

Minimum practical requirements:

- Rust toolchain installed and on `PATH`
- `cargo` and `rustc` working
- Node.js and npm installed for the desktop app
- Python available if you want to run `scripts/verify_ct_asm.py`

Quick sanity checks:

```powershell
rustc --version
cargo --version
node --version
npm --version
python --version
```

## Build commands

### Build the full workspace

Debug build:

```powershell
cargo build --workspace
```

Release build:

```powershell
cargo build --release --workspace
```

### Build one crate

Examples:

```powershell
cargo build -p qssm-le
cargo build -p qssm-api
cargo build -p qssm-desktop
```

Release build for one crate:

```powershell
cargo build --release -p qssm-le
```

## Test commands

## Run every test in the workspace

This is the normal full test command:

```powershell
cargo test --workspace
```

This runs the test suites for all workspace members, including crate-local unit tests and any package test targets.

If you specifically want a release-mode full test run:

```powershell
cargo test --release --workspace
```

Use release mode only when you intentionally want the slower, heavier full pass.

## Run tests for one crate

General form:

```powershell
cargo test -p <package-name>
```

Examples:

```powershell
cargo test -p qssm-le
cargo test -p qssm-ms
cargo test -p qssm-api
cargo test -p qssm-local-prover
cargo test -p qssm-local-verifier
cargo test -p qssm-entropy
cargo test -p qssm-utils
cargo test -p qssm-gadget
cargo test -p qssm-templates
cargo test -p qssm-proofs
cargo test -p zk-examples
cargo test -p qssm-integration
```

## Run one specific test by name

General form:

```powershell
cargo test -p <package-name> <test-name-substring>
```

Examples:

```powershell
cargo test -p qssm-proofs ci_security_floor_112_bits
cargo test -p qssm-entropy to_seed_determinism
cargo test -p qssm-api wire_format
```

Use this when you know the test function name or a stable substring of it.

## Run one named integration test target

General form:

```powershell
cargo test -p <package-name> --test <target-name>
```

This is for explicit test target files, not individual `#[test]` functions.

### Dedicated cross-crate integration tests

The repository has a dedicated integration package at `integration/` with package name `qssm-integration`.

Run the entire integration package:

```powershell
cargo test -p qssm-integration
```

Run all its named integration test targets one by one:

```powershell
cargo test -p qssm-integration --test adversarial_replay
cargo test -p qssm-integration --test test_roundtrip
cargo test -p qssm-integration --test test_negative
cargo test -p qssm-integration --test test_serialization
cargo test -p qssm-integration --test test_entropy
cargo test -p qssm-integration --test test_template_resolution
```

If you want every cross-crate integration file to run, `cargo test -p qssm-integration` is the easiest command and should be your default.

## Run all integration-style test targets across the workspace

If you want Cargo's `--tests` pass across all workspace members:

```powershell
cargo test --workspace --tests
```

Use this when you want package test targets only and do not want a full "everything" pass.

For this repository, the dedicated cross-crate package `qssm-integration` is still the main integration suite to remember.

## qssm-proofs specific commands

`qssm-proofs` is the internal analysis crate.

Run all its tests:

```powershell
cargo test -p qssm-proofs
```

Run the explicit parameter sync test target:

```powershell
cargo test -p qssm-proofs --test parameter_sync
```

Run the CI hardness floor test directly:

```powershell
cargo test -p qssm-proofs ci_security_floor_112_bits
```

What this is checking:

- the effective security floor encoded in `qssm-proofs`
- whether the current parameter set stays above the enforced CI minimum

## Example binaries that actually exist today

The examples package is `zk-examples` under `truth-engine/examples`.

The currently defined binaries are:

- `simple_proof`
- `age_gate`

Run them like this:

```powershell
cargo run -p zk-examples --bin simple_proof
cargo run -p zk-examples --bin age_gate
```

Release mode:

```powershell
cargo run --release -p zk-examples --bin simple_proof
cargo run --release -p zk-examples --bin age_gate
```

## Desktop app: install, run, build

The desktop app frontend is in `desktop/` and the Tauri backend crate is `desktop/src-tauri/` with package name `qssm-desktop`.

### First-time setup

Install frontend dependencies:

```powershell
npm --prefix desktop install
```

You only need to repeat this after dependency changes or if `node_modules` is removed.

### Run the desktop app in dev mode

From repo root:

```powershell
npm --prefix desktop run tauri:dev
```

This starts the Vite frontend and the Tauri shell together.

Equivalent if you want to `cd` first:

```powershell
Set-Location .\desktop
npm install
npm run tauri:dev
```

### Build the desktop app

From repo root:

```powershell
npm --prefix desktop run tauri:build
```

Equivalent from inside `desktop/`:

```powershell
Set-Location .\desktop
npm run tauri:build
```

### Run only the web frontend without the Tauri shell

```powershell
npm --prefix desktop run dev
```

### Build only the frontend assets

```powershell
npm --prefix desktop run build
```

### Optional desktop utility script

Fetch the DBIP MaxMind-style database used by the desktop app:

```powershell
npm --prefix desktop run geo:fetch-dbip
```

## Compile / verification commands you will actually use

Check everything compiles without running tests:

```powershell
cargo check --workspace
```

Check one crate only:

```powershell
cargo check -p qssm-api
cargo check -p qssm-entropy
```

Format the workspace:

```powershell
cargo fmt --all
```

Format check without rewriting files:

```powershell
cargo fmt --all -- --check
```

Run Clippy across the workspace:

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

## Constant-time verification helper

The root `scripts/verify_ct_asm.py` script is still part of the security/tooling path.

Run it from repo root:

```powershell
python scripts/verify_ct_asm.py
```

This script is referenced by:

- `SECURITY.md`
- `.github/workflows/ct-assembly-gate.yml`
- the `qssm-le` freeze/security artifacts

## Common command patterns to remember

Run everything:

```powershell
cargo test --workspace
```

Run one crate:

```powershell
cargo test -p qssm-api
```

Run one named integration target:

```powershell
cargo test -p qssm-integration --test test_roundtrip
```

Run one named test function or filtered subset:

```powershell
cargo test -p qssm-entropy to_seed_determinism
```

Run desktop app:

```powershell
npm --prefix desktop install
npm --prefix desktop run tauri:dev
```

Build desktop app:

```powershell
npm --prefix desktop run tauri:build
```

## If a command from an old doc fails

Check these first:

- old docs may still say `crates/...`; current paths are `truth-engine/...` and `desktop/...`
- old docs may still say `qssm-examples`; current package name is `zk-examples`
- old docs may still mention `millionaires_duel`; that binary is not currently defined in `truth-engine/examples/Cargo.toml`
- the dedicated integration package is `qssm-integration`
- the desktop app is `desktop/`, not `crates/qssm-desktop`
