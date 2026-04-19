# qssm-cli

`qssm-cli` is the command-line wrapper around `qssm-core`.

It installs a binary named `qssm` with five commands matching the core lifecycle:

- `compile`
- `commit`
- `prove`
- `verify`
- `open`

## Build

```powershell
cargo build --release -p qssm-cli
```

On Windows, the executable is typically written to `target\release\qssm.exe`.

## Quick usage

```powershell
qssm compile age-gate-21
qssm commit "{\"claim\":{\"age_years\":25}}" 0707070707070707070707070707070707070707070707070707070707070707
qssm open "{\"claim\":{\"age_years\":25}}" 0707070707070707070707070707070707070707070707070707070707070707
```

## Full lifecycle

```powershell
$blueprint = qssm compile age-gate-21
$salt = "0707070707070707070707070707070707070707070707070707070707070707"
$claim = '{"claim":{"age_years":25}}'
$commitment = qssm commit $claim $salt
$proof = qssm prove $claim $salt $blueprint
qssm verify $proof $blueprint
qssm open $claim $salt
```

`verify` prints `true` on success and exits non-zero on failure.

Arguments that represent proof or blueprint bytes can be passed either as raw hex or as `@path` file references.
