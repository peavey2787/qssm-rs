# qssm-templates Institutional Freeze Contract

**Version:** 1.0.0
**Status:** Frozen

## Scope

This crate provides the canonical template gallery, predicate evaluator, and
resolver for QSSM verifier policy. It is part of the institutional API surface
shipped to external consumers.

## Frozen Public API

| Symbol | Kind |
|---|---|
| `QssmTemplate` | Struct (`#[non_exhaustive]`, private fields, read-only accessors) |
| `TemplateAnchorKind` | Enum (`#[non_exhaustive]`) |
| `TemplateError` | Enum (`#[non_exhaustive]`) |
| `PredicateBlock` | Enum (`#[non_exhaustive]`) |
| `PredicateError` | Enum (`#[non_exhaustive]`) |
| `CmpOp` | Enum (`#[non_exhaustive]`) |
| `QSSM_TEMPLATE_VERSION` | Const (`u32`) |
| `resolve(id)` | Function (built-in template lookup) |
| `standard_templates()` | Function (list all built-ins) |
| `eval_all_predicates()` | Function |
| `eval_predicate()` | Function |
| `json_at_path()` | Function |

## Feature-Gated Exports (not frozen)

The `script-helpers` feature gates convenience functions for CLI tooling and
desktop integration (`age_gate_script`, `millionaires_duel_script`, etc.).
These are **not** part of the institutional API surface.

## Change Policy

- No breaking changes to frozen symbols without a major version bump.
- New templates may be added to `resolve()` and `standard_templates()` in minor
  releases.
- New `#[non_exhaustive]` enum variants may be added in minor releases.
- All additions require review against `SECURITY_CHECKLIST.md`.
