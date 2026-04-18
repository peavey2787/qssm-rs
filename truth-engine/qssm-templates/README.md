# qssm-templates

Canonical template gallery and predicate evaluation crate for QSSM verifier
policy.

This crate is part of the frozen institutional surface. Adding a new built-in
template is allowed, but contributors need to do it in a way that preserves the
stable carrier types and the documented review contract.

## What Lives Here

- `QssmTemplate`: serialized template carrier with private fields and read-only
  accessors
- `TemplateAnchorKind`: anchor categories allowed by a template
- `PredicateBlock` and `CmpOp`: predicate DSL used for public claim checks
- `standard_templates()` and `resolve()`: built-in template registry
- Optional `script-helpers` exports for CLI/desktop integration

Core implementation files:

- [src/template.rs](src/template.rs)
- [src/predicate.rs](src/predicate.rs)
- [src/lib.rs](src/lib.rs)
- [src/predicate_templates.rs](src/predicate_templates.rs) behind the
  `script-helpers` feature

## How To Add A Built-In Template

Use this workflow for a new template that should ship in the SDK.

1. Add a constructor in [src/template.rs](src/template.rs).

Follow the `QssmTemplate::proof_of_age()` pattern. Set:

- `qssm_template_version` to `QSSM_TEMPLATE_VERSION`
- a stable `id`
- human-readable `title`
- optional `description`
- allowed `TemplateAnchorKind` values
- a non-empty `Vec<PredicateBlock>`

Keep field writes inside the impl. External code should continue to use
constructors, accessors, and builder-style methods instead of struct literals.

2. Define the predicate set in [src/predicate.rs](src/predicate.rs) if it is
shared or reused.

If the new built-in has a reusable predicate bundle, add an internal helper like
`proof_of_age_predicates()`. If the logic is only used once, keeping it inline
inside the constructor is acceptable.

3. Register the template in [src/lib.rs](src/lib.rs).

Update both:

- `standard_templates()` so the template appears in the built-in gallery
- `resolve(id)` so callers can look it up by stable identifier

Those two functions must stay in sync.

4. Add tests.

At minimum, add or update tests for:

- `resolve("new-id")` returns the expected template
- a valid claim passes `verify_public_claim()`
- an invalid claim fails
- serde round-trip still works if the constructor is intended to be canonical

5. Update review docs when the public built-in set changes.

Check whether the new template changes any contributor-facing expectations in:

- [FREEZE.md](FREEZE.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)

Adding a template does not normally require changing the frozen carrier types,
but it may require documenting new review assumptions.

## Predicate Authoring Notes

Current predicate variants are in [src/predicate.rs](src/predicate.rs):

- `Compare { field, op, rhs }`
- `Range { field, min, max }`
- `InSet { field, values }`
- `AtLeast { field, min }`

Use dotted JSON paths such as `claim.age_years`. Predicate evaluation is
fail-closed: missing fields or invalid types return `PredicateError`.

## Script Helper Templates

If the change is only for desktop or CLI helper JSON, update
[src/predicate_templates.rs](src/predicate_templates.rs) instead of the frozen
built-in registry. That module is feature-gated behind `script-helpers` and is
explicitly not part of the institutional API surface.

## Validation

Run:

```sh
cargo test -p qssm-templates --all-features
```

If you changed any public carrier or enum shape, also review:

- [FREEZE.md](FREEZE.md)
- [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)

Do not expose `QssmTemplate` fields publicly again. Future evolution is meant to
flow through constructors, accessors, builder methods, and `#[non_exhaustive]`
types.