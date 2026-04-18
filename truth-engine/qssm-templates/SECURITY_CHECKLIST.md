# qssm-templates Security Checklist

Pre-release review gate for any change to `qssm-templates`.

## Checklist

- [ ] `#[forbid(unsafe_code)]` — no unsafe blocks introduced.
- [ ] All public error enums carry `#[non_exhaustive]`.
- [ ] `from_json_slice` validates `qssm_template_version` and rejects empty
      predicates before returning.
- [ ] Predicate evaluator (`eval_predicate`) does not panic on any valid JSON
      input (returns `Err` instead).
- [ ] `serde` round-trip property holds: `from_json_slice(to_vec(t)) == t` for
      every built-in template.
- [ ] No new dependencies added without security review.
- [ ] `cargo clippy --all-features` clean.
- [ ] `cargo test -p qssm-templates --all-features` passes.
- [ ] Feature-gated modules (`script-helpers`) do not leak into the default
      compilation surface.
