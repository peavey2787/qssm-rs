//! API-shape enforcement tests for qssm-api.
//!
//! These tests exist to prevent accidental public surface expansion.
//! If any test here fails, someone added a public item that violates
//! the 5-function byte-array-only contract.

/// The façade source file. Read at test time so the assertion stays
/// in sync with the actual code — no manual list to maintain.
const LIB_SOURCE: &str = include_str!("../src/lib.rs");

// ── 1. Exactly 5 public functions ────────────────────────────────────

/// Parses lib.rs for every `pub fn` outside `#[cfg(test)]` blocks and
/// asserts the exact set matches the frozen contract.
#[test]
fn exactly_five_public_functions() {
    let allowed: std::collections::BTreeSet<String> =
        ["compile", "commit", "prove", "verify", "open"]
            .iter()
            .map(|s| s.to_string())
            .collect();

    let public_fns = public_fn_names(LIB_SOURCE);

    assert_eq!(
        public_fns, allowed,
        "\nPublic function set does not match the frozen contract.\
         \n  Expected: {allowed:?}\
         \n  Found:    {public_fns:?}\
         \n\nIf you added a function, it must NOT be `pub`.\
         \nIf you renamed one, update the frozen contract in FREEZE.md first.",
    );
}

// ── 2. Zero public types / constants / re-exports ────────────────────

/// Scans lib.rs for any `pub struct`, `pub enum`, `pub trait`,
/// `pub const`, `pub static`, `pub type`, `pub use`, or `pub mod`
/// outside `#[cfg(test)]` blocks. All of these are forbidden.
#[test]
fn zero_public_types_or_reexports() {
    let production = strip_cfg_test(LIB_SOURCE);

    let forbidden_prefixes = [
        "pub struct ",
        "pub enum ",
        "pub trait ",
        "pub const ",
        "pub static ",
        "pub type ",
        "pub use ",
        "pub mod ",
    ];

    let mut violations = Vec::new();
    for (i, line) in production.lines().enumerate() {
        let trimmed = line.trim();
        // Skip comments and doc-comments.
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("#") {
            continue;
        }
        for prefix in &forbidden_prefixes {
            if trimmed.starts_with(prefix) {
                violations.push(format!("  line {}: {trimmed}", i + 1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "\nForbidden public items found in lib.rs (production code):\n{}\n\
         \nThe façade must expose exactly 5 `pub fn` and nothing else.\
         \nIf this is intentional, update FREEZE.md and SECURITY_CHECKLIST.md first.",
        violations.join("\n"),
    );
}

// ── 3. Byte-array round-trip: compile → prove → verify ───────────────

/// Exercises the full public API using only Vec<u8> / &[u8] / bool / String.
/// No engine types appear anywhere in this test.
#[test]
fn byte_array_round_trip() {
    // compile returns Vec<u8>
    let blueprint: Vec<u8> = qssm_api::compile("age-gate-21")
        .expect("compile should succeed for age-gate-21");

    // prove returns Vec<u8>
    let claim = br#"{"claim":{"age_years":30}}"#;
    let salt = [99u8; 32];
    let proof: Vec<u8> = qssm_api::prove(claim, &salt, &blueprint)
        .expect("prove should succeed for valid claim");

    // verify accepts &[u8] and returns bool
    let ok: bool = qssm_api::verify(&proof, &blueprint);
    assert!(ok, "valid proof must verify");

    // commit / open return Vec<u8>, compared with ==
    let secret = b"some-secret";
    let commitment: Vec<u8> = qssm_api::commit(secret, &salt);
    let revealed: Vec<u8> = qssm_api::open(secret, &salt);
    assert_eq!(commitment, revealed, "commit and open must match");

    // wrong secret must differ
    let wrong: Vec<u8> = qssm_api::open(b"wrong-secret", &salt);
    assert_ne!(commitment, wrong, "different secret must produce different output");
}

// ── 4. Error paths return Result, never panic ────────────────────────

#[test]
fn compile_bad_template_returns_err() {
    let result = qssm_api::compile("no-such-template-42");
    assert!(result.is_err());
}

#[test]
fn prove_bad_json_returns_err() {
    let blueprint = qssm_api::compile("age-gate-21").unwrap();
    let result = qssm_api::prove(b"not json!", &[0u8; 32], &blueprint);
    assert!(result.is_err());
}

#[test]
fn prove_bad_blueprint_returns_err() {
    let result = qssm_api::prove(br#"{"claim":{}}"#, &[0u8; 32], b"garbage");
    assert!(result.is_err());
}

#[test]
fn verify_bad_inputs_returns_false() {
    // Garbage proof + garbage blueprint → false, not panic.
    assert!(!qssm_api::verify(b"bad-proof", b"bad-blueprint"));
}

// ── 5. Function signatures are exactly as frozen ─────────────────────

/// Compile-time assertions that the 5 functions have exactly the
/// expected signatures. If any signature changes, this won't compile.
#[test]
fn signatures_match_frozen_contract() {
    let _: fn(&str) -> Result<Vec<u8>, String> = qssm_api::compile;
    let _: fn(&[u8], &[u8; 32]) -> Vec<u8> = qssm_api::commit;
    let _: fn(&[u8], &[u8; 32], &[u8]) -> Result<Vec<u8>, String> = qssm_api::prove;
    let _: fn(&[u8], &[u8]) -> bool = qssm_api::verify;
    let _: fn(&[u8], &[u8; 32]) -> Vec<u8> = qssm_api::open;
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Extract all `pub fn <name>` identifiers from production code
/// (skipping `#[cfg(test)]` blocks).
fn public_fn_names(source: &str) -> std::collections::BTreeSet<String> {
    let production = strip_cfg_test(source);
    let mut names = std::collections::BTreeSet::new();
    for line in production.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub fn ") {
            if let Some(name) = rest.split('(').next() {
                names.insert(name.trim().to_string());
            }
        }
    }
    names
}

/// Strip everything from the first `#[cfg(test)]` to the end of source,
/// so we only inspect production code.
fn strip_cfg_test(source: &str) -> String {
    if let Some(pos) = source.find("#[cfg(test)]") {
        source[..pos].to_string()
    } else {
        source.to_string()
    }
}
