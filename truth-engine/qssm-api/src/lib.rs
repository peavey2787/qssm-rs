#![forbid(unsafe_code)]
//! # QSSM Truth Engine — Layer 6 (Façade)
//!
//! The single entry point for the entire truth engine.
//! Developers only import this crate. Everything else is internal.
//!
//! ## Five functions, one byte array — that's it.
//!
//! | Function    | Role |
//! |-------------|------|
//! | [`compile`] | Resolves a template ID into an opaque byte-array blueprint. |
//! | [`commit`]  | Locks a secret without revealing it — returns 32 bytes. |
//! | [`prove`]   | Creates a ZK proof (byte array) that a secret satisfies the blueprint's rules. |
//! | [`verify`]  | Checks a proof byte array against a blueprint — returns `true` / `false`. |
//! | [`open`]    | Returns the commitment bytes for a `(secret, salt)` pair; compare with [`commit`] output. |
//!
//! ## Quick start
//!
//! ```no_run
//! use qssm_api::{compile, commit, prove, verify, open};
//!
//! let blueprint = compile("age-gate-21").unwrap();
//! let commitment = commit(b"my-secret", &[1u8; 32]);
//! let claim = br#"{"claim":{"age_years":25}}"#;
//! let proof = prove(claim, &[1u8; 32], &blueprint).unwrap();
//! assert!(verify(&proof, &blueprint));
//! assert_eq!(open(b"my-secret", &[1u8; 32]), commitment);
//! ```

mod commit_impl;

use qssm_local_prover::ProofContext;
use qssm_utils::hashing::blake3_hash;
use serde::{Deserialize, Serialize};

// ── Internal wire-format structs (never public) ──────────────────────

#[derive(Serialize, Deserialize)]
struct WireBlueprint {
    seed_hex: String,
    template_id: String,
}

#[derive(Serialize, Deserialize)]
struct WireZkProof {
    bundle: qssm_local_prover::ProofBundle,
    claim: serde_json::Value,
    binding_ctx_hex: String,
}

// ── The 5 façade functions ───────────────────────────────────────────

/// **The Blueprint.** Resolves a template ID and harvests entropy to produce
/// an opaque byte-array blueprint.
///
/// # Errors
///
/// Returns `Err` if `template_id` is not a known built-in template, or if
/// hardware entropy is unavailable.
pub fn compile(template_id: &str) -> Result<Vec<u8>, String> {
    // Validate the template exists (fail fast).
    let _template = qssm_templates::resolve(template_id)
        .ok_or_else(|| format!("unknown template: {template_id}"))?;
    let seed = qssm_entropy::harvest(&qssm_entropy::HarvestConfig::default())
        .map_err(|e| format!("entropy unavailable: {e}"))?
        .to_seed();
    let wire = WireBlueprint {
        seed_hex: hex::encode(seed),
        template_id: template_id.to_owned(),
    };
    serde_json::to_vec(&wire).map_err(|e| format!("serialization failed: {e}"))
}

/// **The Envelope.** Locks a secret without revealing it.
///
/// Returns a 32-byte commitment. Compare with [`open`] output using `==`.
#[must_use]
pub fn commit(secret: &[u8], salt: &[u8; 32]) -> Vec<u8> {
    commit_impl::commit_hash(secret, salt).to_vec()
}

/// **The Proof Generator.** Creates a ZK proof (byte array) that the secret
/// satisfies the blueprint's rules.
///
/// - `secret`: the claim data as JSON bytes (e.g. `b'{"claim":{"age_years":25}}'`).
/// - `salt`: 32-byte caller-chosen salt (used to derive binding context).
/// - `blueprint`: the opaque byte array from [`compile`].
///
/// # Errors
///
/// Returns `Err` if `secret` is not valid JSON, if the claim fails the
/// template's predicates, if hardware entropy is unavailable, or if the
/// internal prove pipeline fails.
pub fn prove(secret: &[u8], salt: &[u8; 32], blueprint: &[u8]) -> Result<Vec<u8>, String> {
    let wire_bp: WireBlueprint =
        serde_json::from_slice(blueprint).map_err(|e| format!("invalid blueprint: {e}"))?;
    let seed = decode_hex_32(&wire_bp.seed_hex, "blueprint seed")?;
    let template = qssm_templates::resolve(&wire_bp.template_id)
        .ok_or_else(|| format!("unknown template: {}", wire_bp.template_id))?;
    let ctx = ProofContext::new(seed);

    let claim: serde_json::Value =
        serde_json::from_slice(secret).map_err(|e| format!("invalid JSON claim: {e}"))?;
    let binding_ctx = blake3_hash(salt);
    let entropy_seed = qssm_entropy::harvest(&qssm_entropy::HarvestConfig::default())
        .map_err(|e| format!("entropy unavailable: {e}"))?
        .to_seed();
    let (value, target) = extract_value_target(&claim, &template);

    let proof = qssm_local_prover::prove(
        &ctx,
        &template,
        &claim,
        value,
        target,
        binding_ctx,
        entropy_seed,
    )
    .map_err(|e| format!("prove failed: {e}"))?;

    let wire = WireZkProof {
        bundle: qssm_local_prover::ProofBundle::from_proof(&proof),
        claim,
        binding_ctx_hex: hex::encode(binding_ctx),
    };
    serde_json::to_vec(&wire).map_err(|e| format!("serialization failed: {e}"))
}

/// **The Truth Checker.** Validates a proof byte array against a blueprint.
///
/// Returns `true` if the proof is valid, `false` otherwise. All internal
/// errors (tampered proofs, wrong bindings, deserialization failures, etc.)
/// collapse to `false`.
#[must_use]
pub fn verify(proof: &[u8], blueprint: &[u8]) -> bool {
    verify_inner(proof, blueprint).unwrap_or(false)
}

/// **The Simple Reveal.** Reconstructs the commitment from `(secret, salt)`.
///
/// Returns the same 32 bytes that [`commit`] would produce for the same
/// inputs. Compare with `==`.
#[must_use]
pub fn open(secret: &[u8], salt: &[u8; 32]) -> Vec<u8> {
    commit_impl::commit_hash(secret, salt).to_vec()
}

// ── Internal helpers ─────────────────────────────────────────────────

fn verify_inner(proof: &[u8], blueprint: &[u8]) -> Result<bool, String> {
    let wire_bp: WireBlueprint =
        serde_json::from_slice(blueprint).map_err(|e| format!("invalid blueprint: {e}"))?;
    let seed = decode_hex_32(&wire_bp.seed_hex, "blueprint seed")?;
    let template = qssm_templates::resolve(&wire_bp.template_id)
        .ok_or_else(|| format!("unknown template: {}", wire_bp.template_id))?;
    let ctx = ProofContext::new(seed);

    let wire_proof: WireZkProof =
        serde_json::from_slice(proof).map_err(|e| format!("invalid proof: {e}"))?;
    let binding_ctx = decode_hex_32(&wire_proof.binding_ctx_hex, "binding_ctx")?;
    let inner_proof = wire_proof
        .bundle
        .to_proof()
        .map_err(|e| format!("invalid proof bundle: {e}"))?;

    qssm_local_verifier::verify(
        &ctx,
        &template,
        &wire_proof.claim,
        &inner_proof,
        binding_ctx,
    )
    .map_err(|e| format!("verification failed: {e}"))
}

fn decode_hex_32(hex_str: &str, field: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex for {field}: {e}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{field}: expected 32 bytes, got {}", bytes.len()))
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Extract (value, target) from claim + template predicates.
fn extract_value_target(
    claim: &serde_json::Value,
    template: &qssm_templates::QssmTemplate,
) -> (u64, u64) {
    use qssm_templates::{json_at_path, PredicateBlock};

    for pred in template.predicates() {
        match pred {
            PredicateBlock::Range { field, min, .. } => {
                if let Some(val) = json_at_path(claim, field).and_then(|v| v.as_u64()) {
                    return (val, *min as u64);
                }
            }
            PredicateBlock::AtLeast { field, min } => {
                if let Some(val) = json_at_path(claim, field).and_then(|v| v.as_u64()) {
                    return (val, *min as u64);
                }
            }
            PredicateBlock::Compare {
                field,
                op: qssm_templates::CmpOp::Gt,
                rhs,
            } => {
                if let (Some(lhs), Some(rhs_val)) = (
                    json_at_path(claim, field).and_then(|v| v.as_u64()),
                    rhs.as_u64(),
                ) {
                    return (lhs, rhs_val);
                }
            }
            _ => {}
        }
    }
    (1, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_round_trip() {
        let secret = b"my-secret-value";
        let salt = [42u8; 32];
        let c = commit(secret, &salt);
        let d = open(secret, &salt);
        assert_eq!(c, d);
    }

    #[test]
    fn open_rejects_wrong_secret() {
        let salt = [42u8; 32];
        let c = commit(b"correct", &salt);
        let d = open(b"wrong", &salt);
        assert_ne!(c, d);
    }

    #[test]
    fn extract_value_target_age_gate() {
        let template = qssm_templates::QssmTemplate::proof_of_age("age-gate-21");
        let claim = serde_json::json!({ "claim": { "age_years": 25 } });
        let (v, t) = extract_value_target(&claim, &template);
        assert_eq!(v, 25);
        assert_eq!(t, 21);
    }

    #[test]
    fn compile_rejects_unknown_template() {
        let result = compile("nonexistent-template-xyz");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown template"));
    }
}
