//! Predicate template verification for inbound sovereign gossip (`jsonl_line` claim tree).

use std::borrow::Cow;

use qssm_le::{verify_lattice, Commitment, LatticeProof, PublicInstance, RqPoly, VerifyingKey, N};
use serde_json::Value;
use template_lib::{
    eval_all_predicates, parse_template_id_param, predicate_blocks_from_template_value,
    standard_library_script,
};

/// Claim field used when gossip omits `template_script` and the Lab names a standard library entry.
pub const VERIFIER_TEMPLATE_ID_FIELD: &str = "verifier_template_id";
pub const BLINDED_PARAMETER_HASH_FIELD: &str = "blinded_parameter_hash_hex";
pub const ZK_BUNDLE_FIELD: &str = "zk_lattice_bundle";

/// Run predicate checks on the JSONL claim: use inline **`template_script`** when present, otherwise
/// resolve **`standard_library_script`** from **`verifier_template_id`** on the claim.
pub fn verify_sovereign_jsonl_with_templates(
    jsonl_line: &str,
    template_script: Option<&Value>,
) -> Result<(), String> {
    let claim: Value = serde_json::from_str(jsonl_line)
        .map_err(|e| format!("sovereign jsonl: invalid JSON: {e}"))?;

    let script_ref: Cow<'_, Value> = match template_script {
        Some(v) => Cow::Borrowed(v),
        None => {
            let tid = claim
                .get(VERIFIER_TEMPLATE_ID_FIELD)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "missing gossip template_script and claim.verifier_template_id".to_string()
                })?;
            let doc = standard_library_script(tid).ok_or_else(|| {
                format!("unknown verifier_template_id (not in standard library): {tid:?}")
            })?;
            Cow::Owned(doc)
        }
    };

    let verifier_id = claim
        .get(VERIFIER_TEMPLATE_ID_FIELD)
        .and_then(Value::as_str)
        .unwrap_or("");
    let parsed = parse_template_id_param(verifier_id);
    if parsed.base_id.ends_with("_zk_v1") {
        return verify_lattice_zk_family(&claim, &parsed.base_id);
    }

    let blocks = predicate_blocks_from_template_value(script_ref.as_ref())?;
    eval_all_predicates(&claim, &blocks).map_err(|e| e.to_string())
}

fn decode_hex32(s: &str) -> Result<[u8; 32], String> {
    let raw = s
        .strip_prefix("0x")
        .ok_or_else(|| format!("hex must start with 0x: {s}"))?;
    let bytes = hex::decode(raw).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("hex32 length mismatch: {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn coeffs_to_poly(v: &Value, field: &str) -> Result<RqPoly, String> {
    let arr = v
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field} missing/invalid"))?;
    if arr.len() != N {
        return Err(format!("{field} len {} != {}", arr.len(), N));
    }
    let mut out = [0u32; N];
    for (i, x) in arr.iter().enumerate() {
        out[i] = x
            .as_u64()
            .ok_or_else(|| format!("{field}[{i}] invalid"))? as u32;
    }
    Ok(RqPoly(out))
}

fn verify_lattice_zk_family(claim: &Value, template_id: &str) -> Result<(), String> {
    let blinded_hex = claim
        .get(BLINDED_PARAMETER_HASH_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(|| "missing blinded_parameter_hash_hex".to_string())?;
    let blinded = decode_hex32(blinded_hex)?;
    // Commit hidden goalposts to public input while keeping raw parameters private.
    let public_message = u64::from_le_bytes(blinded[..8].try_into().unwrap()) & ((1u64 << 30) - 1);
    if template_id == "simple_math_zk_v1" {
        let ans = claim
            .get("claim")
            .and_then(|v| v.get("answer"))
            .and_then(Value::as_u64)
            .ok_or_else(|| "simple_math_zk_v1 requires claim.answer".to_string())?;
        if ans != public_message {
            return Err("simple_math_zk_v1: claim.answer mismatches blinded commitment".into());
        }
    }

    let bundle = claim
        .get(ZK_BUNDLE_FIELD)
        .ok_or_else(|| "missing zk_lattice_bundle".to_string())?;
    let crs_seed = decode_hex32(
        bundle
            .get("crs_seed_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "zk_lattice_bundle.crs_seed_hex missing".to_string())?,
    )?;
    let rollup = decode_hex32(
        bundle
            .get("rollup_context_digest_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "zk_lattice_bundle.rollup_context_digest_hex missing".to_string())?,
    )?;
    let challenge_seed = decode_hex32(
        bundle
            .get("challenge_seed_hex")
            .and_then(Value::as_str)
            .ok_or_else(|| "zk_lattice_bundle.challenge_seed_hex missing".to_string())?,
    )?;
    let commitment = Commitment(coeffs_to_poly(bundle, "commitment_coeffs_u32")?);
    let proof = LatticeProof {
        t: coeffs_to_poly(bundle, "proof_t_coeffs_u32")?,
        z: coeffs_to_poly(bundle, "proof_z_coeffs_u32")?,
        challenge_seed,
    };
    let vk = VerifyingKey::from_seed(crs_seed);
    let public = PublicInstance::from_u64_nibbles(public_message);
    let ok = verify_lattice(&vk, &public, &commitment, &proof, &rollup).map_err(|e| e.to_string())?;
    if ok {
        Ok(())
    } else {
        Err("lattice verification failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_non_zk_standard_id_rejected() {
        let claim = json!({
            "verifier_template_id": "simple_math_v1",
            "claim": { "answer": 42 }
        });
        assert!(verify_sovereign_jsonl_with_templates(&claim.to_string(), None).is_err());
    }

    #[test]
    fn verifies_with_inline_template_script() {
        let claim = json!({ "n": 3 });
        let script = json!({
            "predicates": [
                { "kind": "range", "field": "n", "min": 0, "max": 5 }
            ]
        });
        verify_sovereign_jsonl_with_templates(&claim.to_string(), Some(&script)).unwrap();
    }

    #[test]
    fn simple_math_zk_rejects_wrong_commitment_bound_answer() {
        use qssm_le::{prove_arithmetic, PublicInstance, Witness};
        let rollup = [7u8; 32];
        let vk = VerifyingKey::from_seed([9u8; 32]);
        let witness = Witness::new([0i32; N]);
        let right_answer = 100u64;
        let blinded = {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&right_answer.to_le_bytes());
            b
        };
        let msg = u64::from_le_bytes(blinded[..8].try_into().unwrap()) & ((1u64 << 30) - 1);
        let public = PublicInstance::from_u64_nibbles(msg);
        let (c, p) = prove_arithmetic(&vk, &public, &witness, &rollup, [0xBB; 32]).unwrap();
        let claim = serde_json::json!({
            "verifier_template_id": "simple_math_zk_v1",
            "claim": { "answer": 42 },
            "blinded_parameter_hash_hex": format!("0x{}", hex::encode(blinded)),
            "zk_lattice_bundle": {
                "crs_seed_hex": format!("0x{}", hex::encode(vk.crs_seed)),
                "rollup_context_digest_hex": format!("0x{}", hex::encode(rollup)),
                "challenge_seed_hex": format!("0x{}", hex::encode(p.challenge_seed)),
                "commitment_coeffs_u32": c.0.0.to_vec(),
                "proof_t_coeffs_u32": p.t.0.to_vec(),
                "proof_z_coeffs_u32": p.z.0.to_vec()
            }
        });
        assert!(verify_sovereign_jsonl_with_templates(&claim.to_string(), None).is_err());
    }

    #[test]
    fn simple_math_death_test_tampered_jsonl_answer_rejected() {
        use qssm_le::{prove_arithmetic, PublicInstance, Witness};
        let rollup = [8u8; 32];
        let vk = VerifyingKey::from_seed([0x55; 32]);
        let witness = Witness::new([0i32; N]);
        let committed_answer = 42u64;
        let blinded = {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&committed_answer.to_le_bytes());
            b
        };
        let public = PublicInstance::from_u64_nibbles(committed_answer);
        let (c, p) = prove_arithmetic(&vk, &public, &witness, &rollup, [0xBB; 32]).unwrap();
        let mut claim = serde_json::json!({
            "verifier_template_id": "simple_math_zk_v1",
            "claim": { "answer": 42 },
            "blinded_parameter_hash_hex": format!("0x{}", hex::encode(blinded)),
            "zk_lattice_bundle": {
                "crs_seed_hex": format!("0x{}", hex::encode(vk.crs_seed)),
                "rollup_context_digest_hex": format!("0x{}", hex::encode(rollup)),
                "challenge_seed_hex": format!("0x{}", hex::encode(p.challenge_seed)),
                "commitment_coeffs_u32": c.0.0.to_vec(),
                "proof_t_coeffs_u32": p.t.0.to_vec(),
                "proof_z_coeffs_u32": p.z.0.to_vec()
            }
        });
        assert!(verify_sovereign_jsonl_with_templates(&claim.to_string(), None).is_ok());
        claim["claim"]["answer"] = serde_json::json!(43);
        assert!(verify_sovereign_jsonl_with_templates(&claim.to_string(), None).is_err());
    }
}
