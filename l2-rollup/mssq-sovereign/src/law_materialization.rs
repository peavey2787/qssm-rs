//! Parametric-law expansion, blinded parameter commitment, and local salt persistence.

use std::fs;
use std::path::Path;

use qssm_utils::hashing::hash_domain;
use template_lib::{
    parametric_age_gate_vk, parametric_millionaires_duel_vk, parse_template_id_param,
};

use crate::{hex_lower_prefixed, StepEnvelope};

/// Errors specific to sovereign-law materialization.
#[derive(Debug)]
pub(crate) enum LawMaterializationError {
    SovereignLaw(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl From<std::io::Error> for LawMaterializationError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for LawMaterializationError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Materialize parametric law template into immutable form (deterministic, idempotent).
///
/// If `sovereign_law` is `None` or has no parametric `:param` suffix, returns step unchanged.
/// Otherwise: parses template_id, derives salt, blinded parameter hash, and fills template_script.
pub(crate) fn materialize_step(
    step: &StepEnvelope,
    binding_context: [u8; 32],
    secrets_path: &Path,
) -> Result<StepEnvelope, LawMaterializationError> {
    let mut out = step.clone();
    let Some(law) = out.wrapper_v1.sovereign_law.as_mut() else {
        return Ok(out);
    };
    let parsed = parse_template_id_param(&law.template_id);
    let Some(param) = parsed.param else {
        return Ok(out);
    };
    let salt = hash_domain(
        "QSSM-WRAP-SALT-v1",
        &[
            out.wrapper_v1.step_index.to_le_bytes().as_slice(),
            binding_context.as_slice(),
            law.template_id.as_bytes(),
        ],
    );
    let blinded = hash_domain("QSSM-WRAP-LAW-COMMIT-v1", &[salt.as_slice(), param.as_bytes()]);
    persist_salt(secrets_path, out.wrapper_v1.step_index, salt)?;
    law.template_id = parsed.base_id.clone();
    law.blinded_parameter_hash_hex = Some(hex_lower_prefixed(&blinded));
    if law.template_script.is_none() {
        law.template_script = Some(match parsed.base_id.as_str() {
            "age_gate_zk_v1" => parametric_age_gate_vk(blinded),
            "millionaires_duel_zk_v1" => parametric_millionaires_duel_vk(blinded),
            "simple_math_zk_v1" => serde_json::json!({
                "template_id": "simple_math_zk_v1",
                "constraints": [
                    {
                        "kind": "zk_field_comparison",
                        "lhs_field": "claim.answer",
                        "public_input_commitment_hex": hex_lower_prefixed(&blinded)
                    }
                ]
            }),
            _ => serde_json::json!({ "template_id": parsed.base_id }),
        });
    }
    Ok(out)
}

/// Append salt to secrets.json under `sovereign_law_salts.<step_index>`.
fn persist_salt(
    secrets_path: &Path,
    step_index: u64,
    salt: [u8; 32],
) -> Result<(), LawMaterializationError> {
    let mut root: serde_json::Value = if secrets_path.exists() {
        let raw = fs::read_to_string(secrets_path)?;
        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };
    let obj = root.as_object_mut().ok_or_else(|| {
        LawMaterializationError::SovereignLaw("secrets.json root must be object".to_string())
    })?;
    let salts = obj
        .entry("sovereign_law_salts")
        .or_insert_with(|| serde_json::json!({}));
    let salts_obj = salts.as_object_mut().ok_or_else(|| {
        LawMaterializationError::SovereignLaw(
            "secrets.json.sovereign_law_salts must be object".to_string(),
        )
    })?;
    salts_obj.insert(
        step_index.to_string(),
        serde_json::Value::String(hex_lower_prefixed(&salt)),
    );
    fs::write(
        secrets_path,
        serde_json::to_string_pretty(&root)?,
    )?;
    Ok(())
}
