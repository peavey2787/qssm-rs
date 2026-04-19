//! Thin Tauri wrappers around qssm-api and qssm-templates.

use qssm_api::{commit, compile, open, prove, verify};
use qssm_templates::QssmTemplate;

fn decode_hex_bytes(input: &str, label: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim().trim_start_matches("0x");
    hex::decode(trimmed).map_err(|error| format!("invalid hex for {label}: {error}"))
}

fn decode_hex_32(input: &str, label: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex_bytes(input, label)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{label}: expected 32 bytes, got {}", bytes.len()))
}

#[tauri::command]
pub fn compile_blueprint(template_source: String) -> Result<String, String> {
    let blueprint = compile(template_source.trim())?;
    Ok(hex::encode(blueprint))
}

#[tauri::command]
pub fn commit_secret(secret_utf8: String, salt_hex: String) -> Result<String, String> {
    let salt = decode_hex_32(&salt_hex, "salt")?;
    Ok(hex::encode(commit(secret_utf8.as_bytes(), &salt)))
}

#[tauri::command]
pub fn prove_claim(
    claim_utf8: String,
    salt_hex: String,
    blueprint_hex: String,
) -> Result<String, String> {
    let salt = decode_hex_32(&salt_hex, "salt")?;
    let blueprint = decode_hex_bytes(&blueprint_hex, "blueprint")?;
    let proof = prove(claim_utf8.as_bytes(), &salt, &blueprint)?;
    Ok(hex::encode(proof))
}

#[tauri::command]
pub fn verify_proof(proof_hex: String, blueprint_hex: String) -> Result<bool, String> {
    let proof = decode_hex_bytes(&proof_hex, "proof")?;
    let blueprint = decode_hex_bytes(&blueprint_hex, "blueprint")?;
    Ok(verify(&proof, &blueprint))
}

#[tauri::command]
pub fn open_secret(secret_utf8: String, salt_hex: String) -> Result<String, String> {
    let salt = decode_hex_32(&salt_hex, "salt")?;
    Ok(hex::encode(open(secret_utf8.as_bytes(), &salt)))
}

#[tauri::command]
pub fn proof_of_age_template_json() -> Result<String, String> {
    let template = QssmTemplate::proof_of_age("age-gate-21");
    serde_json::to_string_pretty(&template).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn verify_claim_with_template(
    template_json: String,
    claim_json: String,
) -> Result<String, String> {
    let template = QssmTemplate::from_json_slice(template_json.as_bytes())
        .map_err(|error| format!("invalid .qssm template: {error}"))?;
    let claim: serde_json::Value = serde_json::from_str(&claim_json)
        .map_err(|error| format!("invalid claim JSON: {error}"))?;

    let result = match template.verify_public_claim(&claim) {
        Ok(()) => serde_json::json!({
            "ok": true,
            "detail": "Pass - verified"
        }),
        Err(error) => serde_json::json!({
            "ok": false,
            "detail": format!("Failed - requirement not met ({error})")
        }),
    };

    serde_json::to_string(&result).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn import_qssm_template(path: String) -> Result<String, String> {
    let raw = std::fs::read(&path).map_err(|error| format!("read {path}: {error}"))?;
    let template = QssmTemplate::from_json_slice(&raw)
        .map_err(|error| format!("invalid .qssm template: {error}"))?;
    serde_json::to_string_pretty(&template).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn export_qssm_template(path: String, template_json: String) -> Result<(), String> {
    let template = QssmTemplate::from_json_slice(template_json.as_bytes())
        .map_err(|error| format!("invalid .qssm template: {error}"))?;
    let pretty = serde_json::to_string_pretty(&template).map_err(|error| error.to_string())?;
    std::fs::write(&path, pretty.as_bytes()).map_err(|error| format!("write {path}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const CLAIM_21: &str = r#"{"claim":{"age_years":21}}"#;
    const CLAIM_25: &str = r#"{"claim":{"age_years":25}}"#;
    const CLAIM_20: &str = r#"{"claim":{"age_years":20}}"#;

    // ── helpers ──

    fn age_template_json() -> String {
        proof_of_age_template_json().unwrap()
    }

    fn compile_age_blueprint() -> String {
        compile_blueprint("age-gate-21".into()).unwrap()
    }

    // ── compile ──

    #[test]
    fn test_compile_blueprint_known_id() {
        let hex = compile_blueprint("age-gate-21".into()).unwrap();
        assert!(!hex.is_empty());
        assert!(hex::decode(&hex).is_ok(), "output must be valid hex");
    }

    #[test]
    fn test_compile_blueprint_raw_json() {
        let json = age_template_json();
        let hex = compile_blueprint(json).unwrap();
        assert!(!hex.is_empty());
    }

    #[test]
    fn test_compile_unknown_template_errors() {
        let result = compile_blueprint("nonexistent-xyz".into());
        assert!(result.is_err());
    }

    // ── commit / open ──

    #[test]
    fn test_commit_returns_64_hex_chars() {
        let hex = commit_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        assert_eq!(hex.len(), 64, "32 bytes = 64 hex chars");
    }

    #[test]
    fn test_commit_open_round_trip() {
        let c = commit_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        let o = open_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        assert_eq!(c, o, "commit and open must match for same inputs");
    }

    #[test]
    fn test_commit_open_different_input_differs() {
        let c = commit_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        let o = open_secret(CLAIM_20.into(), SALT_HEX.into()).unwrap();
        assert_ne!(c, o, "different input must produce different commitment");
    }

    #[test]
    fn test_open_returns_64_hex_chars() {
        let hex = open_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        assert_eq!(hex.len(), 64);
    }

    // ── prove ──

    #[test]
    fn test_prove_value_meets_min() {
        let bp = compile_age_blueprint();
        let proof = prove_claim(CLAIM_21.into(), SALT_HEX.into(), bp);
        assert!(
            proof.is_ok(),
            "age=21 must pass age-gate-21: {}",
            proof.unwrap_err()
        );
    }

    #[test]
    fn test_prove_value_above_min() {
        let bp = compile_age_blueprint();
        let proof = prove_claim(CLAIM_25.into(), SALT_HEX.into(), bp);
        assert!(proof.is_ok(), "age=25 must pass: {}", proof.unwrap_err());
    }

    #[test]
    fn test_prove_value_below_min_fails() {
        let bp = compile_age_blueprint();
        let proof = prove_claim(CLAIM_20.into(), SALT_HEX.into(), bp);
        assert!(proof.is_err(), "age=20 must fail age-gate-21");
    }

    // ── verify ──

    #[test]
    fn test_verify_valid_proof() {
        let bp = compile_age_blueprint();
        let proof_hex = prove_claim(CLAIM_25.into(), SALT_HEX.into(), bp.clone()).unwrap();
        let valid = verify_proof(proof_hex, bp).unwrap();
        assert!(valid, "valid proof must verify");
    }

    #[test]
    fn test_verify_invalid_proof() {
        let bp = compile_age_blueprint();
        let garbage = "aa".repeat(64);
        let result = verify_proof(garbage, bp);
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("garbage proof must not verify"),
        }
    }

    // ── template helpers ──

    #[test]
    fn test_proof_of_age_template_json() {
        let json = age_template_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], "age-gate-21");
        assert!(parsed["predicates"].is_array());
        assert!(!parsed["predicates"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_verify_claim_pass() {
        let json = age_template_json();
        let result = verify_claim_with_template(json, CLAIM_25.into()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn test_verify_claim_fail() {
        let json = age_template_json();
        let result = verify_claim_with_template(json, CLAIM_20.into()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["ok"], false);
    }

    #[test]
    fn test_verify_claim_min_boundary_pass() {
        let json = age_template_json();
        let result = verify_claim_with_template(json, CLAIM_21.into()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(
            parsed["ok"], true,
            "age=21 must pass age-gate-21 predicate check"
        );
    }

    // ── import / export round-trip ──

    #[test]
    fn test_import_export_round_trip() {
        let json = age_template_json();
        let dir = std::env::temp_dir().join("qssm-desktop-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test-template.qssm");
        let path_str = path.display().to_string();

        export_qssm_template(path_str.clone(), json.clone()).unwrap();
        let imported = import_qssm_template(path_str.clone()).unwrap();

        let orig: serde_json::Value = serde_json::from_str(&json).unwrap();
        let back: serde_json::Value = serde_json::from_str(&imported).unwrap();
        assert_eq!(orig["id"], back["id"]);
        assert_eq!(orig["predicates"], back["predicates"]);

        let _ = std::fs::remove_file(&path);
    }

    // ── hex decoding edge cases ──

    #[test]
    fn test_decode_hex_32_invalid() {
        let result = decode_hex_32("not-hex", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid hex"));
    }

    #[test]
    fn test_decode_hex_32_wrong_length() {
        let result = decode_hex_32("aabb", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected 32 bytes"));
    }

    #[test]
    fn test_commit_bad_salt_errors() {
        let result = commit_secret(CLAIM_25.into(), "bad-hex".into());
        assert!(result.is_err());
    }

    // ── full cycle: compile → commit → prove → verify → open ──

    #[test]
    fn test_full_api_cycle() {
        let bp = compile_age_blueprint();
        let commitment = commit_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        let proof = prove_claim(CLAIM_25.into(), SALT_HEX.into(), bp.clone()).unwrap();
        let valid = verify_proof(proof, bp).unwrap();
        assert!(valid, "full cycle verify must pass");
        let opened = open_secret(CLAIM_25.into(), SALT_HEX.into()).unwrap();
        assert_eq!(commitment, opened, "open must match commit");
    }
}
