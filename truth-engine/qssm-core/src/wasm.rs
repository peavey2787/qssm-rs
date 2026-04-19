use wasm_bindgen::prelude::*;

/// Resolve a built-in template ID or raw template JSON into an opaque blueprint.
#[wasm_bindgen(js_name = "compile")]
pub fn wasm_compile(template_id: &str) -> Result<Vec<u8>, JsValue> {
    qssm_api::compile(template_id).map_err(|e| JsValue::from_str(&e))
}

/// Lock a secret without revealing it — returns 32-byte commitment.
#[wasm_bindgen(js_name = "commit")]
pub fn wasm_commit(secret: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsValue> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| JsValue::from_str("salt must be exactly 32 bytes"))?;
    Ok(qssm_api::commit(secret, &salt))
}

/// Create a ZK proof that the secret satisfies the blueprint's rules.
#[wasm_bindgen(js_name = "prove")]
pub fn wasm_prove(secret: &[u8], salt: &[u8], blueprint: &[u8]) -> Result<Vec<u8>, JsValue> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| JsValue::from_str("salt must be exactly 32 bytes"))?;
    qssm_api::prove(secret, &salt, blueprint).map_err(|e| JsValue::from_str(&e))
}

/// Verify a proof byte array against a blueprint — returns true / false.
#[wasm_bindgen(js_name = "verify")]
pub fn wasm_verify(proof: &[u8], blueprint: &[u8]) -> bool {
    qssm_api::verify(proof, blueprint)
}

/// Reconstruct the commitment from (secret, salt); compare with commit output.
#[wasm_bindgen(js_name = "open")]
pub fn wasm_open(secret: &[u8], salt: &[u8]) -> Result<Vec<u8>, JsValue> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| JsValue::from_str("salt must be exactly 32 bytes"))?;
    Ok(qssm_api::open(secret, &salt))
}
