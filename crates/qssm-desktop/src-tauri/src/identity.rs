use std::fs;
use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::Mnemonic;
use libp2p::identity::ed25519;
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySummary {
    pub id: String,
    pub id_name: String,
    pub public_peer_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedIdentity {
    pub id: String,
    pub id_name: String,
    pub public_peer_id: String,
    pub mnemonic_24: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegistryFile {
    identities: Vec<IdentityRecord>,
}

impl Default for RegistryFile {
    fn default() -> Self {
        Self {
            identities: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityRecord {
    id: String,
    id_name: String,
    public_peer_id: String,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

pub fn list_identities(app: &tauri::AppHandle) -> Result<Vec<IdentitySummary>, String> {
    let reg = read_registry(app)?;
    Ok(reg
        .identities
        .into_iter()
        .map(|x| IdentitySummary {
            id: x.id,
            id_name: x.id_name,
            public_peer_id: x.public_peer_id,
        })
        .collect())
}

pub fn create_identity(
    app: &tauri::AppHandle,
    id_name: String,
    mut mnemonic_24: String,
    password: String,
) -> Result<IdentitySummary, String> {
    if id_name.trim().is_empty() {
        return Err("identity name is required".into());
    }
    if password.len() < 8 {
        return Err("vault password must be at least 8 characters".into());
    }
    let m = Mnemonic::parse(mnemonic_24.trim()).map_err(|e| format!("invalid mnemonic: {e}"))?;
    if m.word_count() != 24 {
        return Err("mnemonic must be 24 words".into());
    }

    let mut entropy = m.to_entropy();
    let id = deterministic_identity_id(&entropy);
    let public_peer_id = deterministic_peer_id(&entropy)?;

    let mut reg = read_registry(app)?;
    if reg.identities.iter().any(|x| x.id == id) {
        return Err("identity already exists for this seed".into());
    }

    let mut salt = random_16();
    let mut nonce = random_12();
    let mut key = [0u8; 32];
    argon2_for_vault()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("argon2: {e}"))?;

    // Once entropy is derived, wipe the original word-buffer as early as possible.
    mnemonic_24.zeroize();
    let mut plain = m.to_string().into_bytes();
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("aes init: {e}"))?
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| "aes-gcm encrypt failed".to_string())?;
    plain.zeroize();
    entropy.zeroize();

    let rec = IdentityRecord {
        id: id.clone(),
        id_name: id_name.trim().to_string(),
        public_peer_id: public_peer_id.clone(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(cipher),
    };
    reg.identities.push(rec);
    write_registry(app, &reg)?;
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();

    Ok(IdentitySummary {
        id,
        id_name: id_name.trim().to_string(),
        public_peer_id,
    })
}

pub fn validate_mnemonic_and_derive_peer_id(mnemonic_24: &str) -> Result<String, String> {
    let m = Mnemonic::parse(mnemonic_24.trim()).map_err(|e| format!("invalid mnemonic: {e}"))?;
    if m.word_count() != 24 {
        return Err("mnemonic must be 24 words".into());
    }
    let mut entropy = m.to_entropy();
    let peer_id = deterministic_peer_id(&entropy)?;
    entropy.zeroize();
    Ok(peer_id)
}

pub fn decrypt_identity(
    app: &tauri::AppHandle,
    id: &str,
    password: &str,
) -> Result<DecryptedIdentity, String> {
    let reg = read_registry(app)?;
    let rec = reg
        .identities
        .iter()
        .find(|x| x.id == id)
        .ok_or_else(|| "identity not found".to_string())?;
    let mut salt = hex_to_16(&rec.salt_hex)?;
    let mut nonce = hex_to_12(&rec.nonce_hex)?;
    let mut key = [0u8; 32];
    argon2_for_vault()
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| format!("argon2: {e}"))?;
    let mut cipher = hex::decode(&rec.ciphertext_hex).map_err(|e| format!("cipher decode: {e}"))?;
    let mut plain = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("aes init: {e}"))?
        .decrypt(Nonce::from_slice(&nonce), cipher.as_ref())
        .map_err(|_| "password check failed".to_string())?;
    let mut mnemonic =
        String::from_utf8(plain.clone()).map_err(|_| "decryption failed".to_string())?;
    let parsed =
        Mnemonic::parse(mnemonic.trim()).map_err(|_| "password check failed".to_string())?;

    let out = DecryptedIdentity {
        id: rec.id.clone(),
        id_name: rec.id_name.clone(),
        public_peer_id: rec.public_peer_id.clone(),
        mnemonic_24: parsed.to_string(),
    };
    salt.zeroize();
    nonce.zeroize();
    key.zeroize();
    plain.zeroize();
    cipher.zeroize();
    mnemonic.zeroize();
    Ok(out)
}

pub fn delete_identity(app: &tauri::AppHandle, id: &str, password: &str) -> Result<(), String> {
    let _ = decrypt_identity(app, id, password)?;
    let mut reg = read_registry(app)?;
    let idx = reg
        .identities
        .iter()
        .position(|x| x.id == id)
        .ok_or_else(|| "identity not found".to_string())?;
    let mut rec = reg.identities.remove(idx);
    rec.ciphertext_hex.zeroize();
    write_registry(app, &reg)?;
    // Best-effort secure rewrite of registry file after removal.
    secure_rewrite_registry(app, &reg)?;
    Ok(())
}

fn deterministic_identity_id(entropy: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"QSSM_IDENTITY_ID_V1");
    h.update(entropy);
    let out = h.finalize();
    format!("id-{}", hex::encode(&out.as_bytes()[..10]))
}

fn deterministic_peer_id(entropy: &[u8]) -> Result<String, String> {
    let mut seed_hasher = blake3::Hasher::new();
    seed_hasher.update(b"QSSM_DERIVE_PEERID_M_0");
    seed_hasher.update(entropy);
    let seed = seed_hasher.finalize();
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed.as_bytes()[..32]);
    let secret =
        ed25519::SecretKey::try_from_bytes(&mut sk).map_err(|e| format!("ed25519 secret: {e}"))?;
    let keypair = ed25519::Keypair::from(secret);
    let peer_id = PeerId::from_public_key(&keypair.public().into());
    sk.zeroize();
    Ok(peer_id.to_string())
}

fn random_16() -> [u8; 16] {
    let mut out = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn random_12() -> [u8; 12] {
    let mut out = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut out);
    out
}

fn hex_to_16(s: &str) -> Result<[u8; 16], String> {
    let v = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 16 {
        return Err("expected 16-byte hex".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Ok(out)
}

fn hex_to_12(s: &str) -> Result<[u8; 12], String> {
    let v = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if v.len() != 12 {
        return Err("expected 12-byte hex".into());
    }
    let mut out = [0u8; 12];
    out.copy_from_slice(&v);
    Ok(out)
}

fn registry_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("app_data_dir: {e}"))?;
    fs::create_dir_all(&base).map_err(|e| format!("mkdir app_data: {e}"))?;
    Ok(base.join("registry.json"))
}

fn read_registry(app: &tauri::AppHandle) -> Result<RegistryFile, String> {
    let p = registry_path(app)?;
    if !p.exists() {
        return Ok(RegistryFile::default());
    }
    let s = fs::read_to_string(&p).map_err(|e| format!("read registry: {e}"))?;
    serde_json::from_str(&s).map_err(|e| format!("parse registry: {e}"))
}

fn write_registry(app: &tauri::AppHandle, reg: &RegistryFile) -> Result<(), String> {
    let p = registry_path(app)?;
    let s = serde_json::to_string_pretty(reg).map_err(|e| format!("serialize registry: {e}"))?;
    fs::write(p, s.as_bytes()).map_err(|e| format!("write registry: {e}"))
}

fn secure_rewrite_registry(app: &tauri::AppHandle, reg: &RegistryFile) -> Result<(), String> {
    // For single-file encrypted records, hard wipe = remove entry + rewrite file immediately.
    write_registry(app, reg)
}

fn argon2_for_vault() -> Argon2<'static> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).unwrap_or(Params::DEFAULT);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}
