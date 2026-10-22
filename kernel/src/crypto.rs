//! Ed25519 keys and signatures (§25.2), plus SHA-256 digests.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const KEY_PREFIX: &str = "key:ed25519:";
pub const SIG_PREFIX: &str = "ed25519:";

pub fn signing_key_from_seed(seed: &[u8]) -> Result<SigningKey, String> {
    let bytes: [u8; 32] = seed
        .try_into()
        .map_err(|_| "seed must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn public_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub fn key_id_from_public(public: &[u8; 32]) -> String {
    format!("{}{}", KEY_PREFIX, URL_SAFE_NO_PAD.encode(public))
}

pub fn key_id(key: &SigningKey) -> String {
    key_id_from_public(&public_key_bytes(key))
}

pub fn sign_message(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

pub fn signature_field(signature: &[u8; 64]) -> String {
    format!("{}{}", SIG_PREFIX, URL_SAFE_NO_PAD.encode(signature))
}

pub fn signature_from_field(field: &str) -> Result<[u8; 64], String> {
    let encoded = field
        .strip_prefix(SIG_PREFIX)
        .ok_or_else(|| "unsupported signature encoding".to_string())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "invalid signature encoding".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())
}

pub fn verify_message(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(public) {
        Ok(key) => key
            .verify_strict(message, &Signature::from_bytes(signature))
            .is_ok(),
        Err(_) => false,
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    hex::decode(text).map_err(|_| "invalid hex".to_string())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}
