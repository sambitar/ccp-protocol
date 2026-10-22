//! Shared value, canonical JSON, key-id, and signature helpers.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ccp_kernel::crypto;
use ccp_kernel::Value;
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Build an object value from borrowed keys.
pub fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

/// Build an object value from owned keys.
pub fn object_owned(entries: Vec<(String, Value)>) -> Value {
    Value::Object(entries)
}

/// A string value.
pub fn text(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

/// A non-negative integer value.
pub fn uint(value: u64) -> Value {
    Value::Int(BigUint::from(value))
}

/// An array value.
pub fn array(items: Vec<Value>) -> Value {
    Value::Array(items)
}

/// An array of strings.
pub fn string_array(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::Str).collect())
}

/// A null value, or a string when present.
pub fn optional_text(value: &Option<String>) -> Value {
    match value {
        Some(text) => Value::Str(text.clone()),
        None => Value::Null,
    }
}

/// Read a non-negative integer that fits in `u64`.
pub fn as_u64(value: &Value) -> Option<u64> {
    value.as_int().and_then(|number| number.to_u64())
}

/// Read an array of non-empty strings.
pub fn string_list(value: &Value) -> Option<Vec<String>> {
    value.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect()
    })
}

/// Parse the strict canonical profile.
pub fn parse(text: &str) -> Result<Value, String> {
    ccp_kernel::parse_strict(text)
}

/// Canonicalize a value.
pub fn serialize(value: &Value) -> Result<String, String> {
    ccp_kernel::serialize(value)
}

/// Canonical signing bytes for a document (top-level `signature` excluded).
pub fn signing_bytes(value: &Value) -> Result<String, String> {
    let mut unsigned = value.clone();
    unsigned.remove("signature");
    serialize(&unsigned)
}

/// Decode a `key:ed25519:<base64url>` identifier into raw public key bytes.
pub fn public_bytes_from_key_id(key_id: &str) -> Result<[u8; 32], String> {
    let encoded = key_id
        .strip_prefix(crypto::KEY_PREFIX)
        .ok_or_else(|| "unsupported key identifier".to_string())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| "invalid key identifier".to_string())?;
    bytes
        .try_into()
        .map_err(|_| "key identifier is not 32 bytes".to_string())
}

/// The key id for a 32-byte Ed25519 seed.
pub fn key_id_from_seed(seed: &[u8; 32]) -> Result<String, String> {
    let key = crypto::signing_key_from_seed(seed)?;
    Ok(crypto::key_id(&key))
}

/// The public key bytes for a seed.
pub fn public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let key = crypto::signing_key_from_seed(seed).expect("32-byte seed");
    crypto::public_key_bytes(&key)
}

/// Sign an object and apply the `signature` field.
pub fn sign_document(value: Value, seed: &[u8; 32]) -> Result<Value, String> {
    let key = crypto::signing_key_from_seed(seed)?;
    let bytes = signing_bytes(&value)?;
    let signature = crypto::sign_message(&key, bytes.as_bytes());
    let mut signed = value;
    signed.set("signature", Value::Str(crypto::signature_field(&signature)));
    Ok(signed)
}

/// Sign an object and return its canonical wire form.
pub fn signed_wire(value: Value, seed: &[u8; 32]) -> Result<String, String> {
    let signed = sign_document(value, seed)?;
    serialize(&signed)
}

/// Verify a signature field over signing bytes with a public key.
pub fn verify_signature(public_key: &[u8; 32], bytes: &str, signature_field: &str) -> bool {
    match crypto::signature_from_field(signature_field) {
        Ok(signature) => crypto::verify_message(public_key, bytes.as_bytes(), &signature),
        Err(_) => false,
    }
}

/// A fresh opaque 128-bit identifier as lowercase hex.
///
/// Uses the OS entropy source when available and falls back to a process-local
/// mix; ids are opaque, never secret material.
pub fn random_id() -> String {
    let mut seed = Vec::with_capacity(64);
    if let Ok(mut source) = std::fs::File::open("/dev/urandom") {
        let mut bytes = [0u8; 32];
        if std::io::Read::read_exact(&mut source, &mut bytes).is_ok() {
            seed.extend_from_slice(&bytes);
        }
    }
    if seed.is_empty() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        seed.extend_from_slice(now.to_le_bytes().as_slice());
        seed.extend_from_slice(&std::process::id().to_le_bytes());
        let address = &seed as *const _ as usize;
        seed.extend_from_slice(&address.to_le_bytes());
    }
    crypto::sha256_hex(&seed)
        .chars()
        .take(32)
        .collect::<String>()
}

/// The canonical `sha256:<hex>` digest over signing bytes.
pub fn document_digest(value: &Value) -> Result<String, String> {
    signing_bytes(value).map(|bytes| crypto::digest_bytes(bytes.as_bytes()))
}
