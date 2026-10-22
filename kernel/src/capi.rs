//! String-based C ABI shared by the native library and the WASM build.
//!
//! Every call writes a JSON envelope to a global result buffer:
//! `{"ok":true,"value":…}` or `{"ok":false,"error":"…"}`. The buffer is
//! valid until the next call.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use num_bigint::BigUint;

use crate::crypto;
use crate::decision::decide;
use crate::json::{parse_strict, serialize};
use crate::state_machine::next_state;
use crate::value::Value;

static RESULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn invalid() -> String {
    "invalid_request".to_string()
}

fn set_result(text: String) {
    let mut guard = RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = text.into_bytes();
}

fn respond(result: Result<Value, String>) -> i32 {
    match result {
        Ok(value) => {
            let envelope = Value::Object(vec![
                ("ok".to_string(), Value::Bool(true)),
                ("value".to_string(), value),
            ]);
            set_result(
                serialize(&envelope)
                    .unwrap_or_else(|_| "{\"error\":\"malformed\",\"ok\":false}".to_string()),
            );
            0
        }
        Err(code) => {
            let envelope = Value::Object(vec![
                ("error".to_string(), Value::Str(code)),
                ("ok".to_string(), Value::Bool(false)),
            ]);
            set_result(
                serialize(&envelope)
                    .unwrap_or_else(|_| "{\"error\":\"malformed\",\"ok\":false}".to_string()),
            );
            1
        }
    }
}

unsafe fn text_input<'a>(pointer: *const u8, length: usize) -> Result<&'a str, String> {
    if length == 0 {
        return Ok("");
    }
    if pointer.is_null() {
        return Err("malformed".to_string());
    }
    std::str::from_utf8(std::slice::from_raw_parts(pointer, length))
        .map_err(|_| "malformed".to_string())
}

unsafe fn parse_input(pointer: *const u8, length: usize) -> Result<Value, String> {
    parse_strict(text_input(pointer, length)?)
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value.get(name).ok_or_else(invalid)
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    field(value, name)?.as_str().ok_or_else(invalid)
}

// -- memory ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn ccp_alloc(length: usize) -> *mut u8 {
    if length == 0 {
        return std::ptr::null_mut();
    }
    let mut buffer = vec![0u8; length].into_boxed_slice();
    let pointer = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    pointer
}

/// # Safety
/// `pointer` must have come from `ccp_alloc` with the same `length`.
#[no_mangle]
pub unsafe extern "C" fn ccp_free(pointer: *mut u8, length: usize) {
    if pointer.is_null() || length == 0 {
        return;
    }
    let slice = std::ptr::slice_from_raw_parts_mut(pointer, length);
    drop(Box::from_raw(slice));
}

/// The result buffer is valid until the next exported call.
#[no_mangle]
pub extern "C" fn ccp_result_ptr() -> *const u8 {
    RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ptr()
}

#[no_mangle]
pub extern "C" fn ccp_result_len() -> usize {
    RESULT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .len()
}

// -- operations -----------------------------------------------------------

/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_canonicalize(pointer: *const u8, length: usize) -> i32 {
    let result = unsafe { text_input(pointer, length) }
        .and_then(parse_strict)
        .and_then(|value| serialize(&value))
        .map(Value::Str);
    respond(result)
}

/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_decide(pointer: *const u8, length: usize) -> i32 {
    let result = (|| -> Result<Value, String> {
        let input = unsafe { parse_input(pointer, length)? };
        let signal = field(&input, "signal")?;
        let signer = string_field(&input, "signer")?;
        let now = string_field(&input, "now")?;

        let mut seen: HashSet<String> = HashSet::new();
        if let Some(Value::Array(items)) = input.get("seen") {
            for item in items {
                if let Some(text) = item.as_str() {
                    seen.insert(text.to_string());
                }
            }
        }

        let mut counters: HashMap<String, BigUint> = HashMap::new();
        if let Some(Value::Object(entries)) = input.get("counters") {
            for (name, value) in entries {
                if let Some(number) = value.as_int() {
                    counters.insert(name.clone(), number.clone());
                }
            }
        }

        let decision = decide(
            input.get("grant"),
            signal,
            signer,
            now,
            &seen,
            &counters,
            input.get("intent_spec"),
            input.get("params_schema"),
            &["0.5-draft", "0.4-draft"],
        );
        Ok(Value::Str(decision))
    })();
    respond(result)
}

/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_next_state(pointer: *const u8, length: usize) -> i32 {
    let result = (|| -> Result<Value, String> {
        let input = unsafe { parse_input(pointer, length)? };
        let from = match input.get("from") {
            None | Some(Value::Null) => None,
            Some(Value::Str(text)) => Some(text.as_str()),
            _ => return Err(invalid()),
        };
        let event = string_field(&input, "event")?;
        next_state(from, event).map(|state| Value::Str(state.to_string()))
    })();
    respond(result)
}

/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_sign(pointer: *const u8, length: usize) -> i32 {
    let result = (|| -> Result<Value, String> {
        let input = unsafe { parse_input(pointer, length)? };
        let seed = crypto::hex_decode(string_field(&input, "seed_hex")?)?;
        let message = crypto::hex_decode(string_field(&input, "message_hex")?)?;
        let key = crypto::signing_key_from_seed(&seed)?;
        let public = crypto::public_key_bytes(&key);
        let signature = crypto::sign_message(&key, &message);

        Ok(Value::Object(vec![
            (
                "public_key_hex".to_string(),
                Value::Str(crypto::hex_encode(&public)),
            ),
            (
                "key_id".to_string(),
                Value::Str(crypto::key_id_from_public(&public)),
            ),
            (
                "signature_hex".to_string(),
                Value::Str(crypto::hex_encode(&signature)),
            ),
            (
                "signature_field".to_string(),
                Value::Str(crypto::signature_field(&signature)),
            ),
        ]))
    })();
    respond(result)
}

/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_verify(pointer: *const u8, length: usize) -> i32 {
    let result = (|| -> Result<Value, String> {
        let input = unsafe { parse_input(pointer, length)? };
        let public = crypto::hex_decode(string_field(&input, "public_key_hex")?)?;
        let public: [u8; 32] = public.try_into().map_err(|_| invalid())?;
        let message = crypto::hex_decode(string_field(&input, "message_hex")?)?;
        let signature = crypto::signature_from_field(string_field(&input, "signature_field")?)?;
        Ok(Value::Bool(crypto::verify_message(
            &public, &message, &signature,
        )))
    })();
    respond(result)
}

/// Sign a parsed document: canonicalize without `signature`, sign, and emit
/// the wire form with `signature` last.
/// # Safety
/// `pointer` must be valid for `length` bytes of UTF-8.
#[no_mangle]
pub unsafe extern "C" fn ccp_sign_document(pointer: *const u8, length: usize) -> i32 {
    let result = (|| -> Result<Value, String> {
        let input = unsafe { parse_input(pointer, length)? };
        let seed = crypto::hex_decode(string_field(&input, "seed_hex")?)?;
        let key = crypto::signing_key_from_seed(&seed)?;
        let public = crypto::public_key_bytes(&key);

        let mut value = parse_strict(string_field(&input, "document")?)?;
        value.remove("signature");
        let signing_input = serialize(&value)?;
        let signature = crypto::sign_message(&key, signing_input.as_bytes());
        let field = crypto::signature_field(&signature);
        value.set("signature", Value::Str(field.clone()));

        Ok(Value::Object(vec![
            (
                "key_id".to_string(),
                Value::Str(crypto::key_id_from_public(&public)),
            ),
            (
                "public_key_hex".to_string(),
                Value::Str(crypto::hex_encode(&public)),
            ),
            ("signature_field".to_string(), Value::Str(field)),
            (
                "signing_input_sha256".to_string(),
                Value::Str(crypto::sha256_hex(signing_input.as_bytes())),
            ),
            ("wire".to_string(), Value::Str(serialize(&value)?)),
        ]))
    })();
    respond(result)
}
