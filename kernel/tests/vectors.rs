//! Conformance tests: the frozen v1 vectors and the adversarial v2 set.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ccp_kernel::crypto;
use ccp_kernel::decision::decide;
use ccp_kernel::json::{parse_strict, serialize};
use ccp_kernel::state_machine::next_state;
use ccp_kernel::Value;
use num_bigint::BigUint;

const INTENT_SPEC_JSON: &str =
    r#"{"confirmation":"grant-policy","required_capabilities":["store.read"]}"#;
const PARAMS_SCHEMA_JSON: &str = r#"{"additionalProperties":false,"properties":{"item_id":{"type":"string"}},"required":["item_id"],"type":"object"}"#;

fn load(relative: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = root.join("..").join(relative);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    parse_strict(&text).unwrap_or_else(|code| panic!("parse {}: {code}", path.display()))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {name}"))
}

fn items<'a>(value: &'a Value, name: &str) -> &'a [Value] {
    value
        .get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("missing array field {name}"))
}

fn check_canonical(relative: &str) -> usize {
    let data = load(relative);
    let vectors = items(&data, "vectors");
    for vector in vectors {
        let id = text(vector, "id");
        let document = text(vector, "document");
        let result = parse_strict(document).and_then(|value| serialize(&value));
        match vector.get("expect_error") {
            Some(Value::Str(expected)) => {
                let got = result
                    .err()
                    .unwrap_or_else(|| panic!("{id}: expected error {expected}"));
                assert_eq!(&got, expected, "{id}");
            }
            _ => {
                let expected = text(vector, "expected_canonical");
                assert_eq!(
                    result.unwrap_or_else(|code| panic!("{id}: {code}")),
                    expected,
                    "{id}"
                );
            }
        }
    }
    vectors.len()
}

fn check_validation(relative: &str) -> usize {
    let data = load(relative);
    let vectors = items(&data, "vectors");
    let intent_spec = parse_strict(INTENT_SPEC_JSON).unwrap();
    let params_schema = parse_strict(PARAMS_SCHEMA_JSON).unwrap();

    for vector in vectors {
        let id = text(vector, "id");
        let mut seen = HashSet::new();
        if let Some(Value::Array(entries)) = vector.get("context").and_then(|c| c.get("seen")) {
            for entry in entries {
                if let Some(request_id) = entry.as_str() {
                    seen.insert(request_id.to_string());
                }
            }
        }

        let mut counters: HashMap<String, BigUint> = HashMap::new();
        if let Some(Value::Object(entries)) = vector.get("context").and_then(|c| c.get("counters"))
        {
            for (name, value) in entries {
                if let Some(number) = value.as_int() {
                    counters.insert(name.clone(), number.clone());
                }
            }
        }

        let now = text(vector.get("context").unwrap(), "now");
        let result = decide(
            vector.get("grant"),
            vector.get("signal").unwrap(),
            text(vector, "signer"),
            now,
            &seen,
            &counters,
            Some(&intent_spec),
            Some(&params_schema),
            &["0.5-draft", "0.4-draft"],
        );
        assert_eq!(result, text(vector, "expected"), "{id}");
    }
    vectors.len()
}

#[test]
fn canonical_v1() {
    assert_eq!(check_canonical("test-vectors/canonical-json.json"), 18);
}

#[test]
fn canonical_v2() {
    assert_eq!(check_canonical("test-vectors/v2/canonical-json.json"), 21);
}

#[test]
fn validation_v1() {
    assert_eq!(check_validation("test-vectors/validation.json"), 18);
}

#[test]
fn validation_v2() {
    assert_eq!(check_validation("test-vectors/v2/validation.json"), 17);
}

#[test]
fn canonical_v3() {
    assert_eq!(check_canonical("test-vectors/v3/canonical-json.json"), 3);
}

#[test]
fn validation_v3() {
    assert_eq!(check_validation("test-vectors/v3/validation.json"), 5);
}

#[test]
fn state_machine_v1() {
    let data = load("test-vectors/state-machine.json");
    let vectors = items(&data, "vectors");
    for vector in vectors {
        let id = text(vector, "id");
        let from = text(vector, "from");
        let to = next_state(Some(from), text(vector, "event"))
            .unwrap_or_else(|error| panic!("{id}: {error}"));
        assert_eq!(to, text(vector, "to"), "{id}");
    }
    assert!(next_state(Some("completed"), "arrive").is_err());
    assert_eq!(vectors.len(), 10);
}

#[test]
fn ed25519_known_answers() {
    let data = load("test-vectors/ed25519.json");
    let vectors = items(&data, "kat_vectors");
    for vector in vectors {
        let id = text(vector, "id");
        let seed = crypto::hex_decode(text(vector, "secret_key_hex")).unwrap();
        let message = crypto::hex_decode(text(vector, "message_hex")).unwrap();
        let key = crypto::signing_key_from_seed(&seed).unwrap();
        let public = crypto::public_key_bytes(&key);

        assert_eq!(
            crypto::hex_encode(&public),
            text(vector, "public_key_hex"),
            "{id}"
        );
        assert_eq!(
            crypto::key_id_from_public(&public),
            text(vector, "key_id"),
            "{id}"
        );

        let signature = crypto::sign_message(&key, &message);
        assert_eq!(
            crypto::hex_encode(&signature),
            text(vector, "signature_hex"),
            "{id}"
        );
        assert_eq!(
            crypto::signature_field(&signature),
            text(vector, "signature_field"),
            "{id}"
        );
        let decoded = crypto::signature_from_field(text(vector, "signature_field")).unwrap();
        assert!(crypto::verify_message(&public, &message, &decoded), "{id}");
    }
    assert_eq!(vectors.len(), 3);
}

#[test]
fn ed25519_signing() {
    let data = load("test-vectors/ed25519.json");
    let vectors = items(&data, "signing_vectors");
    for vector in vectors {
        let id = text(vector, "id");
        let seed = crypto::hex_decode(text(vector, "seed_hex")).unwrap();
        let key = crypto::signing_key_from_seed(&seed).unwrap();
        let public = crypto::public_key_bytes(&key);
        assert_eq!(
            crypto::hex_encode(&public),
            text(vector, "public_key_hex"),
            "{id}"
        );

        let mut value = parse_strict(text(vector, "document")).unwrap();
        value.remove("signature");
        let signing_input = serialize(&value).unwrap();
        assert_eq!(signing_input, text(vector, "signing_input"), "{id}");
        assert_eq!(
            crypto::sha256_hex(signing_input.as_bytes()),
            text(vector, "signing_input_sha256"),
            "{id}"
        );

        let signature = crypto::sign_message(&key, signing_input.as_bytes());
        let field = crypto::signature_field(&signature);
        assert_eq!(field, text(vector, "signature_field"), "{id}");

        let mut wire_value = parse_strict(text(vector, "document")).unwrap();
        wire_value.set("signature", Value::Str(field));
        assert_eq!(
            serialize(&wire_value).unwrap(),
            text(vector, "wire"),
            "{id}"
        );
    }
    assert_eq!(vectors.len(), 2);
}
