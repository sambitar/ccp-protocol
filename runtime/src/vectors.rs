//! Language-neutral conformance harness over the frozen vector suites.
//!
//! The binary in `src/bin/conformance.rs` prints the same summary shape as
//! `sdk/typescript/conformance/run.mjs` and `sdk/python/conformance/run.py`.
//! This module is also used by `tests/vectors.rs`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use ccp_kernel::decision::decide;
use ccp_kernel::{parse_strict, serialize, Value};
use num_bigint::BigUint;

use crate::hosts::{validate_host_profile, HostProfile};
use crate::identity::{
    admit, verify_admission_policy, verify_identity_document, VerifyIdentityOptions,
    VerifyPolicyOptions,
};
use crate::model::AdmissionRequest;
use crate::util::{as_u64, object, object_owned, string_list, text, uint};

/// Run whichever suites exist in `directory` and return the JSON summary.
pub fn run_directory(directory: &Path) -> Result<Value, String> {
    let mut suites: Vec<(String, Value)> = Vec::new();

    if directory.join("canonical-json.json").exists() {
        let data = load(directory, "canonical-json.json")?;
        suites.push(("canonical-json".to_string(), run_canonical(&data)?));
    }
    if directory.join("validation.json").exists() {
        let data = load(directory, "validation.json")?;
        suites.push(("validation".to_string(), run_validation(&data)?));
    }
    if directory.join("identity.json").exists() {
        let data = load(directory, "identity.json")?;
        suites.push(("identity".to_string(), run_identities(&data)?));
        suites.push(("policy".to_string(), run_policies(&data)?));
        suites.push(("admission".to_string(), run_admissions(&data)?));
    }
    if directory.join("hosts.json").exists() {
        let data = load(directory, "hosts.json")?;
        suites.push(("hosts".to_string(), run_hosts(&data)?));
    }

    Ok(object_owned(suites))
}

/// Total failures across every suite in a summary.
pub fn total_failed(summary: &Value) -> u64 {
    match summary {
        Value::Object(entries) => entries
            .iter()
            .filter_map(|(_, suite)| suite.get("failed").and_then(as_u64))
            .sum(),
        _ => 0,
    }
}

fn load(directory: &Path, name: &str) -> Result<Value, String> {
    let text = fs::read_to_string(directory.join(name))
        .map_err(|error| format!("read {name}: {error}"))?;
    parse_strict(&text)
}

fn run_canonical(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "vectors")?;
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let document = string_field(vector, "document")?;
        let got = match parse_strict(&document) {
            Ok(value) => match serialize(&value) {
                Ok(canonical) => canonical,
                Err(error) => format!("error:{error}"),
            },
            Err(error) => format!("error:{error}"),
        };
        let expected = if let Some(error) = optional_string_field(vector, "expect_error") {
            format!("error:{error}")
        } else {
            string_field(vector, "expected_canonical")?
        };
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn run_validation(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "vectors")?;
    let intent_spec = object(vec![
        (
            "required_capabilities",
            Value::Array(vec![text("store.read")]),
        ),
        ("confirmation", text("grant-policy")),
    ]);
    let params_schema = object(vec![
        ("type", text("object")),
        (
            "properties",
            object(vec![("item_id", object(vec![("type", text("string"))]))]),
        ),
        ("required", Value::Array(vec![text("item_id")])),
        ("additionalProperties", Value::Bool(false)),
    ]);
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let signal = vector
            .get("signal")
            .ok_or_else(|| "validation vector missing signal".to_string())?;
        let grant = vector.get("grant").filter(|value| !value.is_null());
        let signer = string_field(vector, "signer")?;
        let context = vector
            .get("context")
            .ok_or_else(|| "validation vector missing context".to_string())?;
        let now = string_field(context, "now")?;
        let seen: HashSet<String> = array_field(context, "seen")?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_string))
            .collect();
        let mut counters = HashMap::new();
        if let Some(Value::Object(entries)) = context.get("counters") {
            for (name, value) in entries {
                counters.insert(name.clone(), BigUint::from(as_u64(value).unwrap_or(0)));
            }
        }
        let got = decide(
            grant,
            signal,
            &signer,
            &now,
            &seen,
            &counters,
            Some(&intent_spec),
            Some(&params_schema),
            &["0.5-draft", "0.4-draft"],
        );
        let expected = string_field(vector, "expected")?;
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn run_identities(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "identities")?;
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let document = string_field(vector, "document")?;
        let options = VerifyIdentityOptions {
            now: optional_string_field(vector, "now"),
            expected_identity: optional_string_field(vector, "expected_identity"),
            manifest_digest: optional_string_field(vector, "manifest_digest"),
            policy_digest: optional_string_field(vector, "policy_digest"),
        };
        let got = match verify_identity_document(&document, &options) {
            Ok(_) => "valid".to_string(),
            Err(error) => error.code,
        };
        let expected = string_field(vector, "expected")?;
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn run_policies(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "policies")?;
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let document = string_field(vector, "document")?;
        let options = VerifyPolicyOptions {
            now: optional_string_field(vector, "now"),
            expected_host: optional_string_field(vector, "expected_host"),
        };
        let got = match verify_admission_policy(&document, &options) {
            Ok(_) => "valid".to_string(),
            Err(error) => error.code,
        };
        let expected = string_field(vector, "expected")?;
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn run_admissions(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "admissions")?;
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let policy_document = string_field(vector, "policy")?;
        let verify_now = optional_string_field(vector, "verify_now");
        let request = vector
            .get("request")
            .ok_or_else(|| "admission vector missing request".to_string())?;
        let revoked: HashSet<String> = vector
            .get("revoked")
            .and_then(string_list)
            .unwrap_or_default()
            .into_iter()
            .collect();

        let got = match verify_admission_policy(
            &policy_document,
            &VerifyPolicyOptions {
                now: verify_now,
                expected_host: None,
            },
        ) {
            Ok(policy) => {
                let admission = AdmissionRequest {
                    requester_key: string_field(request, "requester_key")?,
                    contact_id: string_field(request, "contact_id")?,
                    intent: string_field(request, "intent")?,
                    risk: string_field(request, "risk")?,
                    now: string_field(request, "now")?,
                    destination: optional_string_field(request, "destination"),
                };
                let result = admit(&policy, &admission, Some(&revoked));
                let mut got = result.decision;
                if vector.get("expected_rule").is_some() {
                    got = format!("{}:{}", got, result.rule_id.as_deref().unwrap_or(""));
                }
                if vector.get("expected_reason").is_some() {
                    got = format!("{}:{}", got, result.reason);
                }
                got
            }
            Err(error) => error.code,
        };

        let mut expected = string_field(vector, "expected")?;
        if let Some(rule) = optional_string_field(vector, "expected_rule") {
            expected = format!("{expected}:{rule}");
        }
        if let Some(reason) = optional_string_field(vector, "expected_reason") {
            expected = format!("{expected}:{reason}");
        }
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn run_hosts(data: &Value) -> Result<Value, String> {
    let vectors = array_field(data, "vectors")?;
    let mut failures = Vec::new();
    for vector in vectors {
        let id = string_field(vector, "id")?;
        let host = string_field(vector, "host")?;
        let raw_profile = vector.get("profile");
        let invalid_network = raw_profile
            .and_then(|profile| profile.get("network"))
            .map(|network| !matches!(network, Value::Bool(_)))
            .unwrap_or(false);
        let profile = host_profile(raw_profile)?;
        let got = if invalid_network {
            "invalid_request".to_string()
        } else {
            match validate_host_profile(&host, &profile) {
                Ok(_) => "valid".to_string(),
                Err(error) => error.code.to_string(),
            }
        };
        let expected = string_field(vector, "expected")?;
        if got != expected {
            failures.push(failure(&id, &expected, &got));
        }
    }
    Ok(summary(vectors.len(), failures))
}

fn host_profile(value: Option<&Value>) -> Result<HostProfile, String> {
    let Some(value) = value else {
        return Ok(HostProfile::default());
    };
    Ok(HostProfile {
        class: optional_string_field(value, "class"),
        risk: optional_string_field(value, "risk"),
        min_confirmation: optional_string_field(value, "minConfirmation"),
        idempotency: optional_string_field(value, "idempotency"),
        network: value.get("network").and_then(Value::as_bool),
        placement: value.get("placement").and_then(string_list),
        fields: value.get("fields").and_then(string_list),
    })
}

fn array_field<'a>(value: &'a Value, name: &str) -> Result<&'a [Value], String> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing array field {name}"))
}

fn string_field(value: &Value, name: &str) -> Result<String, String> {
    optional_string_field(value, name).ok_or_else(|| format!("missing string field {name}"))
}

fn optional_string_field(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

fn failure(id: &str, expected: &str, got: &str) -> Value {
    object(vec![
        ("id", text(id)),
        ("expected", text(expected)),
        ("got", text(got)),
    ])
}

fn summary(total: usize, failures: Vec<Value>) -> Value {
    object(vec![
        ("passed", uint((total - failures.len()) as u64)),
        ("failed", uint(failures.len() as u64)),
        ("failures", Value::Array(failures)),
    ])
}
