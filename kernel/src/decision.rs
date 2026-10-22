//! The pure §10.3 validation decision.

use std::collections::{HashMap, HashSet};

use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::schema;
use crate::value::Value;

#[allow(clippy::too_many_arguments)]
pub fn decide(
    grant: Option<&Value>,
    signal: &Value,
    signer: &str,
    now: &str,
    seen: &HashSet<String>,
    counters: &HashMap<String, BigUint>,
    intent_spec: Option<&Value>,
    params_schema: Option<&Value>,
    supported_ccp: &[&str],
) -> String {
    let version = signal.get("ccp").and_then(Value::as_str);
    if !version
        .map(|value| supported_ccp.contains(&value))
        .unwrap_or(false)
    {
        return "invalid_request".to_string();
    }

    let grant = match grant {
        Some(value) if !value.is_null() => value,
        _ => return "no_matching_grant".to_string(),
    };
    if signer
        != grant
            .get("requester_key")
            .and_then(Value::as_str)
            .unwrap_or("")
    {
        return "unauthenticated".to_string();
    }
    if signal.get("grant_digest").and_then(Value::as_str)
        != grant.get("manifest_digest").and_then(Value::as_str)
    {
        return "no_matching_grant".to_string();
    }

    let state = grant
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("active");
    match state {
        "revoked" => return "grant_revoked".to_string(),
        "paused" => return "grant_paused".to_string(),
        "suspended" => return "grant_suspended".to_string(),
        _ => {}
    }
    let grant_expiry = grant
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    if state == "expired" || now >= grant_expiry {
        return "grant_expired".to_string();
    }

    let intent = signal.get("intent").and_then(Value::as_str).unwrap_or("");
    let allowed = grant
        .get("intents")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    if !allowed.iter().any(|value| value.as_str() == Some(intent)) {
        return "intent_not_allowed".to_string();
    }

    let (intent_spec, params_schema) = match (intent_spec, params_schema) {
        (Some(spec), Some(schema)) => (spec, schema),
        _ => return "capability_unavailable".to_string(),
    };
    match signal.get("params") {
        Some(params) if schema::is_valid(params, params_schema) => {}
        _ => return "invalid_request".to_string(),
    }

    let signal_expiry = signal
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    if now >= signal_expiry {
        return "request_expired".to_string();
    }
    let request_id = signal
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if seen.contains(request_id) {
        return "replay_detected".to_string();
    }

    if let Some(Value::Object(limits)) = grant.get("limits") {
        for (name, maximum) in limits {
            let maximum = match maximum.as_int() {
                Some(value) => value,
                None => continue,
            };
            let counter = counters.get(name).cloned().unwrap_or_else(BigUint::zero);
            if counter + BigUint::one() > *maximum {
                return "limit_exceeded".to_string();
            }
        }
    }

    let required = intent_spec
        .get("required_capabilities")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    let granted = grant
        .get("capabilities")
        .and_then(Value::as_array)
        .unwrap_or(&[]);
    for capability in required {
        let name = capability.as_str().unwrap_or("");
        if !granted.iter().any(|value| value.as_str() == Some(name)) {
            return "capability_unavailable".to_string();
        }
    }

    if confirmation_policy(grant, intent_spec, intent) == "per_action" {
        return "confirmation_required".to_string();
    }
    "authorized".to_string()
}

/// Grant policy, then manifest policy, then `per_action`.
pub fn confirmation_policy(grant: &Value, intent_spec: &Value, intent: &str) -> String {
    if let Some(Value::Object(policies)) = grant.get("confirmation") {
        if let Some(policy) = policies
            .iter()
            .find(|(name, _)| name == intent)
            .and_then(|(_, value)| value.as_str())
        {
            if policy == "none" || policy == "per_action" {
                return policy.to_string();
            }
        }
    }
    if let Some(policy) = intent_spec.get("confirmation").and_then(Value::as_str) {
        if policy == "none" || policy == "per_action" {
            return policy.to_string();
        }
    }
    "per_action".to_string()
}
