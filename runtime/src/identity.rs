//! Identity documents and admission policies (CCP §25.8).
//!
//! These checks happen while a contact is established, before any signal
//! exists. Their codes are deliberately separate from the §10.4 decision
//! codes and must never be returned as a signal outcome.

use std::collections::{BTreeMap, HashSet};

use ccp_kernel::crypto;
use ccp_kernel::Value;

use crate::errors::IdentityError;
use crate::model::{
    AdmissionRequest, AdmissionResult, AdmittedGrant, Endpoint, PolicyRule, VerifiedIdentity,
    VerifiedPolicy,
};
use crate::time::{add_seconds, is_timestamp, utcnow};
use crate::util::{
    as_u64, object, object_owned, parse, public_bytes_from_key_id, serialize, signed_wire,
    signing_bytes, uint, verify_signature,
};

pub const IDENTITY_TYPE: &str = "ccp.identity.v1";
pub const POLICY_TYPE: &str = "ccp.admission-policy.v1";
pub const IDENTITY_CLOCK_SKEW_SECONDS: i64 = 120;

const SUPPORTED_LABELS: [&str; 2] = ["0.5-draft", "0.4-draft"];
const ROLES: [&str; 3] = ["provider", "requester", "consumer"];
const ADMITTABLE_RISK: [&str; 2] = ["read", "disclose"];

/// Input for [`build_identity_document`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityInput {
    pub ccp: Option<String>,
    pub name: Option<String>,
    pub roles: Option<Vec<String>>,
    pub endpoints: Option<Vec<Endpoint>>,
    pub manifest_digest: Option<String>,
    pub policy_digest: Option<String>,
    pub issued_at: String,
    pub expires_at: String,
}

/// Options for [`verify_identity_document`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyIdentityOptions {
    pub now: Option<String>,
    pub expected_identity: Option<String>,
    pub manifest_digest: Option<String>,
    pub policy_digest: Option<String>,
}

/// Input for [`build_admission_policy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicyInput {
    pub ccp: Option<String>,
    pub version: u64,
    pub default: String,
    pub rules: Vec<PolicyRule>,
    pub issued_at: String,
    pub expires_at: String,
}

/// Options for [`verify_admission_policy`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyPolicyOptions {
    pub now: Option<String>,
    pub expected_host: Option<String>,
}

/// Build and sign an identity document; the identity comes from the seed.
pub fn build_identity_document(
    input: &IdentityInput,
    seed: &[u8; 32],
) -> Result<String, IdentityError> {
    let key = crypto::signing_key_from_seed(seed)
        .map_err(|error| IdentityError::new("invalid_request", error))?;
    let mut entries = vec![
        (
            "ccp".to_string(),
            Value::Str(input.ccp.clone().unwrap_or_else(|| "0.5-draft".to_string())),
        ),
        ("type".to_string(), Value::Str(IDENTITY_TYPE.to_string())),
        ("identity".to_string(), Value::Str(crypto::key_id(&key))),
        ("issued_at".to_string(), Value::Str(input.issued_at.clone())),
        (
            "expires_at".to_string(),
            Value::Str(input.expires_at.clone()),
        ),
    ];
    if let Some(name) = &input.name {
        entries.push(("name".to_string(), Value::Str(name.clone())));
    }
    if let Some(roles) = &input.roles {
        entries.push((
            "roles".to_string(),
            Value::Array(roles.iter().cloned().map(Value::Str).collect()),
        ));
    }
    if let Some(endpoints) = &input.endpoints {
        entries.push((
            "endpoints".to_string(),
            Value::Array(
                endpoints
                    .iter()
                    .map(|endpoint| {
                        let mut entry = vec![(
                            "transport".to_string(),
                            Value::Str(endpoint.transport.clone()),
                        )];
                        if let Some(manifest) = &endpoint.manifest {
                            entry.push(("manifest".to_string(), Value::Str(manifest.clone())));
                        }
                        if let Some(signal) = &endpoint.signal {
                            entry.push(("signal".to_string(), Value::Str(signal.clone())));
                        }
                        object_owned(entry)
                    })
                    .collect(),
            ),
        ));
    }
    if let Some(digest) = &input.manifest_digest {
        entries.push(("manifest_digest".to_string(), Value::Str(digest.clone())));
    }
    if let Some(digest) = &input.policy_digest {
        entries.push(("policy_digest".to_string(), Value::Str(digest.clone())));
    }
    signed_wire(object_owned(entries), seed)
        .map_err(|error| IdentityError::new("invalid_request", error))
}

/// Parse and verify an identity document (§25.8.1).
pub fn verify_identity_document(
    document: &str,
    options: &VerifyIdentityOptions,
) -> Result<VerifiedIdentity, IdentityError> {
    let obj = parse(document).map_err(|error| IdentityError::new("invalid_request", error))?;
    if !matches!(obj, Value::Object(_)) {
        return Err(IdentityError::new(
            "invalid_request",
            "identity document must be an object",
        ));
    }
    assert_label(&obj)?;

    if read_string(&obj, "type", "identity")? != IDENTITY_TYPE {
        return Err(IdentityError::new(
            "invalid_request",
            "type is not an identity",
        ));
    }

    let identity = read_string(&obj, "identity", "identity")?;
    assert_key_id(&identity)?;
    assert_signature(&obj, &identity)?;

    if let Some(expected) = &options.expected_identity {
        if expected != &identity {
            return Err(IdentityError::new(
                "identity_changed",
                "identity key differs from the known contact",
            ));
        }
    }

    let issued_at = read_timestamp(&obj, "issued_at", "identity")?;
    let expires_at = read_timestamp(&obj, "expires_at", "identity")?;
    if expires_at <= issued_at {
        return Err(IdentityError::new(
            "invalid_request",
            "expires_at must sort after issued_at",
        ));
    }

    let now = options.now.clone().unwrap_or_else(utcnow);
    let skewed = add_seconds(&now, IDENTITY_CLOCK_SKEW_SECONDS)
        .ok_or_else(|| IdentityError::new("invalid_request", "invalid timestamp"))?;
    if issued_at > skewed {
        return Err(IdentityError::new(
            "identity_expired",
            "identity document is not yet valid",
        ));
    }
    if now > expires_at {
        return Err(IdentityError::new(
            "identity_expired",
            "identity document expired",
        ));
    }

    let mut roles = Vec::new();
    if obj.get("roles").is_some() {
        roles = read_string_array(&obj, "roles", "identity")?;
        let mut seen = HashSet::new();
        for role in &roles {
            if !ROLES.contains(&role.as_str()) {
                return Err(IdentityError::new(
                    "invalid_request",
                    format!("unknown role: {role}"),
                ));
            }
            if !seen.insert(role.clone()) {
                return Err(IdentityError::new(
                    "invalid_request",
                    "roles must be unique",
                ));
            }
        }
    }

    let mut endpoints = Vec::new();
    if let Some(raw) = obj.get("endpoints") {
        let items = raw
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or_else(|| {
                IdentityError::new("invalid_request", "endpoints must be a non-empty array")
            })?;
        for item in items {
            if !matches!(item, Value::Object(_)) {
                return Err(IdentityError::new(
                    "invalid_request",
                    "endpoint must be an object",
                ));
            }
            let transport = read_string(item, "transport", "endpoint")?;
            let manifest = optional_string(item, "manifest", "endpoint")?;
            let signal = optional_string(item, "signal", "endpoint")?;
            if manifest.is_none() && signal.is_none() {
                return Err(IdentityError::new(
                    "invalid_request",
                    "endpoint must carry manifest or signal",
                ));
            }
            endpoints.push(Endpoint {
                transport,
                manifest,
                signal,
            });
        }
    }

    let document_manifest = optional_string(&obj, "manifest_digest", "identity")?;
    assert_digest(&document_manifest, "manifest_digest")?;
    if let (Some(expected), Some(actual)) = (&options.manifest_digest, &document_manifest) {
        if expected != actual {
            return Err(IdentityError::new(
                "manifest_mismatch",
                "manifest digest does not match the document",
            ));
        }
    }

    let document_policy = optional_string(&obj, "policy_digest", "identity")?;
    assert_digest(&document_policy, "policy_digest")?;
    if let (Some(expected), Some(actual)) = (&options.policy_digest, &document_policy) {
        if expected != actual {
            return Err(IdentityError::new(
                "policy_mismatch",
                "policy digest does not match the document",
            ));
        }
    }

    Ok(VerifiedIdentity {
        document: document.to_string(),
        identity,
        issued_at,
        expires_at,
        name: optional_string(&obj, "name", "identity")?,
        roles,
        endpoints,
        manifest_digest: document_manifest,
        policy_digest: document_policy,
    })
}

/// `sha256:<hex>` over the signing bytes of an identity document.
pub fn identity_digest(document: &str) -> Result<String, IdentityError> {
    let value = parse(document).map_err(|error| IdentityError::new("invalid_request", error))?;
    let bytes =
        signing_bytes(&value).map_err(|error| IdentityError::new("invalid_request", error))?;
    Ok(crypto::digest_bytes(bytes.as_bytes()))
}

/// `sha256:<hex>` over the signing bytes of an admission policy.
pub fn policy_digest(document: &str) -> Result<String, IdentityError> {
    identity_digest(document)
}

/// Build and sign an admission policy; the host comes from the seed.
pub fn build_admission_policy(
    input: &AdmissionPolicyInput,
    seed: &[u8; 32],
) -> Result<String, IdentityError> {
    let key = crypto::signing_key_from_seed(seed)
        .map_err(|error| IdentityError::new("invalid_request", error))?;
    let rules = input
        .rules
        .iter()
        .map(rule_to_value)
        .collect::<Vec<Value>>();
    let value = object(vec![
        (
            "ccp",
            Value::Str(input.ccp.clone().unwrap_or_else(|| "0.5-draft".to_string())),
        ),
        ("type", Value::Str(POLICY_TYPE.to_string())),
        ("host", Value::Str(crypto::key_id(&key))),
        ("version", uint(input.version)),
        ("default", Value::Str(input.default.clone())),
        ("rules", Value::Array(rules)),
        ("issued_at", Value::Str(input.issued_at.clone())),
        ("expires_at", Value::Str(input.expires_at.clone())),
    ]);
    signed_wire(value, seed).map_err(|error| IdentityError::new("invalid_request", error))
}

fn rule_to_value(rule: &PolicyRule) -> Value {
    let mut entries = vec![
        ("id".to_string(), Value::Str(rule.id.clone())),
        (
            "intents".to_string(),
            Value::Array(rule.intents.iter().cloned().map(Value::Str).collect()),
        ),
        ("risk".to_string(), Value::Str(rule.risk.clone())),
        (
            "confirmation".to_string(),
            Value::Str(rule.confirmation.clone()),
        ),
        (
            "expires_at".to_string(),
            Value::Str(rule.expires_at.clone()),
        ),
    ];
    if let Some(contacts) = &rule.contacts {
        entries.push((
            "contacts".to_string(),
            Value::Array(contacts.iter().cloned().map(Value::Str).collect()),
        ));
    }
    if let Some(requesters) = &rule.requesters {
        entries.push((
            "requesters".to_string(),
            Value::Array(requesters.iter().cloned().map(Value::Str).collect()),
        ));
    }
    if let Some(destinations) = &rule.destinations {
        entries.push((
            "destinations".to_string(),
            Value::Array(destinations.iter().cloned().map(Value::Str).collect()),
        ));
    }
    if let Some(limits) = &rule.limits {
        entries.push((
            "limits".to_string(),
            object_owned(
                limits
                    .iter()
                    .map(|(name, value)| (name.clone(), uint(*value)))
                    .collect(),
            ),
        ));
    }
    object_owned(entries)
}

/// Parse and verify an admission policy (§25.8.3).
pub fn verify_admission_policy(
    document: &str,
    options: &VerifyPolicyOptions,
) -> Result<VerifiedPolicy, IdentityError> {
    let obj = parse(document).map_err(|error| IdentityError::new("invalid_request", error))?;
    if !matches!(obj, Value::Object(_)) {
        return Err(IdentityError::new(
            "invalid_request",
            "policy must be an object",
        ));
    }
    assert_label(&obj)?;

    if read_string(&obj, "type", "policy")? != POLICY_TYPE {
        return Err(IdentityError::new(
            "invalid_request",
            "type is not a policy",
        ));
    }

    let host = read_string(&obj, "host", "policy")?;
    assert_key_id(&host)?;
    assert_signature(&obj, &host)?;

    if let Some(expected) = &options.expected_host {
        if expected != &host {
            return Err(IdentityError::new(
                "identity_changed",
                "policy host differs from the known identity",
            ));
        }
    }

    let version = obj
        .get("version")
        .and_then(as_u64)
        .ok_or_else(|| IdentityError::new("invalid_request", "version must be an integer"))?;
    if version < 1 {
        return Err(IdentityError::new(
            "invalid_request",
            "version is out of range",
        ));
    }

    let fallback = read_string(&obj, "default", "policy")?;
    if fallback != "confirm" && fallback != "deny" {
        return Err(IdentityError::new(
            "invalid_request",
            "default must be confirm or deny",
        ));
    }

    let issued_at = read_timestamp(&obj, "issued_at", "policy")?;
    let expires_at = read_timestamp(&obj, "expires_at", "policy")?;
    if expires_at <= issued_at {
        return Err(IdentityError::new(
            "invalid_request",
            "expires_at must sort after issued_at",
        ));
    }

    let raw_rules = obj
        .get("rules")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| IdentityError::new("invalid_request", "rules must be a non-empty array"))?;

    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut seen = HashSet::new();
    for value in raw_rules {
        let rule = read_rule(value, &expires_at)?;
        if !seen.insert(rule.id.clone()) {
            return Err(IdentityError::new(
                "invalid_request",
                "rule ids must be unique",
            ));
        }
        rules.push(rule);
    }

    let now = options.now.clone().unwrap_or_else(utcnow);
    if now > expires_at {
        return Err(IdentityError::new(
            "policy_expired",
            "admission policy expired",
        ));
    }

    let bytes =
        signing_bytes(&obj).map_err(|error| IdentityError::new("invalid_request", error))?;
    Ok(VerifiedPolicy {
        document: document.to_string(),
        host,
        version,
        default: fallback,
        rules,
        issued_at,
        expires_at,
        digest: crypto::digest_bytes(bytes.as_bytes()),
    })
}

fn read_rule(value: &Value, policy_expires_at: &str) -> Result<PolicyRule, IdentityError> {
    if !matches!(value, Value::Object(_)) {
        return Err(IdentityError::new(
            "invalid_request",
            "rule must be an object",
        ));
    }
    let id = read_string(value, "id", "rule")?;
    let intents = read_string_array(value, "intents", "rule")?;
    let risk = read_string(value, "risk", "rule")?;
    if !ADMITTABLE_RISK.contains(&risk.as_str()) {
        return Err(IdentityError::new(
            "invalid_request",
            "a policy may only admit read or disclose intents",
        ));
    }

    let contacts = optional_string_array(value, "contacts", "rule")?;
    let requesters = optional_string_array(value, "requesters", "rule")?;
    if contacts.is_none() && requesters.is_none() {
        return Err(IdentityError::new(
            "invalid_request",
            "a rule must name contacts or requesters",
        ));
    }

    let destinations = optional_string_array(value, "destinations", "rule")?;
    if risk == "disclose" && destinations.is_none() {
        return Err(IdentityError::new(
            "invalid_request",
            "a disclose rule must pin destinations",
        ));
    }
    if risk == "read" && destinations.is_some() {
        return Err(IdentityError::new(
            "invalid_request",
            "only a disclose rule may pin destinations",
        ));
    }

    let confirmation = read_string(value, "confirmation", "rule")?;
    if confirmation != "none" {
        return Err(IdentityError::new(
            "invalid_request",
            "rule.confirmation must be none",
        ));
    }

    let expires_at = read_timestamp(value, "expires_at", "rule")?;
    if expires_at.as_str() > policy_expires_at {
        return Err(IdentityError::new(
            "invalid_request",
            "rule expires after the policy",
        ));
    }

    Ok(PolicyRule {
        id,
        intents,
        risk,
        confirmation: "none".to_string(),
        expires_at,
        contacts,
        requesters,
        destinations,
        limits: read_limits(value)?,
    })
}

fn read_limits(value: &Value) -> Result<Option<BTreeMap<String, u64>>, IdentityError> {
    let Some(raw) = value.get("limits") else {
        return Ok(None);
    };
    if !matches!(raw, Value::Object(_)) {
        return Err(IdentityError::new(
            "invalid_request",
            "rule.limits must be an object",
        ));
    }
    let mut limits = BTreeMap::new();
    if let Value::Object(entries) = raw {
        for (name, value) in entries {
            let parsed = as_u64(value).ok_or_else(|| {
                IdentityError::new("invalid_request", "rule.limits values must be integers")
            })?;
            limits.insert(name.clone(), parsed);
        }
    }
    Ok(Some(limits))
}

/// Evaluate a verified policy against one request (§25.8.3).
pub fn admit(
    policy: &VerifiedPolicy,
    request: &AdmissionRequest,
    revoked: Option<&HashSet<String>>,
) -> AdmissionResult {
    if request.now > policy.expires_at {
        return AdmissionResult::new("deny", "policy_expired");
    }
    if !ADMITTABLE_RISK.contains(&request.risk.as_str()) {
        return AdmissionResult::new("deny", "risk_not_admittable");
    }

    for rule in &policy.rules {
        if request.now > rule.expires_at {
            continue;
        }
        if !rule.intents.contains(&request.intent) {
            continue;
        }
        if rule.risk != request.risk {
            continue;
        }
        if let Some(contacts) = &rule.contacts {
            if !contacts.contains(&request.contact_id) {
                continue;
            }
        }
        if let Some(requesters) = &rule.requesters {
            if !requesters.contains(&request.requester_key) {
                continue;
            }
        }
        if rule.risk == "disclose" {
            let matches = match (&request.destination, &rule.destinations) {
                (Some(destination), Some(destinations)) => destinations.contains(destination),
                _ => false,
            };
            if !matches {
                continue;
            }
        }
        if let Some(revoked) = revoked {
            if revoked.contains(&admitted_grant_id(policy, &rule.id, request)) {
                return AdmissionResult::with_rule("deny", "grant_revoked", rule.id.clone());
            }
        }
        return AdmissionResult::with_rule("allow", "rule_matched", rule.id.clone());
    }

    if policy.default == "deny" {
        AdmissionResult::new("deny", "default_deny")
    } else {
        AdmissionResult::new("confirm", "default_confirm")
    }
}

/// The grant record a match may create, or `None` if not admitted.
pub fn admitted_grant(
    policy: &VerifiedPolicy,
    request: &AdmissionRequest,
    result: &AdmissionResult,
) -> Option<AdmittedGrant> {
    if result.decision != "allow" {
        return None;
    }
    let rule_id = result.rule_id.as_ref()?;
    let rule = policy.rules.iter().find(|entry| &entry.id == rule_id)?;
    let expires_at = if rule.expires_at < policy.expires_at {
        rule.expires_at.clone()
    } else {
        policy.expires_at.clone()
    };
    Some(AdmittedGrant {
        id: admitted_grant_id(policy, &rule.id, request),
        intent: request.intent.clone(),
        limits: rule.limits.clone().unwrap_or_default(),
        expires_at,
    })
}

/// Deterministic grant id for a policy rule and requester (§25.8.3).
pub fn admitted_grant_id(
    policy: &VerifiedPolicy,
    rule_id: &str,
    request: &AdmissionRequest,
) -> String {
    let material = object(vec![
        ("intent", Value::Str(request.intent.clone())),
        ("policy", Value::Str(policy.digest.clone())),
        ("requester", Value::Str(request.requester_key.clone())),
        ("rule", Value::Str(rule_id.to_string())),
    ]);
    let serialized = serialize(&material).expect("canonical object");
    let digest = crypto::sha256_hex(serialized.as_bytes());
    format!("pg-{}", &digest[..32])
}

fn assert_label(obj: &Value) -> Result<(), IdentityError> {
    let label = read_string(obj, "ccp", "document")?;
    if !SUPPORTED_LABELS.contains(&label.as_str()) {
        return Err(IdentityError::new(
            "invalid_request",
            "unsupported ccp label",
        ));
    }
    Ok(())
}

fn assert_key_id(identity: &str) -> Result<(), IdentityError> {
    public_bytes_from_key_id(identity)
        .map(|_| ())
        .map_err(|_| IdentityError::new("invalid_request", "identity is not a key id"))
}

fn assert_signature(obj: &Value, identity: &str) -> Result<(), IdentityError> {
    let signature = obj
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| IdentityError::new("invalid_request", "signature is required"))?;
    if !signature.starts_with(crypto::SIG_PREFIX) {
        return Err(IdentityError::new(
            "invalid_request",
            "signature is required",
        ));
    }
    let public_key = public_bytes_from_key_id(identity)
        .map_err(|_| IdentityError::new("invalid_request", "identity is not a key id"))?;
    let bytes = signing_bytes(obj).map_err(|error| IdentityError::new("invalid_request", error))?;
    if !verify_signature(&public_key, &bytes, signature) {
        return Err(IdentityError::new(
            "unauthenticated",
            "signature is invalid",
        ));
    }
    Ok(())
}

fn read_string(obj: &Value, key: &str, what: &str) -> Result<String, IdentityError> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| IdentityError::new("invalid_request", format!("{what}.{key} is required")))
}

fn optional_string(obj: &Value, key: &str, what: &str) -> Result<Option<String>, IdentityError> {
    if obj.get(key).is_none() {
        return Ok(None);
    }
    read_string(obj, key, what).map(Some)
}

fn read_string_array(obj: &Value, key: &str, what: &str) -> Result<Vec<String>, IdentityError> {
    let value = obj.get(key).ok_or_else(|| {
        IdentityError::new("invalid_request", format!("{what}.{key} is required"))
    })?;
    let items = value
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or_else(|| {
            IdentityError::new("invalid_request", format!("{what}.{key} is required"))
        })?;
    let mut strings = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                IdentityError::new(
                    "invalid_request",
                    format!("{what}.{key} must contain non-empty strings"),
                )
            })?;
        strings.push(text.to_string());
    }
    Ok(strings)
}

fn optional_string_array(
    obj: &Value,
    key: &str,
    what: &str,
) -> Result<Option<Vec<String>>, IdentityError> {
    if obj.get(key).is_none() {
        return Ok(None);
    }
    read_string_array(obj, key, what).map(Some)
}

fn read_timestamp(obj: &Value, key: &str, what: &str) -> Result<String, IdentityError> {
    let value = read_string(obj, key, what)?;
    if !is_timestamp(&value) {
        return Err(IdentityError::new(
            "invalid_request",
            format!("{what}.{key} must be RFC 3339 UTC with second precision"),
        ));
    }
    Ok(value)
}

fn assert_digest(value: &Option<String>, field: &str) -> Result<(), IdentityError> {
    let Some(value) = value else {
        return Ok(());
    };
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !valid {
        return Err(IdentityError::new(
            "invalid_request",
            format!("{field} is not a digest"),
        ));
    }
    Ok(())
}
