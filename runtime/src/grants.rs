//! Least-authority grant construction (§9.1, §9.2, §26.1).
//!
//! The helper only narrows what a manifest declares: limits cannot exceed the
//! suggested ceilings, confirmation cannot be relaxed to `none` unless an
//! admission policy admitted the grant, and capabilities, placement, and
//! egress are derived from the approved intents.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ccp_kernel::Value;

use crate::consumer::verify_manifest;
use crate::errors::CcpError;
use crate::model::{Grant, VerifiedManifest};
use crate::time::{is_timestamp, utcnow};
use crate::util::{as_u64, object_owned, public_bytes_from_key_id, random_id, string_array};

/// The approved manifest, either already verified or as signed wire text.
#[derive(Clone, Debug)]
pub enum ManifestSource {
    Verified(VerifiedManifest),
    Document(String),
}

impl From<VerifiedManifest> for ManifestSource {
    fn from(manifest: VerifiedManifest) -> Self {
        Self::Verified(manifest)
    }
}

impl From<String> for ManifestSource {
    fn from(document: String) -> Self {
        Self::Document(document)
    }
}

impl From<&str> for ManifestSource {
    fn from(document: &str) -> Self {
        Self::Document(document.to_string())
    }
}

/// Options for [`create_grant`].
#[derive(Clone, Debug)]
pub struct CreateGrantOptions {
    /// Opaque local id. Defaults to a random 128-bit hex id.
    pub id: Option<String>,
    /// Local contact reference; never sent to the provider.
    pub contact_id: String,
    /// `key:ed25519:<base64url>` of the approved requester.
    pub requester_key: String,
    /// Signed manifest wire or an already-verified manifest.
    pub manifest: ManifestSource,
    /// Intents the user approved. Each must exist in the manifest.
    pub intents: Vec<String>,
    /// Consumer-selected ceilings; cannot exceed the manifest suggestion.
    pub limits: Option<BTreeMap<String, u64>>,
    /// Per-intent confirmation policy.
    pub confirmation: Option<BTreeMap<String, String>>,
    /// Host capabilities. Defaults to the union required by the intents.
    pub capabilities: Option<Vec<String>>,
    /// Allowed placement. Defaults to the union declared by the intents.
    pub placement: Option<Vec<String>>,
    /// Data-egress policy. Defaults to the union declared by the intents.
    pub egress: Option<Value>,
    /// RFC 3339 UTC, second precision. Defaults to now.
    pub created_at: Option<String>,
    /// Must be after `created_at`.
    pub expires_at: String,
    pub state: Option<String>,
    pub state_reason: Option<String>,
    /// Rule id that admitted this grant under an admission policy (§25.8.3).
    pub admitted_by: Option<String>,
}

const GRANT_STATES: [&str; 5] = ["active", "paused", "suspended", "revoked", "expired"];
const CONFIRMATION_POLICIES: [&str; 2] = ["none", "per_action"];

/// Build a least-authority grant from an approved manifest and intent list.
pub fn create_grant(options: CreateGrantOptions) -> Result<Grant, CcpError> {
    let verified = match options.manifest {
        ManifestSource::Verified(manifest) => manifest,
        ManifestSource::Document(document) => verify_manifest(&document, None)?,
    };

    if options.intents.is_empty() {
        return Err(CcpError::new(
            "invalid_request",
            "grant must enable at least one intent",
        ));
    }
    let mut seen_intents = HashSet::new();
    let intents: Vec<String> = options
        .intents
        .iter()
        .filter(|intent| seen_intents.insert((*intent).clone()))
        .cloned()
        .collect();
    let mut definitions = Vec::with_capacity(intents.len());
    for intent in &intents {
        let definition = verified
            .manifest
            .get("intents")
            .and_then(|value| value.get(intent))
            .ok_or_else(|| {
                CcpError::new(
                    "intent_not_allowed",
                    format!("intent {intent} is not in the manifest"),
                )
            })?;
        definitions.push(definition);
    }

    assert_requester_key(&options.requester_key)?;
    if options.contact_id.is_empty() {
        return Err(CcpError::new("invalid_request", "contactId is required"));
    }

    let version = verified
        .manifest
        .get("version")
        .and_then(as_u64)
        .ok_or_else(|| CcpError::new("invalid_request", "manifest version must be an integer"))?;

    let created_at = options.created_at.unwrap_or_else(utcnow);
    assert_timestamp(&created_at, "createdAt")?;
    assert_timestamp(&options.expires_at, "expiresAt")?;
    if options.expires_at <= created_at {
        return Err(CcpError::new(
            "invalid_request",
            "expiresAt must be after createdAt",
        ));
    }

    let limits = resolve_limits(&definitions, options.limits.as_ref())?;
    let confirmation = resolve_confirmation(
        &intents,
        &definitions,
        options.confirmation.as_ref(),
        options.admitted_by.as_deref(),
    )?;
    let capabilities = resolve_capabilities(&definitions, options.capabilities.as_ref())?;
    let placement = resolve_placement(&definitions, options.placement.as_ref())?;
    let egress = resolve_egress(&definitions, options.egress.as_ref())?;

    let state = options.state.unwrap_or_else(|| "active".to_string());
    if !GRANT_STATES.contains(&state.as_str()) {
        return Err(CcpError::new(
            "invalid_request",
            format!("unknown grant state: {state}"),
        ));
    }
    let reason = options.state_reason.filter(|value| !value.is_empty());
    if state != "active" && reason.is_none() {
        return Err(CcpError::new(
            "invalid_request",
            "stateReason is required when the grant is not active",
        ));
    }

    Ok(Grant {
        id: options.id.unwrap_or_else(random_id),
        requester_key: options.requester_key,
        contact_id: options.contact_id,
        manifest_digest: verified.digest,
        manifest_version: version,
        intents,
        limits,
        created_at,
        expires_at: options.expires_at,
        confirmation,
        capabilities,
        placement,
        egress,
        state,
        state_reason: reason,
    })
}

fn resolve_limits(
    definitions: &[&Value],
    requested: Option<&BTreeMap<String, u64>>,
) -> Result<BTreeMap<String, u64>, CcpError> {
    let mut suggested = BTreeMap::new();
    for definition in definitions {
        if let Some(Value::Object(entries)) = definition.get("suggested_limits") {
            for (name, raw) in entries {
                let value = as_u64(raw).ok_or_else(|| {
                    CcpError::new(
                        "invalid_request",
                        format!("limit {name} must be a non-negative integer"),
                    )
                })?;
                let entry = suggested.entry(name.clone()).or_insert(value);
                if value < *entry {
                    *entry = value;
                }
            }
        }
    }

    let mut limits = suggested.clone();
    if let Some(requested) = requested {
        for (name, value) in requested {
            if let Some(ceiling) = suggested.get(name) {
                if value > ceiling {
                    return Err(CcpError::new(
                        "invalid_request",
                        format!(
                            "limit {name} ({value}) exceeds the manifest suggestion ({ceiling})"
                        ),
                    ));
                }
            }
            limits.insert(name.clone(), *value);
        }
    }
    Ok(limits)
}

fn resolve_confirmation(
    intents: &[String],
    definitions: &[&Value],
    requested: Option<&BTreeMap<String, String>>,
    admitted_by: Option<&str>,
) -> Result<BTreeMap<String, String>, CcpError> {
    if let Some(overrides) = requested {
        for intent in overrides.keys() {
            if !intents.contains(intent) {
                return Err(CcpError::new(
                    "invalid_request",
                    format!("confirmation override for an intent that is not enabled: {intent}"),
                ));
            }
        }
    }

    let mut confirmation = BTreeMap::new();
    for (intent, definition) in intents.iter().zip(definitions.iter()) {
        let manifest_policy = definition
            .get("confirmation")
            .and_then(Value::as_str)
            .filter(|policy| CONFIRMATION_POLICIES.contains(policy))
            .unwrap_or("per_action");
        let Some(overrides) = requested else {
            confirmation.insert(intent.clone(), manifest_policy.to_string());
            continue;
        };
        let Some(override_value) = overrides.get(intent) else {
            confirmation.insert(intent.clone(), manifest_policy.to_string());
            continue;
        };
        if !CONFIRMATION_POLICIES.contains(&override_value.as_str()) {
            return Err(CcpError::new(
                "invalid_request",
                format!("unknown confirmation policy: {override_value}"),
            ));
        }
        if manifest_policy == "per_action" && override_value == "none" && admitted_by.is_none() {
            return Err(CcpError::new(
                "invalid_request",
                format!("confirmation for {intent} cannot be relaxed to none"),
            ));
        }
        confirmation.insert(intent.clone(), override_value.clone());
    }
    Ok(confirmation)
}

fn resolve_capabilities(
    definitions: &[&Value],
    requested: Option<&Vec<String>>,
) -> Result<Vec<String>, CcpError> {
    let mut required = BTreeSet::new();
    for definition in definitions {
        if let Some(capabilities) = definition
            .get("required_capabilities")
            .and_then(crate::util::string_list)
        {
            required.extend(capabilities);
        }
    }

    let Some(requested) = requested else {
        return Ok(required.into_iter().collect());
    };
    let supplied: BTreeSet<String> = requested.iter().cloned().collect();
    if let Some(missing) = required.iter().find(|entry| !supplied.contains(*entry)) {
        return Err(CcpError::new(
            "capability_unavailable",
            format!("grant is missing required capability: {missing}"),
        ));
    }
    if let Some(extra) = supplied.iter().find(|entry| !required.contains(*entry)) {
        return Err(CcpError::new(
            "invalid_request",
            format!("capability is not required by the enabled intents: {extra}"),
        ));
    }
    Ok(supplied.into_iter().collect())
}

fn resolve_placement(
    definitions: &[&Value],
    requested: Option<&Vec<String>>,
) -> Result<Vec<String>, CcpError> {
    let mut declared = BTreeSet::new();
    for definition in definitions {
        declared.insert(
            definition
                .get("placement")
                .and_then(Value::as_str)
                .unwrap_or("local")
                .to_string(),
        );
    }

    let Some(requested) = requested else {
        return Ok(declared.into_iter().collect());
    };
    if requested.is_empty() {
        return Err(CcpError::new(
            "invalid_request",
            "placement must not be empty",
        ));
    }
    for placement in requested {
        if !declared.contains(placement) {
            return Err(CcpError::new(
                "invalid_request",
                format!("placement is not declared by the enabled intents: {placement}"),
            ));
        }
    }
    let mut seen = HashSet::new();
    Ok(requested
        .iter()
        .filter(|placement| seen.insert((*placement).clone()))
        .cloned()
        .collect())
}

fn resolve_egress(definitions: &[&Value], requested: Option<&Value>) -> Result<Value, CcpError> {
    let mut network = false;
    let mut declared_fields = BTreeSet::new();
    for definition in definitions {
        let Some(egress) = definition.get("data_egress") else {
            continue;
        };
        if egress.get("network").and_then(Value::as_bool) == Some(true) {
            network = true;
        }
        if let Some(fields) = egress.get("fields").and_then(crate::util::string_list) {
            declared_fields.extend(fields);
        }
    }

    let mut entries: Vec<(String, Value)> = Vec::new();
    if let Some(requested) = requested {
        let Value::Object(requested_entries) = requested else {
            return Err(CcpError::new("invalid_request", "egress must be an object"));
        };
        if let Some(value) = requested.get("network") {
            if !matches!(value, Value::Bool(_)) {
                return Err(CcpError::new(
                    "invalid_request",
                    "egress.network must be a boolean",
                ));
            }
            if value.as_bool() == Some(true) && !network {
                return Err(CcpError::new(
                    "invalid_request",
                    "egress network is not declared by the enabled intents",
                ));
            }
        }
        if let Some(value) = requested.get("fields") {
            let fields = crate::util::string_list(value)
                .ok_or_else(|| CcpError::new("invalid_request", "egress.fields must be strings"))?;
            for field in &fields {
                if !declared_fields.contains(field) {
                    return Err(CcpError::new(
                        "invalid_request",
                        format!("egress field is not declared by the enabled intents: {field}"),
                    ));
                }
            }
        }
        entries.extend(requested_entries.iter().cloned());
    }

    let effective_network = requested
        .and_then(|value| value.get("network"))
        .and_then(Value::as_bool)
        .unwrap_or(network);
    let effective_fields = requested
        .and_then(|value| value.get("fields"))
        .and_then(crate::util::string_list)
        .unwrap_or_else(|| declared_fields.into_iter().collect());

    let mut egress = object_owned(entries);
    egress.set("network", Value::Bool(effective_network));
    egress.set("fields", string_array(&effective_fields));
    Ok(egress)
}

fn assert_requester_key(key_id: &str) -> Result<(), CcpError> {
    public_bytes_from_key_id(key_id)
        .map_err(|_| CcpError::new("invalid_request", "requesterKey is not an Ed25519 key id"))?;
    Ok(())
}

fn assert_timestamp(value: &str, name: &str) -> Result<(), CcpError> {
    if !is_timestamp(value) {
        return Err(CcpError::new(
            "invalid_request",
            format!("{name} must be an RFC 3339 UTC timestamp with second precision"),
        ));
    }
    Ok(())
}
