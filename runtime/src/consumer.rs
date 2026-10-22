//! Consumer role: verify inbound documents and build permission cards.

use ccp_kernel::Value;

use crate::errors::CcpError;
use crate::model::{PermissionCard, VerifiedManifest, VerifiedSignal};
use crate::util::{
    document_digest, parse, public_bytes_from_key_id, signing_bytes, string_list, verify_signature,
};

const SIGNAL_FIELDS: [&str; 8] = [
    "ccp",
    "request_id",
    "grant_digest",
    "intent",
    "params",
    "issued_at",
    "expires_at",
    "signature",
];

/// Parse and verify a signed manifest (§8).
pub fn verify_manifest(
    document: &str,
    expected_provider_id: Option<&str>,
) -> Result<VerifiedManifest, CcpError> {
    let manifest = parse(document).map_err(|error| CcpError::new("invalid_request", error))?;
    if !matches!(manifest, Value::Object(_)) {
        return Err(CcpError::new(
            "invalid_request",
            "manifest must be an object",
        ));
    }
    let provider_id = manifest
        .get("provider")
        .and_then(|provider| provider.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| CcpError::new("invalid_request", "manifest provider.id is required"))?
        .to_string();
    if let Some(expected) = expected_provider_id {
        if provider_id != expected {
            return Err(CcpError::new(
                "unauthenticated",
                "provider id does not match",
            ));
        }
    }
    let signature = manifest
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| CcpError::new("invalid_request", "manifest signature is required"))?;
    let public_key = public_bytes_from_key_id(&provider_id)
        .map_err(|_| CcpError::new("invalid_request", "provider.id is not an Ed25519 key id"))?;
    let bytes =
        signing_bytes(&manifest).map_err(|error| CcpError::new("invalid_request", error))?;
    if !verify_signature(&public_key, &bytes, signature) {
        return Err(CcpError::new(
            "unauthenticated",
            "manifest signature is invalid",
        ));
    }
    let digest =
        document_digest(&manifest).map_err(|error| CcpError::new("invalid_request", error))?;
    Ok(VerifiedManifest {
        document: document.to_string(),
        manifest,
        digest,
        provider_id,
    })
}

/// Parse and verify a signed signal (§10.1) against the transport-bound key.
pub fn verify_signal(document: &str, public_key: &[u8; 32]) -> Result<VerifiedSignal, CcpError> {
    let signal = parse(document).map_err(|error| CcpError::new("invalid_request", error))?;
    if !matches!(signal, Value::Object(_)) {
        return Err(CcpError::new("invalid_request", "signal must be an object"));
    }
    for field in SIGNAL_FIELDS {
        if signal.get(field).is_none() {
            return Err(CcpError::new(
                "invalid_request",
                format!("signal missing {field}"),
            ));
        }
    }
    let signature = signal
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| CcpError::new("invalid_request", "signal signature is required"))?;
    let bytes = signing_bytes(&signal).map_err(|error| CcpError::new("invalid_request", error))?;
    if !verify_signature(public_key, &bytes, signature) {
        return Err(CcpError::new(
            "unauthenticated",
            "signal signature is invalid",
        ));
    }
    Ok(VerifiedSignal {
        document: document.to_string(),
        signal,
    })
}

/// Options for a permission card.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PermissionCardOptions {
    pub provider_name: Option<String>,
    pub data_read: Option<Vec<String>>,
    pub where_: Option<String>,
    pub effects: Option<String>,
    pub future: bool,
    pub revoke: Option<String>,
}

/// Build the plain-language permission card for an intent (§11.4).
pub fn permission_card(
    manifest: &Value,
    intent: &str,
    options: &PermissionCardOptions,
) -> Result<PermissionCard, CcpError> {
    let definition = manifest
        .get("intents")
        .and_then(|intents| intents.get(intent))
        .ok_or_else(|| CcpError::new("intent_not_allowed", format!("unknown intent {intent}")))?;
    let provider = manifest.get("provider");
    let who = options
        .provider_name
        .clone()
        .or_else(|| {
            provider
                .and_then(|value| value.get("name"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .or_else(|| {
            provider
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());

    let placement = definition
        .get("placement")
        .and_then(Value::as_str)
        .unwrap_or("local");
    let egress_spec = definition.get("data_egress");
    let network = egress_spec
        .and_then(|value| value.get("network"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fields = egress_spec
        .and_then(|value| value.get("fields"))
        .and_then(string_list)
        .unwrap_or_default();

    let data_read = options.data_read.clone().unwrap_or_else(|| {
        definition
            .get("required_capabilities")
            .and_then(string_list)
            .unwrap_or_default()
    });
    let where_ = options.where_.clone().unwrap_or_else(|| {
        if placement == "local" {
            "on this device".to_string()
        } else {
            format!("via {placement}")
        }
    });
    let egress = if network {
        let listed = if fields.is_empty() {
            "declared fields".to_string()
        } else {
            fields.join(", ")
        };
        format!("sends {listed} to a remote endpoint")
    } else {
        "does not send data off the device".to_string()
    };
    let what = definition
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or(intent)
        .to_string();

    Ok(PermissionCard {
        who,
        what,
        data_read,
        where_,
        egress,
        effects: options
            .effects
            .clone()
            .unwrap_or_else(|| "no external side effect declared".to_string()),
        recurrence: if options.future {
            "applies to future requests".to_string()
        } else {
            "applies once".to_string()
        },
        revoke: options
            .revoke
            .clone()
            .unwrap_or_else(|| "you can revoke this grant at any time".to_string()),
    })
}

/// The required capabilities declared by an intent definition.
pub fn required_capabilities(intent_spec: &Value) -> Vec<String> {
    intent_spec
        .get("required_capabilities")
        .and_then(string_list)
        .unwrap_or_default()
}
