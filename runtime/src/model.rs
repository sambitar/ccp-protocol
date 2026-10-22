//! Runtime records and role-facing result types.

use std::collections::BTreeMap;

use ccp_kernel::Value;

use crate::util::{array, object, object_owned, optional_text, string_array, uint};

/// A local grant record (§9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub requester_key: String,
    pub contact_id: String,
    pub manifest_digest: String,
    pub manifest_version: u64,
    pub intents: Vec<String>,
    pub limits: BTreeMap<String, u64>,
    pub created_at: String,
    pub expires_at: String,
    pub confirmation: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub placement: Vec<String>,
    pub egress: Value,
    pub state: String,
    pub state_reason: Option<String>,
}

impl Grant {
    /// The value shape the kernel's §10.3 decision consumes.
    pub fn to_value(&self) -> Value {
        let limits = object_owned(
            self.limits
                .iter()
                .map(|(name, value)| (name.clone(), uint(*value)))
                .collect(),
        );
        let confirmation = object_owned(
            self.confirmation
                .iter()
                .map(|(name, policy)| (name.clone(), Value::Str(policy.clone())))
                .collect(),
        );
        object(vec![
            ("id", Value::Str(self.id.clone())),
            ("requester_key", Value::Str(self.requester_key.clone())),
            ("contact_id", Value::Str(self.contact_id.clone())),
            ("manifest_digest", Value::Str(self.manifest_digest.clone())),
            ("manifest_version", uint(self.manifest_version)),
            ("intents", string_array(&self.intents)),
            ("limits", limits),
            ("created_at", Value::Str(self.created_at.clone())),
            ("expires_at", Value::Str(self.expires_at.clone())),
            ("confirmation", confirmation),
            ("capabilities", string_array(&self.capabilities)),
            ("placement", string_array(&self.placement)),
            ("egress", self.egress.clone()),
            ("state", Value::Str(self.state.clone())),
            ("state_reason", optional_text(&self.state_reason)),
        ])
    }
}

/// The outcome of one submission or confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub outcome: String,
    pub request_id: Option<String>,
    pub pending_id: Option<String>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub detail: Option<String>,
    pub state: Option<String>,
}

impl Decision {
    pub fn new(outcome: impl Into<String>) -> Self {
        Self {
            outcome: outcome.into(),
            request_id: None,
            pending_id: None,
            result: None,
            error: None,
            detail: None,
            state: None,
        }
    }

    pub fn authorized(request_id: impl Into<String>, result: Value) -> Self {
        let mut decision = Self::new("authorized");
        decision.request_id = Some(request_id.into());
        decision.result = Some(result);
        decision.state = Some("completed".into());
        decision
    }

    pub fn confirmation(request_id: impl Into<String>, pending_id: impl Into<String>) -> Self {
        let mut decision = Self::new("confirmation_required");
        decision.request_id = Some(request_id.into());
        decision.pending_id = Some(pending_id.into());
        decision.state = Some("awaiting_confirmation".into());
        decision
    }

    pub fn cancelled(request_id: impl Into<String>) -> Self {
        let mut decision = Self::new("cancelled");
        decision.request_id = Some(request_id.into());
        decision.state = Some("cancelled".into());
        decision
    }

    pub fn execution_failed(request_id: impl Into<String>, detail: impl Into<String>) -> Self {
        let mut decision = Self::new("execution_failed");
        decision.request_id = Some(request_id.into());
        decision.error = Some("execution_failed".into());
        decision.detail = Some(detail.into());
        decision.state = Some("failed".into());
        decision
    }

    pub fn rejection(
        code: impl Into<String>,
        request_id: Option<String>,
        detail: Option<String>,
    ) -> Self {
        let code = code.into();
        let mut decision = Self::new(code.clone());
        decision.request_id = request_id;
        decision.error = Some(code);
        decision.detail = detail;
        decision
    }
}

/// A confirmation awaiting a trusted decision (§9.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRequest {
    pub id: String,
    pub signal: Value,
    pub grant: Grant,
    pub intent_spec: Value,
    pub state: String,
}

/// A parsed and verified provider manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManifest {
    pub document: String,
    pub manifest: Value,
    pub digest: String,
    pub provider_id: String,
}

/// A parsed and verified signal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSignal {
    pub document: String,
    pub signal: Value,
}

/// The plain-language permission card (§11.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionCard {
    pub who: String,
    pub what: String,
    pub data_read: Vec<String>,
    pub where_: String,
    pub egress: String,
    pub effects: String,
    pub recurrence: String,
    pub revoke: String,
}

/// One transport endpoint advertised by an identity document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub transport: String,
    pub manifest: Option<String>,
    pub signal: Option<String>,
}

/// A verified identity document (§25.8.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub document: String,
    pub identity: String,
    pub issued_at: String,
    pub expires_at: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    pub endpoints: Vec<Endpoint>,
    pub manifest_digest: Option<String>,
    pub policy_digest: Option<String>,
}

/// One rule in an admission policy (§25.8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRule {
    pub id: String,
    pub intents: Vec<String>,
    pub risk: String,
    pub confirmation: String,
    pub expires_at: String,
    pub contacts: Option<Vec<String>>,
    pub requesters: Option<Vec<String>>,
    pub destinations: Option<Vec<String>>,
    pub limits: Option<BTreeMap<String, u64>>,
}

/// A verified admission policy (§25.8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPolicy {
    pub document: String,
    pub host: String,
    pub version: u64,
    pub default: String,
    pub rules: Vec<PolicyRule>,
    pub issued_at: String,
    pub expires_at: String,
    pub digest: String,
}

/// One request evaluated against an admission policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub requester_key: String,
    pub contact_id: String,
    pub intent: String,
    pub risk: String,
    pub now: String,
    pub destination: Option<String>,
}

/// The policy's answer. `allow` still needs a grant record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionResult {
    pub decision: String,
    pub reason: String,
    pub rule_id: Option<String>,
}

impl AdmissionResult {
    pub fn new(decision: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: decision.into(),
            reason: reason.into(),
            rule_id: None,
        }
    }

    pub fn with_rule(
        decision: impl Into<String>,
        reason: impl Into<String>,
        rule_id: impl Into<String>,
    ) -> Self {
        Self {
            decision: decision.into(),
            reason: reason.into(),
            rule_id: Some(rule_id.into()),
        }
    }
}

/// The grant a matched rule may create.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedGrant {
    pub id: String,
    pub intent: String,
    pub limits: BTreeMap<String, u64>,
    pub expires_at: String,
}

/// The result of `Runtime::admit_request`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmitRequestResult {
    pub result: AdmissionResult,
    pub grant: Option<Grant>,
}

/// Options for `Runtime::verify_contact_identity`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyContactOptions {
    pub contact_id: String,
    pub now: Option<String>,
    pub expected_identity: Option<String>,
    pub manifest_digest: Option<String>,
    pub policy_digest: Option<String>,
}

/// The array-of-strings helper is used by callers building manifests.
pub fn strings_value(items: &[String]) -> Value {
    array(items.iter().cloned().map(Value::Str).collect())
}
