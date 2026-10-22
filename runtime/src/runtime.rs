//! The CCP runtime: validation, confirmation, execution, lifecycle, and audit.
//!
//! A runtime owns the grant store, replay set, limit counters, pending
//! confirmations, host registry, schema registry, and audit log. It is
//! synchronous: methods take `&mut self`, and callers own concurrency.

use std::collections::{BTreeMap, HashMap, HashSet};

use ccp_kernel::decision::decide;
use ccp_kernel::schema;
use ccp_kernel::Value;
use num_bigint::BigUint;

use crate::consumer::required_capabilities;
use crate::errors::CcpError;
use crate::grants::{create_grant, CreateGrantOptions};
use crate::hosts::{EgressPolicy, HostRegistry};
use crate::identity::{admit, admitted_grant, verify_identity_document, VerifyIdentityOptions};
use crate::model::{
    AdmissionRequest, AdmissionResult, AdmitRequestResult, Decision, Grant, PendingRequest,
    VerifiedIdentity, VerifiedManifest, VerifiedPolicy,
};
use crate::stores::{AuditStore, GrantStore, LimitStore, ManifestStore, PendingStore, ReplayStore};
use crate::time::utcnow;
use crate::util::{key_id_from_seed, object_owned, random_id, string_list};

/// The reserved suspension reason for a requester key change (§7.4).
pub const IDENTITY_CHANGED_REASON: &str = "identity_changed";

/// Maps `schema:<...>` identifiers to schemas (§25.3).
#[derive(Default)]
pub struct SchemaRegistry {
    schemas: HashMap<String, Value>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: Vec<(String, Value)>) -> Self {
        let mut registry = Self::default();
        for (id, schema) in entries {
            registry.register(&id, schema);
        }
        registry
    }

    pub fn register(&mut self, id: &str, schema: Value) {
        self.schemas.insert(id.to_string(), schema);
    }

    pub fn get(&self, id: &str) -> Option<&Value> {
        self.schemas.get(id)
    }
}

pub type Clock = Box<dyn Fn() -> String + Send + Sync>;

/// Construction options. Every field has a default.
#[derive(Default)]
pub struct RuntimeOptions {
    pub grants: Option<Box<dyn GrantStore>>,
    pub manifests: Option<Box<dyn ManifestStore>>,
    pub replay: Option<Box<dyn ReplayStore>>,
    pub limits: Option<Box<dyn LimitStore>>,
    pub pending: Option<Box<dyn PendingStore>>,
    pub schemas: Option<SchemaRegistry>,
    pub hosts: Option<HostRegistry>,
    pub audit: Option<Box<dyn AuditStore>>,
    pub clock: Option<Clock>,
    pub supported_ccp: Option<Vec<String>>,
}

/// The reference runtime.
pub struct Runtime {
    pub grants: Box<dyn GrantStore>,
    pub manifests: Box<dyn ManifestStore>,
    pub replay: Box<dyn ReplayStore>,
    pub limits: Box<dyn LimitStore>,
    pub pending_store: Box<dyn PendingStore>,
    pub schemas: SchemaRegistry,
    pub hosts: HostRegistry,
    pub audit: Box<dyn AuditStore>,
    clock: Clock,
    pub supported_ccp: Vec<String>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new(RuntimeOptions::default())
    }
}

impl Runtime {
    pub fn new(options: RuntimeOptions) -> Self {
        Self {
            grants: options
                .grants
                .unwrap_or_else(|| Box::new(crate::stores::MemoryGrantStore::default())),
            manifests: options
                .manifests
                .unwrap_or_else(|| Box::new(crate::stores::MemoryManifestStore::default())),
            replay: options
                .replay
                .unwrap_or_else(|| Box::new(crate::stores::MemoryReplayStore::default())),
            limits: options
                .limits
                .unwrap_or_else(|| Box::new(crate::stores::MemoryLimitStore::default())),
            pending_store: options
                .pending
                .unwrap_or_else(|| Box::new(crate::stores::MemoryPendingStore::default())),
            schemas: options.schemas.unwrap_or_default(),
            hosts: options.hosts.unwrap_or_default(),
            audit: options
                .audit
                .unwrap_or_else(|| Box::new(crate::stores::MemoryAuditLog::default())),
            clock: options.clock.unwrap_or_else(|| Box::new(utcnow)),
            supported_ccp: options
                .supported_ccp
                .unwrap_or_else(|| vec!["0.5-draft".to_string(), "0.4-draft".to_string()]),
        }
    }

    /// Validate and act on one signed signal (§10.3).
    pub fn submit(&mut self, document: &str, public_key: &[u8; 32]) -> Decision {
        let now = (self.clock)();
        let signal = match crate::util::parse(document) {
            Ok(signal) => signal,
            Err(error) => {
                return self.reject("invalid_request", None, None, Some(error));
            }
        };
        if !matches!(signal, Value::Object(_)) {
            return self.reject(
                "invalid_request",
                None,
                None,
                Some("signal must be an object".to_string()),
            );
        }
        for field in [
            "ccp",
            "request_id",
            "grant_digest",
            "intent",
            "params",
            "issued_at",
            "expires_at",
            "signature",
        ] {
            if signal.get(field).is_none() {
                return self.reject(
                    "invalid_request",
                    signal
                        .get("request_id")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    None,
                    Some(format!("missing {field}")),
                );
            }
        }

        let request_id = signal
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let signature = signal
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or("");
        let bytes = match crate::util::signing_bytes(&signal) {
            Ok(bytes) => bytes,
            Err(error) => {
                return self.reject("invalid_request", Some(request_id), None, Some(error));
            }
        };
        if !crate::util::verify_signature(public_key, &bytes, signature) {
            return self.reject(
                "unauthenticated",
                Some(request_id),
                None,
                Some("signature mismatch".to_string()),
            );
        }

        let signer = ccp_kernel::crypto::key_id_from_public(public_key);
        let grant_digest = signal
            .get("grant_digest")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let intent = signal
            .get("intent")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let grant = self.resolve_grant(&signer, &grant_digest, &intent);

        let mut intent_spec = None;
        let mut params_schema = None;
        if let Some(grant) = &grant {
            if let Some(manifest) = self.manifests.get(&grant.manifest_digest) {
                if let Some(spec) = manifest
                    .manifest
                    .get("intents")
                    .and_then(|intents| intents.get(&intent))
                {
                    intent_spec = Some(spec.clone());
                    if let Some(schema_id) = spec.get("params_schema").and_then(Value::as_str) {
                        params_schema = self.schemas.get(schema_id).cloned();
                    }
                }
            }
        }

        let replayed = grant
            .as_ref()
            .map(|_| self.replay.has(&request_id))
            .unwrap_or(false);
        let counters = grant
            .as_ref()
            .map(|grant| self.limits.counters(&grant.id))
            .unwrap_or_default();
        let mut seen = HashSet::new();
        if replayed {
            seen.insert(request_id.clone());
        }
        let counters: HashMap<String, BigUint> = counters
            .into_iter()
            .map(|(name, value)| (name, BigUint::from(value)))
            .collect();
        let supported: Vec<&str> = self.supported_ccp.iter().map(String::as_str).collect();
        let grant_value = grant.as_ref().map(Grant::to_value);
        let outcome = decide(
            grant_value.as_ref(),
            &signal,
            &signer,
            &now,
            &seen,
            &counters,
            intent_spec.as_ref(),
            params_schema.as_ref(),
            &supported,
        );

        if outcome != "authorized" && outcome != "confirmation_required" {
            let detail = self.state_detail(&outcome, grant.as_ref());
            return self.reject(&outcome, Some(request_id), grant.as_ref(), detail);
        }

        if !self.replay.mark_if_new(&request_id) {
            return self.reject("replay_detected", Some(request_id), grant.as_ref(), None);
        }
        let Some(grant) = grant else {
            return self.reject("no_matching_grant", Some(request_id), None, None);
        };
        if !self.limits.try_reserve(&grant.id, &grant.limits) {
            return self.reject("limit_exceeded", Some(request_id), Some(&grant), None);
        }

        let spec = intent_spec.unwrap_or(Value::Null);
        let required = required_capabilities(&spec);
        let unavailable: Vec<&String> = required
            .iter()
            .filter(|capability| !self.hosts.has_host(capability))
            .collect();
        if !unavailable.is_empty() || !self.hosts.has_intent(&intent) {
            self.limits.release(&grant.id, &grant.limits);
            let detail = if unavailable.is_empty() {
                intent.clone()
            } else {
                unavailable
                    .iter()
                    .map(|value| (*value).clone())
                    .collect::<Vec<String>>()
                    .join(",")
            };
            return self.reject(
                "capability_unavailable",
                Some(request_id),
                Some(&grant),
                Some(format!("unavailable: {detail}")),
            );
        }

        if let Some(detail) = self.deployment_error(&grant, &spec, &required) {
            self.limits.release(&grant.id, &grant.limits);
            return self.reject(
                "capability_unavailable",
                Some(request_id),
                Some(&grant),
                Some(detail),
            );
        }

        if outcome == "confirmation_required" || self.host_floor(&spec) {
            let pending_id = random_id();
            self.pending_store.put(PendingRequest {
                id: pending_id.clone(),
                signal: signal.clone(),
                grant: grant.clone(),
                intent_spec: spec,
                state: "awaiting_confirmation".to_string(),
            });
            self.audit_event(
                "awaiting_confirmation",
                Some(&request_id),
                Some(&intent),
                Some(&grant.id),
                None,
                None,
            );
            return Decision::confirmation(request_id, pending_id);
        }

        self.execute(&signal, &request_id, &intent, &grant, &spec)
    }

    /// Resolve a pending confirmation (§9.5).
    pub fn confirm(&mut self, pending_id: &str, approved: bool) -> Decision {
        let Some(pending) = self.pending_store.take(pending_id) else {
            return self.reject(
                "invalid_request",
                None,
                None,
                Some("unknown pending request".to_string()),
            );
        };
        let request_id = pending
            .signal
            .get("request_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !approved {
            self.limits
                .release(&pending.grant.id, &pending.grant.limits);
            self.audit_event(
                "cancelled",
                Some(&request_id),
                None,
                Some(&pending.grant.id),
                None,
                None,
            );
            return Decision::cancelled(request_id);
        }

        // The grant may have been revoked or paused while the prompt was open
        // (§9.4.3); re-read it rather than trusting the snapshot.
        let current = self.grants.get(&pending.grant.id).unwrap_or(pending.grant);
        if let Some(state_error) = self.grant_state_error(&current, &(self.clock)()) {
            self.limits.release(&current.id, &current.limits);
            let detail = self.state_detail(&state_error, Some(&current));
            return self.reject(&state_error, Some(request_id), Some(&current), detail);
        }
        let intent = pending
            .signal
            .get("intent")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        self.execute(
            &pending.signal,
            &request_id,
            &intent,
            &current,
            &pending.intent_spec,
        )
    }

    pub fn pending(&self, pending_id: &str) -> Option<PendingRequest> {
        self.pending_store.get(pending_id)
    }

    // -- lifecycle (§9.4) ------------------------------------------------

    /// Pause one grant; configuration, limits, and history are kept.
    pub fn pause_grant(&mut self, id: &str, reason: Option<&str>) -> Result<Grant, CcpError> {
        self.transition(id, "paused", reason)
    }

    /// Suspend one grant pending a security or identity check.
    pub fn suspend_grant(&mut self, id: &str, reason: Option<&str>) -> Result<Grant, CcpError> {
        self.transition(id, "suspended", reason)
    }

    /// Revoke one grant permanently (§9.4.4).
    pub fn revoke_grant(&mut self, id: &str, reason: Option<&str>) -> Result<Grant, CcpError> {
        self.transition(id, "revoked", reason)
    }

    /// Resume a paused or suspended grant (§9.4.3).
    pub fn resume_grant(&mut self, id: &str) -> Result<Grant, CcpError> {
        let grant = self
            .grants
            .get(id)
            .ok_or_else(|| CcpError::new("no_matching_grant", format!("unknown grant: {id}")))?;
        if grant.state == "revoked" {
            return Err(CcpError::new(
                "grant_revoked",
                "a revoked grant cannot be resumed",
            ));
        }
        if grant.state == "suspended"
            && grant.state_reason.as_deref() == Some(IDENTITY_CHANGED_REASON)
        {
            return Err(CcpError::new(
                "grant_suspended",
                "identity changed; re-introduce the contact and create a new grant",
            ));
        }
        if grant.state == "expired" || (self.clock)() >= grant.expires_at {
            return Err(CcpError::new(
                "grant_expired",
                "an expired grant cannot be resumed",
            ));
        }
        if self.manifests.get(&grant.manifest_digest).is_none() {
            return Err(CcpError::new(
                "capability_unavailable",
                "the approved manifest is no longer stored",
            ));
        }
        if grant.state == "active" {
            return Ok(grant);
        }
        self.set_state(grant, "active", None)
    }

    /// Suspend every non-revoked grant bound to a contact (§7.4).
    pub fn suspend_contact(&mut self, contact_id: &str, reason: Option<&str>) -> usize {
        let affected: Vec<Grant> = self
            .grants
            .all()
            .into_iter()
            .filter(|grant| grant.contact_id == contact_id && grant.state != "revoked")
            .collect();
        let reason = reason.unwrap_or("contact suspended");
        for grant in &affected {
            let _ = self.set_state(grant.clone(), "suspended", Some(reason));
        }
        affected.len()
    }

    /// Verify an identity document for a known contact (§7.4, §25.8.4).
    ///
    /// On `identity_changed` — a valid signature from a different key — the
    /// contact's grants are suspended before the error is returned. A bad
    /// signature never suspends anything.
    pub fn verify_contact_identity(
        &mut self,
        document: &str,
        options: &crate::model::VerifyContactOptions,
    ) -> Result<VerifiedIdentity, crate::errors::IdentityError> {
        let verify_options = VerifyIdentityOptions {
            now: options.now.clone(),
            expected_identity: options.expected_identity.clone(),
            manifest_digest: options.manifest_digest.clone(),
            policy_digest: options.policy_digest.clone(),
        };
        match verify_identity_document(document, &verify_options) {
            Ok(identity) => Ok(identity),
            Err(error) => {
                if error.code == "identity_changed" {
                    let suspended =
                        self.suspend_contact(&options.contact_id, Some(IDENTITY_CHANGED_REASON));
                    self.audit_event(
                        "identity_changed",
                        None,
                        None,
                        None,
                        None,
                        Some(&format!("{suspended} grant(s) suspended")),
                    );
                }
                Err(error)
            }
        }
    }

    /// Admit a request under a reviewed policy (§25.8.3).
    pub fn admit_request(
        &mut self,
        policy: &VerifiedPolicy,
        request: &AdmissionRequest,
        manifest: &VerifiedManifest,
    ) -> AdmitRequestResult {
        let revoked: HashSet<String> = self
            .grants
            .all()
            .into_iter()
            .filter(|grant| grant.state == "revoked")
            .map(|grant| grant.id)
            .collect();
        let result = admit(policy, request, Some(&revoked));
        if result.decision != "allow" {
            return AdmitRequestResult {
                result,
                grant: None,
            };
        }
        let Some(granted) = admitted_grant(policy, request, &result) else {
            return AdmitRequestResult {
                result,
                grant: None,
            };
        };

        // A policy may never admit an intent whose hosts require a human.
        let intent_spec = manifest
            .manifest
            .get("intents")
            .and_then(|intents| intents.get(&granted.intent));
        let capabilities = intent_spec.map(required_capabilities).unwrap_or_default();
        for capability in &capabilities {
            let Some(meta) = self.hosts.host_meta(capability) else {
                return AdmitRequestResult {
                    result: AdmissionResult::new("deny", "capability_unavailable"),
                    grant: None,
                };
            };
            if meta.profile.min_confirmation != "none" {
                return AdmitRequestResult {
                    result: AdmissionResult::new("deny", "risk_not_admittable"),
                    grant: None,
                };
            }
        }

        if let Some(existing) = self.grants.get(&granted.id) {
            return AdmitRequestResult {
                result,
                grant: Some(existing),
            };
        }

        let mut confirmation = BTreeMap::new();
        confirmation.insert(granted.intent.clone(), "none".to_string());
        let created = create_grant(CreateGrantOptions {
            id: Some(granted.id.clone()),
            contact_id: request.contact_id.clone(),
            requester_key: request.requester_key.clone(),
            manifest: manifest.clone().into(),
            intents: vec![granted.intent.clone()],
            limits: Some(granted.limits.clone()),
            confirmation: Some(confirmation),
            capabilities: None,
            placement: None,
            egress: None,
            created_at: Some((self.clock)()),
            expires_at: granted.expires_at,
            state: None,
            state_reason: None,
            admitted_by: result.rule_id.clone(),
        });
        let grant = match created {
            Ok(grant) => grant,
            Err(error) => {
                // The task-level API returns a decision, not a Result. A
                // grant that cannot be built is a deny, never a partial grant.
                return AdmitRequestResult {
                    result: AdmissionResult::new("deny", error.code),
                    grant: None,
                };
            }
        };
        self.grants.add(grant.clone());
        self.manifests.add(manifest.clone());
        self.audit.append(object_owned(vec![
            ("at".to_string(), Value::Str((self.clock)())),
            ("event".to_string(), Value::Str("admitted".to_string())),
            ("grant_id".to_string(), Value::Str(grant.id.clone())),
            ("intent".to_string(), Value::Str(granted.intent.clone())),
            (
                "rule_id".to_string(),
                Value::Str(result.rule_id.clone().unwrap_or_default()),
            ),
        ]));
        AdmitRequestResult {
            result,
            grant: Some(grant),
        }
    }

    // -- internals -------------------------------------------------------

    fn execute(
        &mut self,
        signal: &Value,
        request_id: &str,
        intent: &str,
        grant: &Grant,
        intent_spec: &Value,
    ) -> Decision {
        self.audit_event(
            "executing",
            Some(request_id),
            Some(intent),
            Some(&grant.id),
            None,
            None,
        );
        let Some(executor) = self.hosts.intent(intent) else {
            self.limits.release(&grant.id, &grant.limits);
            return Decision::execution_failed(request_id, "intent not installed");
        };
        let params = signal.get("params").cloned().unwrap_or(Value::Null);
        let execution = {
            let access = self
                .hosts
                .access(&grant.capabilities, self.egress_policy(grant));
            executor(&params, &access)
        };
        let result = match execution {
            Ok(result) => result,
            Err(error) => {
                self.limits.release(&grant.id, &grant.limits);
                self.audit_event(
                    "failed",
                    Some(request_id),
                    None,
                    Some(&grant.id),
                    None,
                    Some(&error),
                );
                return Decision::execution_failed(request_id, error);
            }
        };

        if let Some(result_schema) = intent_spec
            .get("result_schema")
            .and_then(Value::as_str)
            .and_then(|schema_id| self.schemas.get(schema_id))
            .cloned()
        {
            if !schema::is_valid(&result, &result_schema) {
                self.limits.release(&grant.id, &grant.limits);
                self.audit_event(
                    "failed",
                    Some(request_id),
                    None,
                    Some(&grant.id),
                    None,
                    Some("invalid result"),
                );
                return Decision::execution_failed(request_id, "invalid result");
            }
        }

        self.audit_event(
            "completed",
            Some(request_id),
            None,
            Some(&grant.id),
            None,
            None,
        );
        Decision::authorized(request_id, result)
    }

    fn resolve_grant(
        &self,
        requester_key: &str,
        manifest_digest: &str,
        intent: &str,
    ) -> Option<Grant> {
        let found = self.grants.find(requester_key, manifest_digest);
        if let Some(entry) = &found {
            if entry.intents.iter().any(|value| value == intent) {
                return Some(entry.clone());
            }
        }

        let candidates: Vec<Grant> = self
            .grants
            .all()
            .into_iter()
            .filter(|grant| {
                grant.requester_key == requester_key
                    && grant.manifest_digest == manifest_digest
                    && grant.intents.iter().any(|value| value == intent)
            })
            .collect();
        if candidates.is_empty() {
            return found;
        }
        candidates
            .iter()
            .find(|grant| grant.state == "active")
            .cloned()
            .or_else(|| candidates.first().cloned())
    }

    fn transition(
        &mut self,
        id: &str,
        state: &str,
        reason: Option<&str>,
    ) -> Result<Grant, CcpError> {
        let grant = self
            .grants
            .get(id)
            .ok_or_else(|| CcpError::new("no_matching_grant", format!("unknown grant: {id}")))?;
        if grant.state == "revoked" && state != "revoked" {
            return Err(CcpError::new("grant_revoked", "a revoked grant is final"));
        }
        self.set_state(grant, state, reason)
    }

    fn set_state(
        &mut self,
        mut grant: Grant,
        state: &str,
        reason: Option<&str>,
    ) -> Result<Grant, CcpError> {
        grant.state = state.to_string();
        let previous_reason = grant.state_reason.clone();
        grant.state_reason = if state == "active" {
            None
        } else {
            reason.map(str::to_string).or(previous_reason)
        };
        self.grants.add(grant.clone());
        let event = if state == "active" { "resumed" } else { state };
        self.audit_event(event, None, None, Some(&grant.id), None, reason);
        Ok(grant)
    }

    fn deployment_error(
        &self,
        grant: &Grant,
        intent_spec: &Value,
        required: &[String],
    ) -> Option<String> {
        let placement = intent_spec
            .get("placement")
            .and_then(Value::as_str)
            .unwrap_or("local");
        if !grant.placement.iter().any(|value| value == placement) {
            return Some(format!("placement {placement} is not granted"));
        }

        let policy = self.egress_policy(grant);
        for capability in required {
            let Some(meta) = self.hosts.host_meta(capability) else {
                return Some(format!("host {capability} is not installed"));
            };
            if !meta
                .profile
                .placement
                .iter()
                .any(|value| value == placement)
            {
                return Some(format!(
                    "host {capability} cannot run with {placement} placement"
                ));
            }
            if meta.profile.network && !policy.network {
                return Some(format!(
                    "host {capability} requires network egress not granted"
                ));
            }
            for field in &meta.profile.fields {
                if !policy.fields.contains(field) {
                    return Some(format!(
                        "host {capability} may send undeclared field {field}"
                    ));
                }
            }
        }
        None
    }

    fn host_floor(&self, intent_spec: &Value) -> bool {
        required_capabilities(intent_spec).iter().any(|capability| {
            self.hosts
                .host_meta(capability)
                .map(|meta| meta.profile.min_confirmation != "none")
                .unwrap_or(false)
        })
    }

    fn egress_policy(&self, grant: &Grant) -> EgressPolicy {
        let network = grant
            .egress
            .get("network")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let fields = grant
            .egress
            .get("fields")
            .and_then(string_list)
            .unwrap_or_default();
        EgressPolicy::new(network, fields)
    }

    fn grant_state_error(&self, grant: &Grant, now: &str) -> Option<String> {
        if grant.state == "revoked" {
            return Some("grant_revoked".to_string());
        }
        if grant.state == "paused" {
            return Some("grant_paused".to_string());
        }
        if grant.state == "suspended" {
            return Some("grant_suspended".to_string());
        }
        if grant.state == "expired" || now >= grant.expires_at.as_str() {
            return Some("grant_expired".to_string());
        }
        None
    }

    fn state_detail(&self, outcome: &str, grant: Option<&Grant>) -> Option<String> {
        let grant = grant?;
        if outcome == "grant_revoked" || outcome == "grant_paused" || outcome == "grant_suspended" {
            return grant.state_reason.clone();
        }
        None
    }

    fn reject(
        &mut self,
        code: &str,
        request_id: Option<String>,
        grant: Option<&Grant>,
        detail: Option<String>,
    ) -> Decision {
        self.audit_event(
            "rejected",
            request_id.as_deref(),
            None,
            grant.map(|grant| grant.id.as_str()),
            Some(code),
            detail.as_deref(),
        );
        Decision::rejection(code, request_id, detail)
    }

    fn audit_event(
        &mut self,
        event: &str,
        request_id: Option<&str>,
        intent: Option<&str>,
        grant_id: Option<&str>,
        code: Option<&str>,
        detail: Option<&str>,
    ) {
        let mut entries = vec![
            ("at".to_string(), Value::Str((self.clock)())),
            ("event".to_string(), Value::Str(event.to_string())),
        ];
        if let Some(request_id) = request_id {
            entries.push(("request_id".to_string(), Value::Str(request_id.to_string())));
        }
        if let Some(intent) = intent {
            entries.push(("intent".to_string(), Value::Str(intent.to_string())));
        }
        if let Some(grant_id) = grant_id {
            entries.push(("grant_id".to_string(), Value::Str(grant_id.to_string())));
        }
        if let Some(code) = code {
            entries.push(("code".to_string(), Value::Str(code.to_string())));
        }
        if let Some(detail) = detail {
            entries.push(("detail".to_string(), Value::Str(detail.to_string())));
        }
        self.audit.append(object_owned(entries));
    }
}

/// A convenience helper for tests and examples: the public key for a seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    crate::util::public_from_seed(seed)
}

/// A convenience helper for tests and examples: the key id for a seed.
pub fn key_id(seed: &[u8; 32]) -> String {
    key_id_from_seed(seed).expect("32-byte seed")
}
