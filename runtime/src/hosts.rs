//! Host contracts and per-request privilege mediation (§26.4, §12).
//!
//! An intent executor receives a [`HostAccess`] proxy. The proxy exposes only
//! the host functions granted to the requester and re-checks the grant's
//! network and field ceilings on every call, so an executor cannot reach
//! authority outside the grant.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ccp_kernel::Value;

use crate::errors::HostProfileError;

/// Core hosts that may be registered without an explicit profile.
pub const CORE_HOSTS: [&str; 6] = [
    "store.read",
    "files.read",
    "files.search",
    "notify",
    "confirm",
    "audit.append",
];

const HOST_CLASSES: [&str; 5] = ["read", "write", "disclose", "control", "compute"];
const HOST_RISKS: [&str; 4] = ["read", "write", "disclose", "irreversible"];
const HOST_PLACEMENTS: [&str; 3] = ["local", "remote", "delegated"];
const IDEMPOTENCY: [&str; 4] = ["pure", "caller_key", "atomic", "none"];

/// An extension host contract. Core hosts may omit it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostProfile {
    pub class: Option<String>,
    pub risk: Option<String>,
    pub min_confirmation: Option<String>,
    pub idempotency: Option<String>,
    /// May this host send data off the device? Defaults to false.
    pub network: Option<bool>,
    /// Placements this host can serve. Defaults to `["local"]`.
    pub placement: Option<Vec<String>>,
    /// Data categories this host may transmit. Defaults to none.
    pub fields: Option<Vec<String>>,
}

/// A validated host profile with every default resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedHostProfile {
    pub class: String,
    pub risk: String,
    pub min_confirmation: String,
    pub idempotency: String,
    pub network: bool,
    pub placement: Vec<String>,
    pub fields: Vec<String>,
}

/// An installed host function and its contract.
#[derive(Clone)]
pub struct HostEntry {
    pub function: HostFunction,
    pub profile: NormalizedHostProfile,
}

pub type HostFunction = Arc<dyn Fn(&[Value]) -> Result<Value, String> + Send + Sync>;
pub type IntentExecutor =
    Arc<dyn Fn(&Value, &HostAccess<'_>) -> Result<Value, String> + Send + Sync>;

/// The grant's data-egress ceiling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressPolicy {
    pub network: bool,
    pub fields: HashSet<String>,
}

impl EgressPolicy {
    pub fn new(network: bool, fields: impl IntoIterator<Item = String>) -> Self {
        Self {
            network,
            fields: fields.into_iter().collect(),
        }
    }
}

/// Validate and normalize a host profile (§26.4).
pub fn validate_host_profile(
    name: &str,
    profile: &HostProfile,
) -> Result<NormalizedHostProfile, HostProfileError> {
    if name.is_empty() {
        return Err(HostProfileError::new("host name is required"));
    }

    let declared = profile.class.as_deref();
    let core = CORE_HOSTS.contains(&name);
    if declared.is_none() && !core {
        return Err(HostProfileError::new(format!(
            "extension host {name} requires a class"
        )));
    }
    if let Some(class) = declared {
        if !HOST_CLASSES.contains(&class) {
            return Err(HostProfileError::new(format!(
                "unknown host class: {class}"
            )));
        }
    }
    let host_class = declared.unwrap_or("read");
    let (default_risk, default_floor, default_idempotency) = match host_class {
        "read" => ("read", "none", "pure"),
        "disclose" => ("disclose", "per_action", "pure"),
        "write" => ("write", "per_action", "caller_key"),
        "control" => ("write", "per_action", "none"),
        "compute" => ("read", "per_action", "pure"),
        _ => unreachable!("validated class"),
    };

    let risk = profile.risk.as_deref().unwrap_or(default_risk);
    if !HOST_RISKS.contains(&risk) {
        return Err(HostProfileError::new(format!("unknown host risk: {risk}")));
    }

    let min_confirmation = profile.min_confirmation.as_deref().unwrap_or(default_floor);
    if min_confirmation != "none" && min_confirmation != "per_action" {
        return Err(HostProfileError::new(format!(
            "unknown confirmation floor: {min_confirmation}"
        )));
    }
    if min_confirmation == "none" {
        if host_class != "read" && host_class != "disclose" {
            return Err(HostProfileError::new(format!(
                "a {host_class} host cannot suppress confirmation"
            )));
        }
        if risk == "irreversible" {
            return Err(HostProfileError::new(
                "an irreversible host cannot suppress confirmation",
            ));
        }
    }

    let idempotency = profile
        .idempotency
        .as_deref()
        .unwrap_or(default_idempotency);
    if !IDEMPOTENCY.contains(&idempotency) {
        return Err(HostProfileError::new(format!(
            "unknown idempotency: {idempotency}"
        )));
    }

    let network = profile.network.unwrap_or(false);

    let placement = profile
        .placement
        .clone()
        .unwrap_or_else(|| vec!["local".to_string()]);
    if placement.is_empty() {
        return Err(HostProfileError::new("placement must be a non-empty array"));
    }
    let mut seen_placement = HashSet::new();
    for entry in &placement {
        if !HOST_PLACEMENTS.contains(&entry.as_str()) {
            return Err(HostProfileError::new(format!("unknown placement: {entry}")));
        }
        if !seen_placement.insert(entry.clone()) {
            return Err(HostProfileError::new(format!(
                "duplicate placement: {entry}"
            )));
        }
    }

    let fields = profile.fields.clone().unwrap_or_default();
    let mut seen_fields = HashSet::new();
    for field in &fields {
        if field.is_empty() {
            return Err(HostProfileError::new("fields must be non-empty strings"));
        }
        if !seen_fields.insert(field.clone()) {
            return Err(HostProfileError::new(format!("duplicate field: {field}")));
        }
    }
    if network && fields.is_empty() && host_class == "disclose" {
        return Err(HostProfileError::new(
            "a network disclose host must declare the fields it sends",
        ));
    }

    Ok(NormalizedHostProfile {
        class: host_class.to_string(),
        risk: risk.to_string(),
        min_confirmation: min_confirmation.to_string(),
        idempotency: idempotency.to_string(),
        network,
        placement,
        fields,
    })
}

/// Installed intents and their underlying host functions.
#[derive(Default)]
pub struct HostRegistry {
    hosts: HashMap<String, HostEntry>,
    intents: HashMap<String, IntentExecutor>,
}

impl HostRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_host(
        &mut self,
        name: &str,
        function: HostFunction,
        profile: HostProfile,
    ) -> Result<(), HostProfileError> {
        let profile = validate_host_profile(name, &profile)?;
        self.hosts
            .insert(name.to_string(), HostEntry { function, profile });
        Ok(())
    }

    /// Register a core host with the default profile.
    pub fn register_core_host(&mut self, name: &str, function: HostFunction) {
        self.hosts.insert(
            name.to_string(),
            HostEntry {
                function,
                profile: validate_host_profile(name, &HostProfile::default())
                    .expect("core host profile"),
            },
        );
    }

    pub fn register_intent(&mut self, name: &str, function: IntentExecutor) {
        self.intents.insert(name.to_string(), function);
    }

    pub fn host(&self, name: &str) -> Option<HostFunction> {
        self.hosts.get(name).map(|entry| entry.function.clone())
    }

    /// Metadata used to enforce placement, egress, and confirmation.
    pub fn host_meta(&self, name: &str) -> Option<HostEntry> {
        self.hosts.get(name).cloned()
    }

    pub fn has_host(&self, name: &str) -> bool {
        self.hosts.contains_key(name)
    }

    pub fn intent(&self, name: &str) -> Option<IntentExecutor> {
        self.intents.get(name).cloned()
    }

    pub fn has_intent(&self, name: &str) -> bool {
        self.intents.contains_key(name)
    }

    pub fn access(&self, granted: &[String], policy: EgressPolicy) -> HostAccess<'_> {
        HostAccess {
            registry: self,
            granted: granted.iter().cloned().collect(),
            policy,
        }
    }
}

/// The per-request proxy handed to an intent executor.
pub struct HostAccess<'a> {
    registry: &'a HostRegistry,
    granted: HashSet<String>,
    policy: EgressPolicy,
}

impl HostAccess<'_> {
    pub fn call(&self, name: &str, args: &[Value]) -> Result<Value, String> {
        if !self.granted.contains(name) {
            return Err(format!("host function not granted: {name}"));
        }
        let entry = self
            .registry
            .host_meta(name)
            .ok_or_else(|| format!("host function not installed: {name}"))?;
        if entry.profile.network && !self.policy.network {
            return Err(format!("host requires network egress not granted: {name}"));
        }
        for field in &entry.profile.fields {
            if !self.policy.fields.contains(field) {
                return Err(format!("host may send an undeclared field: {name}/{field}"));
            }
        }
        (entry.function)(args)
    }

    pub fn has(&self, name: &str) -> bool {
        self.granted.contains(name) && self.registry.has_host(name)
    }
}
