//! Shared fixtures for the runtime integration tests.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ccp_kernel::Value;
use ccp_runtime::consumer::verify_manifest;
use ccp_runtime::hosts::HostRegistry;
use ccp_runtime::model::{Grant, VerifiedManifest};
use ccp_runtime::runtime::{Runtime, RuntimeOptions, SchemaRegistry};
use ccp_runtime::stores::{
    AuditStore, MemoryGrantStore, MemoryLimitStore, MemoryManifestStore, MemoryPendingStore,
    MemoryReplayStore,
};
use ccp_runtime::util::{array, object, signed_wire, text, uint};

pub const NOW: &str = "2026-10-22T12:00:30Z";
pub const PROVIDER_SEED: [u8; 32] = [0u8; 32];
pub const REQUESTER_SEED: [u8; 32] = [32u8; 32];
pub const STRANGER_SEED: [u8; 32] = [64u8; 32];

pub fn seed(offset: u8) -> [u8; 32] {
    let mut value = [0u8; 32];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = offset.wrapping_add(index as u8);
    }
    value
}

pub fn params_schema() -> Value {
    object(vec![
        ("type", text("object")),
        (
            "properties",
            object(vec![("item_id", object(vec![("type", text("string"))]))]),
        ),
        ("required", array(vec![text("item_id")])),
        ("additionalProperties", Value::Bool(false)),
    ])
}

pub fn result_schema() -> Value {
    object(vec![
        ("type", text("object")),
        (
            "properties",
            object(vec![
                ("item_id", object(vec![("type", text("string"))])),
                ("name", object(vec![("type", text("string"))])),
            ]),
        ),
        ("required", array(vec![text("item_id"), text("name")])),
        ("additionalProperties", Value::Bool(false)),
    ])
}

pub fn intent_definition() -> Value {
    object(vec![
        (
            "description",
            text("Look up one item requested by the consumer"),
        ),
        ("params_schema", text("schema:example.lookup.params.v1")),
        ("result_schema", text("schema:example.lookup.result.v1")),
        ("required_capabilities", array(vec![text("store.read")])),
        ("placement", text("local")),
        (
            "data_egress",
            object(vec![
                ("network", Value::Bool(false)),
                ("fields", array(vec![])),
            ]),
        ),
        (
            "suggested_limits",
            object(vec![("calls_per_hour", uint(10))]),
        ),
        ("confirmation", text("grant-policy")),
    ])
}

pub fn manifest_source(provider_seed: &[u8; 32]) -> (String, VerifiedManifest) {
    let manifest = object(vec![
        ("ccp", text("0.5-draft")),
        (
            "provider",
            object(vec![
                ("id", text(key_id(provider_seed))),
                ("name", text("Example Service")),
            ]),
        ),
        ("version", uint(1)),
        (
            "intents",
            object(vec![("example.lookup", intent_definition())]),
        ),
    ]);
    let wire = signed_wire(manifest, provider_seed).expect("signed manifest");
    let verified = verify_manifest(&wire, None).expect("verified manifest");
    (wire, verified)
}

pub fn key_id(seed: &[u8; 32]) -> String {
    ccp_runtime::key_id(seed)
}

pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    ccp_runtime::public_key(seed)
}

/// An audit store whose events can be inspected while the runtime owns it.
#[derive(Clone, Default)]
pub struct SharedAudit {
    events: Arc<Mutex<Vec<Value>>>,
}

impl SharedAudit {
    pub fn events(&self) -> Vec<Value> {
        self.events.lock().expect("audit lock").clone()
    }

    pub fn has_event(&self, name: &str) -> bool {
        self.events()
            .iter()
            .any(|event| event.get("event").and_then(Value::as_str) == Some(name))
    }
}

impl AuditStore for SharedAudit {
    fn append(&mut self, event: Value) {
        self.events.lock().expect("audit lock").push(event);
    }
}

pub fn schemas() -> SchemaRegistry {
    let mut schemas = SchemaRegistry::new();
    schemas.register("schema:example.lookup.params.v1", params_schema());
    schemas.register("schema:example.lookup.result.v1", result_schema());
    schemas
}

pub fn hosts() -> HostRegistry {
    let mut hosts = HostRegistry::new();
    hosts.register_core_host(
        "store.read",
        Arc::new(|args| {
            let item_id = args
                .first()
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Ok(object(vec![
                ("item_id", text(item_id)),
                ("name", text("Widget")),
            ]))
        }),
    );
    hosts.register_intent(
        "example.lookup",
        Arc::new(|params, access| {
            let item_id = params.get("item_id").and_then(Value::as_str).unwrap_or("");
            access.call("store.read", &[text(item_id)])
        }),
    );
    hosts
}

#[derive(Default)]
pub struct WorldOptions {
    pub confirmation: Option<String>,
    pub limits: Option<BTreeMap<String, u64>>,
    pub capabilities: Option<Vec<String>>,
    pub expires_at: Option<String>,
    pub now: Option<String>,
}

pub struct World {
    pub runtime: Runtime,
    pub grant: Grant,
    pub manifest: VerifiedManifest,
    pub manifest_wire: String,
    pub audit: SharedAudit,
    pub requester_id: String,
    pub requester_seed: [u8; 32],
}

pub fn build_world(options: WorldOptions) -> World {
    let provider_seed = PROVIDER_SEED;
    let requester_seed = REQUESTER_SEED;
    let (manifest_wire, manifest) = manifest_source(&provider_seed);
    let requester_id = key_id(&requester_seed);
    let now = options.now.clone().unwrap_or_else(|| NOW.to_string());

    let grant = Grant {
        id: "g-1".to_string(),
        requester_key: requester_id.clone(),
        contact_id: "c-1".to_string(),
        manifest_digest: manifest.digest.clone(),
        manifest_version: 1,
        intents: vec!["example.lookup".to_string()],
        limits: options.limits.unwrap_or_else(|| {
            let mut limits = BTreeMap::new();
            limits.insert("calls_per_hour".to_string(), 10);
            limits
        }),
        created_at: "2026-10-22T10:00:00Z".to_string(),
        expires_at: options
            .expires_at
            .unwrap_or_else(|| "2026-10-22T23:00:00Z".to_string()),
        confirmation: {
            let mut confirmation = BTreeMap::new();
            confirmation.insert(
                "example.lookup".to_string(),
                options.confirmation.unwrap_or_else(|| "none".to_string()),
            );
            confirmation
        },
        capabilities: options
            .capabilities
            .unwrap_or_else(|| vec!["store.read".to_string()]),
        placement: vec!["local".to_string()],
        egress: object(vec![("network", Value::Bool(false))]),
        state: "active".to_string(),
        state_reason: None,
    };

    let schemas = schemas();
    let hosts = hosts();

    let audit = SharedAudit::default();
    let runtime = Runtime::new(RuntimeOptions {
        grants: Some(Box::new(MemoryGrantStore::new(vec![grant.clone()]))),
        manifests: Some(Box::new(MemoryManifestStore::new(vec![manifest.clone()]))),
        replay: Some(Box::new(MemoryReplayStore::default())),
        limits: Some(Box::new(MemoryLimitStore::default())),
        pending: Some(Box::new(MemoryPendingStore::default())),
        schemas: Some(schemas),
        hosts: Some(hosts),
        audit: Some(Box::new(audit.clone())),
        clock: Some(Box::new(move || now.clone())),
        supported_ccp: None,
    });

    World {
        runtime,
        grant,
        manifest,
        manifest_wire,
        audit,
        requester_id,
        requester_seed,
    }
}

#[derive(Default)]
pub struct SignalOptions {
    pub request_id: Option<String>,
    pub grant_digest: Option<String>,
    pub intent: Option<String>,
    pub params: Option<Value>,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub ccp: Option<String>,
    pub signer_seed: Option<[u8; 32]>,
}

pub fn signal_for(world: &World, options: SignalOptions) -> String {
    let signal = object(vec![
        (
            "ccp",
            text(options.ccp.unwrap_or_else(|| "0.5-draft".to_string())),
        ),
        (
            "request_id",
            text(options.request_id.unwrap_or_else(|| "req-1".to_string())),
        ),
        (
            "grant_digest",
            text(
                options
                    .grant_digest
                    .unwrap_or_else(|| world.manifest.digest.clone()),
            ),
        ),
        (
            "intent",
            text(
                options
                    .intent
                    .unwrap_or_else(|| "example.lookup".to_string()),
            ),
        ),
        (
            "params",
            options
                .params
                .unwrap_or_else(|| object(vec![("item_id", text("item-123"))])),
        ),
        (
            "issued_at",
            text(
                options
                    .issued_at
                    .unwrap_or_else(|| "2026-10-22T12:00:00Z".to_string()),
            ),
        ),
        (
            "expires_at",
            text(
                options
                    .expires_at
                    .unwrap_or_else(|| "2026-10-22T12:01:00Z".to_string()),
            ),
        ),
    ]);
    let signer = options.signer_seed.unwrap_or(world.requester_seed);
    signed_wire(signal, &signer).expect("signed signal")
}
