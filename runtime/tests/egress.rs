mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use ccp_kernel::Value;
use ccp_runtime::identity::{
    build_admission_policy, verify_admission_policy, AdmissionPolicyInput, VerifyPolicyOptions,
};
use ccp_runtime::model::{AdmissionRequest, PolicyRule};
use ccp_runtime::runtime::{Runtime, RuntimeOptions, SchemaRegistry};
use ccp_runtime::stores::{
    MemoryAuditLog, MemoryGrantStore, MemoryLimitStore, MemoryManifestStore, MemoryPendingStore,
    MemoryReplayStore,
};
use ccp_runtime::util::{array, object, signed_wire, text, uint};
use ccp_runtime::{
    create_grant, validate_host_profile, CreateGrantOptions, EgressPolicy, HostProfile,
    HostRegistry, NormalizedHostProfile,
};
use support::{key_id, seed};

const NOW: &str = "2026-10-22T12:00:30Z";

const PROVIDER: [u8; 32] = [0u8; 32];
const REQUESTER: [u8; 32] = [32u8; 32];

fn params_schema() -> Value {
    object(vec![
        ("type", text("object")),
        (
            "properties",
            object(vec![("q", object(vec![("type", text("string"))]))]),
        ),
        ("required", array(vec![text("q")])),
        ("additionalProperties", Value::Bool(false)),
    ])
}

fn result_schema() -> Value {
    object(vec![
        ("type", text("object")),
        (
            "properties",
            object(vec![("ok", object(vec![("type", text("boolean"))]))]),
        ),
        ("required", array(vec![text("ok")])),
        ("additionalProperties", Value::Bool(false)),
    ])
}

fn intent(placement: &str, network: bool, fields: &[&str], confirmation: &str) -> Value {
    object(vec![
        ("description", text("Fetch something")),
        ("params_schema", text("schema:example.fetch.params.v1")),
        ("result_schema", text("schema:example.fetch.result.v1")),
        ("required_capabilities", array(vec![text("net.request")])),
        ("placement", text(placement)),
        (
            "data_egress",
            object(vec![
                ("network", Value::Bool(network)),
                (
                    "fields",
                    array(fields.iter().map(|field| text(*field)).collect()),
                ),
            ]),
        ),
        (
            "suggested_limits",
            object(vec![("calls_per_hour", uint(5))]),
        ),
        ("confirmation", text(confirmation)),
    ])
}

fn manifest_with(intent_definition: Value) -> ccp_runtime::VerifiedManifest {
    let manifest = object(vec![
        ("ccp", text("0.5-draft")),
        (
            "provider",
            object(vec![
                ("id", text(key_id(&PROVIDER))),
                ("name", text("Example Service")),
            ]),
        ),
        ("version", uint(1)),
        (
            "intents",
            object(vec![("example.fetch", intent_definition)]),
        ),
    ]);
    let wire = signed_wire(manifest, &PROVIDER).expect("manifest");
    ccp_runtime::verify_manifest(&wire, None).expect("verified manifest")
}

struct EgressWorld {
    runtime: Runtime,
    manifest: ccp_runtime::VerifiedManifest,
    signal: String,
}

fn build_egress_world(
    intent_definition: Value,
    host_class: &str,
    profile: HostProfile,
) -> EgressWorld {
    let manifest = manifest_with(intent_definition);
    let grant = create_grant(CreateGrantOptions {
        id: Some("g-1".to_string()),
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.clone().into(),
        intents: vec!["example.fetch".to_string()],
        limits: None,
        confirmation: None,
        capabilities: None,
        placement: None,
        egress: None,
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .expect("grant");

    let mut schemas = SchemaRegistry::new();
    schemas.register("schema:example.fetch.params.v1", params_schema());
    schemas.register("schema:example.fetch.result.v1", result_schema());

    let mut hosts = HostRegistry::new();
    hosts
        .register_host(
            "net.request",
            Arc::new(|_| Ok(object(vec![("ok", Value::Bool(true))]))),
            HostProfile {
                class: Some(host_class.to_string()),
                ..profile
            },
        )
        .expect("host profile");
    hosts.register_intent(
        "example.fetch",
        Arc::new(|params, access| {
            let q = params.get("q").and_then(Value::as_str).unwrap_or("");
            access.call("net.request", &[text(q)])
        }),
    );

    let runtime = Runtime::new(RuntimeOptions {
        grants: Some(Box::new(MemoryGrantStore::new(vec![grant]))),
        manifests: Some(Box::new(MemoryManifestStore::new(vec![manifest.clone()]))),
        replay: Some(Box::new(MemoryReplayStore::default())),
        limits: Some(Box::new(MemoryLimitStore::default())),
        pending: Some(Box::new(MemoryPendingStore::default())),
        schemas: Some(schemas),
        hosts: Some(hosts),
        audit: Some(Box::new(MemoryAuditLog::default())),
        clock: Some(Box::new(|| NOW.to_string())),
        supported_ccp: None,
    });

    let signal = object(vec![
        ("ccp", text("0.5-draft")),
        ("request_id", text("r1")),
        ("grant_digest", text(manifest.digest.clone())),
        ("intent", text("example.fetch")),
        ("params", object(vec![("q", text("hello"))])),
        ("issued_at", text("2026-10-22T12:00:00Z")),
        ("expires_at", text("2026-10-22T12:01:00Z")),
    ]);
    let signal = signed_wire(signal, &REQUESTER).expect("signal");
    EgressWorld {
        runtime,
        manifest,
        signal,
    }
}

fn disclose_profile(network: bool, fields: &[&str]) -> HostProfile {
    HostProfile {
        class: Some("disclose".to_string()),
        network: Some(network),
        fields: Some(fields.iter().map(|field| (*field).to_string()).collect()),
        ..HostProfile::default()
    }
}

#[test]
fn refuses_a_network_host_under_a_local_only_grant() {
    let mut world = build_egress_world(
        intent("local", false, &[], "none"),
        "disclose",
        disclose_profile(true, &["q"]),
    );
    let decision = world
        .runtime
        .submit(&world.signal, &support::public_key(&REQUESTER));
    assert_eq!(decision.error.as_deref(), Some("capability_unavailable"));
    assert!(decision
        .detail
        .unwrap_or_default()
        .contains("network egress"));
}

#[test]
fn allows_a_network_host_when_manifest_and_grant_allow_it() {
    let mut world = build_egress_world(
        intent("local", true, &["q"], "none"),
        "disclose",
        disclose_profile(true, &["q"]),
    );
    let first = world
        .runtime
        .submit(&world.signal, &support::public_key(&REQUESTER));
    assert_eq!(first.outcome, "confirmation_required");
    let done = world
        .runtime
        .confirm(&first.pending_id.expect("pending id"), true);
    assert_eq!(done.outcome, "authorized");
    assert_eq!(done.result, Some(object(vec![("ok", Value::Bool(true))])));
}

#[test]
fn refuses_a_host_that_transmits_an_undeclared_field() {
    let mut world = build_egress_world(
        intent("local", true, &["q"], "none"),
        "disclose",
        disclose_profile(true, &["q", "token"]),
    );
    let decision = world
        .runtime
        .submit(&world.signal, &support::public_key(&REQUESTER));
    assert_eq!(decision.error.as_deref(), Some("capability_unavailable"));
    assert!(decision
        .detail
        .unwrap_or_default()
        .contains("undeclared field token"));
}

#[test]
fn refuses_a_remote_intent_on_a_local_only_host() {
    let mut world = build_egress_world(
        intent("remote", true, &["q"], "none"),
        "disclose",
        disclose_profile(true, &["q"]),
    );
    let decision = world
        .runtime
        .submit(&world.signal, &support::public_key(&REQUESTER));
    assert_eq!(decision.error.as_deref(), Some("capability_unavailable"));
    assert!(decision.detail.unwrap_or_default().contains("placement"));
}

#[test]
fn allows_a_remote_intent_on_a_host_that_declares_the_placement() {
    let mut profile = disclose_profile(true, &["q"]);
    profile.placement = Some(vec!["local".to_string(), "remote".to_string()]);
    let mut world = build_egress_world(intent("remote", true, &["q"], "none"), "disclose", profile);
    let first = world
        .runtime
        .submit(&world.signal, &support::public_key(&REQUESTER));
    assert_eq!(first.outcome, "confirmation_required");
    assert_eq!(
        world
            .runtime
            .confirm(&first.pending_id.expect("pending id"), true)
            .outcome,
        "authorized"
    );
}

#[test]
fn enforces_the_ceiling_again_on_a_direct_host_call() {
    let mut hosts = HostRegistry::new();
    hosts
        .register_host(
            "net.request",
            Arc::new(|_| Ok(text("ok"))),
            disclose_profile(true, &["q"]),
        )
        .expect("host profile");
    let access = hosts.access(&["net.request".to_string()], EgressPolicy::default());
    let error = access.call("net.request", &[]).unwrap_err();
    assert!(error.contains("network egress"));
}

#[test]
fn defaults_an_unannotated_host_to_local_and_no_egress() {
    let mut hosts = HostRegistry::new();
    hosts.register_core_host("store.read", Arc::new(|_| Ok(text("ok"))));
    let meta = hosts.host_meta("store.read").expect("host");
    assert_eq!(
        meta.profile,
        NormalizedHostProfile {
            class: "read".to_string(),
            risk: "read".to_string(),
            min_confirmation: "none".to_string(),
            idempotency: "pure".to_string(),
            network: false,
            placement: vec!["local".to_string()],
            fields: vec![],
        }
    );
    let access = hosts.access(&["store.read".to_string()], EgressPolicy::default());
    assert_eq!(access.call("store.read", &[]).expect("call"), text("ok"));
}

#[test]
fn never_lets_a_policy_admit_an_intent_whose_host_needs_a_human() {
    let mut world = build_egress_world(
        intent("local", true, &["q"], "none"),
        "disclose",
        disclose_profile(true, &["q"]),
    );
    let host_seed = seed(96);
    let policy_document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![PolicyRule {
                id: "r-fetch".to_string(),
                intents: vec!["example.fetch".to_string()],
                risk: "read".to_string(),
                confirmation: "none".to_string(),
                expires_at: "2027-01-01T00:00:00Z".to_string(),
                contacts: Some(vec!["c-1".to_string()]),
                requesters: None,
                destinations: None,
                limits: Some({
                    let mut limits = BTreeMap::new();
                    limits.insert("calls_per_hour".to_string(), 5);
                    limits
                }),
            }],
            issued_at: "2026-10-22T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let policy = verify_admission_policy(
        &policy_document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .expect("verified policy");
    let manifest = world.manifest.clone();
    let outcome = world.runtime.admit_request(
        &policy,
        &AdmissionRequest {
            requester_key: key_id(&REQUESTER),
            contact_id: "c-1".to_string(),
            intent: "example.fetch".to_string(),
            risk: "read".to_string(),
            now: NOW.to_string(),
            destination: None,
        },
        &manifest,
    );
    assert_eq!(outcome.result.decision, "deny");
    assert_eq!(outcome.result.reason, "risk_not_admittable");
    assert!(outcome.grant.is_none());
}

#[test]
fn requires_a_class_for_every_extension_host() {
    let mut hosts = HostRegistry::new();
    let error = hosts
        .register_host(
            "net.request",
            Arc::new(|_| Ok(Value::Null)),
            HostProfile::default(),
        )
        .unwrap_err();
    assert!(error.message.contains("requires a class"));
}

#[test]
fn accepts_core_hosts_without_a_profile() {
    let profile =
        validate_host_profile("store.read", &HostProfile::default()).expect("core profile");
    assert_eq!(
        profile,
        NormalizedHostProfile {
            class: "read".to_string(),
            risk: "read".to_string(),
            min_confirmation: "none".to_string(),
            idempotency: "pure".to_string(),
            network: false,
            placement: vec!["local".to_string()],
            fields: vec![],
        }
    );
}

#[test]
fn derives_a_per_action_floor_for_write_control_and_compute() {
    let write = validate_host_profile(
        "store.write",
        &HostProfile {
            class: Some("write".to_string()),
            ..HostProfile::default()
        },
    )
    .expect("write");
    assert_eq!(write.risk, "write");
    assert_eq!(write.min_confirmation, "per_action");
    assert_eq!(write.idempotency, "caller_key");

    let control = validate_host_profile(
        "device.operation",
        &HostProfile {
            class: Some("control".to_string()),
            risk: Some("irreversible".to_string()),
            ..HostProfile::default()
        },
    )
    .expect("control");
    assert_eq!(control.risk, "irreversible");
    assert_eq!(control.min_confirmation, "per_action");

    let compute = validate_host_profile(
        "model.infer",
        &HostProfile {
            class: Some("compute".to_string()),
            ..HostProfile::default()
        },
    )
    .expect("compute");
    assert_eq!(compute.min_confirmation, "per_action");
}

#[test]
fn never_lets_a_write_host_suppress_confirmation() {
    let error = validate_host_profile(
        "store.write",
        &HostProfile {
            class: Some("write".to_string()),
            min_confirmation: Some("none".to_string()),
            ..HostProfile::default()
        },
    )
    .unwrap_err();
    assert!(error.message.contains("cannot suppress confirmation"));
}

#[test]
fn never_lets_an_irreversible_host_suppress_confirmation() {
    let error = validate_host_profile(
        "payment.submit",
        &HostProfile {
            class: Some("write".to_string()),
            risk: Some("irreversible".to_string()),
            min_confirmation: Some("none".to_string()),
            ..HostProfile::default()
        },
    )
    .unwrap_err();
    assert!(error.message.contains("cannot suppress confirmation"));
}

#[test]
fn requires_declared_fields_for_a_network_disclose_host() {
    let error = validate_host_profile(
        "net.request",
        &HostProfile {
            class: Some("disclose".to_string()),
            network: Some(true),
            ..HostProfile::default()
        },
    )
    .unwrap_err();
    assert!(error.message.contains("fields"));
}

#[test]
fn rejects_unknown_placements_and_duplicate_fields() {
    let bad_placement = validate_host_profile(
        "net.request",
        &HostProfile {
            class: Some("disclose".to_string()),
            network: Some(true),
            placement: Some(vec!["edge".to_string()]),
            fields: Some(vec!["q".to_string()]),
            ..HostProfile::default()
        },
    )
    .unwrap_err();
    assert!(bad_placement.message.contains("placement"));

    let duplicate = validate_host_profile(
        "net.request",
        &HostProfile {
            class: Some("disclose".to_string()),
            network: Some(true),
            fields: Some(vec!["q".to_string(), "q".to_string()]),
            ..HostProfile::default()
        },
    )
    .unwrap_err();
    assert!(duplicate.message.contains("duplicate"));
}

#[test]
fn pins_the_core_catalogue() {
    assert_eq!(
        ccp_runtime::CORE_HOSTS.to_vec(),
        vec![
            "store.read",
            "files.read",
            "files.search",
            "notify",
            "confirm",
            "audit.append",
        ]
    );
}

#[test]
fn grant_construction_narrows_limits() {
    let manifest = manifest_with(intent("local", false, &[], "none"));
    let mut limits = BTreeMap::new();
    limits.insert("calls_per_hour".to_string(), 6);
    let error = create_grant(CreateGrantOptions {
        id: None,
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.into(),
        intents: vec!["example.fetch".to_string()],
        limits: Some(limits),
        confirmation: None,
        capabilities: None,
        placement: None,
        egress: None,
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn grant_construction_refuses_extra_capabilities() {
    let manifest = manifest_with(intent("local", false, &[], "none"));
    let error = create_grant(CreateGrantOptions {
        id: None,
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.into(),
        intents: vec!["example.fetch".to_string()],
        limits: None,
        confirmation: None,
        capabilities: Some(vec![
            "net.request".to_string(),
            "extra.capability".to_string(),
        ]),
        placement: None,
        egress: None,
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn grant_construction_cannot_relax_confirmation() {
    let manifest = manifest_with(intent("local", false, &[], "per_action"));
    let mut confirmation = BTreeMap::new();
    confirmation.insert("example.fetch".to_string(), "none".to_string());
    let error = create_grant(CreateGrantOptions {
        id: None,
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.into(),
        intents: vec!["example.fetch".to_string()],
        limits: None,
        confirmation: Some(confirmation),
        capabilities: None,
        placement: None,
        egress: None,
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn grant_construction_refuses_undeclared_egress() {
    let manifest = manifest_with(intent("local", false, &[], "none"));
    let egress = object(vec![
        ("network", Value::Bool(true)),
        ("fields", array(vec![text("q")])),
    ]);
    let error = create_grant(CreateGrantOptions {
        id: None,
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.into(),
        intents: vec!["example.fetch".to_string()],
        limits: None,
        confirmation: None,
        capabilities: None,
        placement: None,
        egress: Some(egress),
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn grant_construction_refuses_undeclared_placement() {
    let manifest = manifest_with(intent("local", false, &[], "none"));
    let error = create_grant(CreateGrantOptions {
        id: None,
        contact_id: "c-1".to_string(),
        requester_key: key_id(&REQUESTER),
        manifest: manifest.into(),
        intents: vec!["example.fetch".to_string()],
        limits: None,
        confirmation: None,
        capabilities: None,
        placement: Some(vec!["remote".to_string()]),
        egress: None,
        created_at: Some("2026-10-22T10:00:00Z".to_string()),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}
