//! End-to-end runtime loop: authorize, execute, revoke, reject.
//!
//!     cargo run --example quickstart --manifest-path runtime/Cargo.toml

use std::sync::Arc;

use ccp_kernel::Value;
use ccp_runtime::util::{array, object, signed_wire, text, uint};
use ccp_runtime::{
    create_grant, verify_manifest, CreateGrantOptions, HostRegistry, Runtime, RuntimeOptions,
    SchemaRegistry,
};

fn main() {
    let provider_seed: [u8; 32] = std::array::from_fn(|index| index as u8);
    let requester_seed: [u8; 32] = std::array::from_fn(|index| index as u8 + 32);

    let manifest_source = object(vec![
        ("ccp", text("0.5-draft")),
        (
            "provider",
            object(vec![
                ("id", text(ccp_runtime::key_id(&provider_seed))),
                ("name", text("Example Service")),
            ]),
        ),
        ("version", uint(1)),
        (
            "intents",
            object(vec![(
                "example.lookup",
                object(vec![
                    ("description", text("Look up one item")),
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
                        object(vec![("calls_per_hour", uint(5))]),
                    ),
                    ("confirmation", text("none")),
                ]),
            )]),
        ),
    ]);
    let manifest_wire = signed_wire(manifest_source, &provider_seed).expect("signed manifest");
    let manifest = verify_manifest(&manifest_wire, None).expect("verified manifest");

    let grant = create_grant(CreateGrantOptions {
        id: Some("g-demo".to_string()),
        contact_id: "c-demo".to_string(),
        requester_key: ccp_runtime::key_id(&requester_seed),
        manifest: manifest.clone().into(),
        intents: vec!["example.lookup".to_string()],
        limits: None,
        confirmation: None,
        capabilities: None,
        placement: None,
        egress: None,
        created_at: Some(ccp_runtime::time::utcnow()),
        expires_at: ccp_runtime::time::add_seconds(&ccp_runtime::time::utcnow(), 3_600)
            .expect("expiry"),
        state: None,
        state_reason: None,
        admitted_by: None,
    })
    .expect("grant");

    let mut schemas = SchemaRegistry::new();
    schemas.register(
        "schema:example.lookup.params.v1",
        object(vec![
            ("type", text("object")),
            (
                "properties",
                object(vec![("item_id", object(vec![("type", text("string"))]))]),
            ),
            ("required", array(vec![text("item_id")])),
            ("additionalProperties", Value::Bool(false)),
        ]),
    );
    schemas.register(
        "schema:example.lookup.result.v1",
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
        ]),
    );

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

    let mut runtime = Runtime::new(RuntimeOptions {
        schemas: Some(schemas),
        hosts: Some(hosts),
        ..RuntimeOptions::default()
    });
    runtime.grants.add(grant);
    runtime.manifests.add(manifest.clone());

    let public_key = ccp_runtime::public_key(&requester_seed);
    let signal_document = build_signal(manifest.digest.clone(), "req-1", "item-123");
    let signal_document = signed_wire(signal_document, &requester_seed).expect("signed signal");
    let decision = runtime.submit(&signal_document, &public_key);
    println!("decision: {}", decision.outcome);
    if let Some(result) = decision.result {
        println!(
            "result: {}",
            ccp_kernel::serialize(&result).unwrap_or_default()
        );
    }

    runtime
        .revoke_grant("g-demo", Some("demo finished"))
        .expect("revoked");
    let signal_document = build_signal(manifest.digest, "req-2", "item-123");
    let signal_document = signed_wire(signal_document, &requester_seed).expect("signed signal");
    let decision = runtime.submit(&signal_document, &public_key);
    println!(
        "after revoke: {}",
        decision.error.unwrap_or(decision.outcome)
    );
}

fn build_signal(grant_digest: String, request_id: &str, item_id: &str) -> Value {
    let now = ccp_runtime::time::utcnow();
    let expires = ccp_runtime::time::add_seconds(&now, 60).expect("expiry");
    object(vec![
        ("ccp", text("0.5-draft")),
        ("request_id", text(request_id)),
        ("grant_digest", text(grant_digest)),
        ("intent", text("example.lookup")),
        ("params", object(vec![("item_id", text(item_id))])),
        ("issued_at", text(now)),
        ("expires_at", text(expires)),
    ])
}
