//! Durable-store behaviour, including revocation and pending across restarts.

#![cfg(feature = "sqlite")]

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use ccp_kernel::Value;
use ccp_runtime::model::{Grant, VerifiedManifest};
use ccp_runtime::runtime::{Runtime, RuntimeOptions};
use ccp_runtime::sqlite::SqliteStores;
use ccp_runtime::util::{object, random_id};
use ccp_runtime::{AuditStore, LimitStore, ManifestStore, PendingStore, ReplayStore};
use support::*;

fn grant_for(manifest: &VerifiedManifest, confirmation: &str) -> Grant {
    let mut limits = BTreeMap::new();
    limits.insert("calls_per_hour".to_string(), 10);
    let mut confirmation_map = BTreeMap::new();
    confirmation_map.insert("example.lookup".to_string(), confirmation.to_string());
    Grant {
        id: "g-1".to_string(),
        requester_key: key_id(&REQUESTER_SEED),
        contact_id: "c-1".to_string(),
        manifest_digest: manifest.digest.clone(),
        manifest_version: 1,
        intents: vec!["example.lookup".to_string()],
        limits,
        created_at: "2026-10-22T10:00:00Z".to_string(),
        expires_at: "2026-10-22T23:00:00Z".to_string(),
        confirmation: confirmation_map,
        capabilities: vec!["store.read".to_string()],
        placement: vec!["local".to_string()],
        egress: object(vec![("network", Value::Bool(false))]),
        state: "active".to_string(),
        state_reason: None,
    }
}

fn runtime_from(stores: SqliteStores) -> Runtime {
    Runtime::new(RuntimeOptions {
        grants: Some(Box::new(stores.grants)),
        manifests: Some(Box::new(stores.manifests)),
        replay: Some(Box::new(stores.replay)),
        limits: Some(Box::new(stores.limits)),
        pending: Some(Box::new(stores.pending)),
        schemas: Some(schemas()),
        hosts: Some(hosts()),
        audit: Some(Box::new(stores.audit)),
        clock: Some(Box::new(|| NOW.to_string())),
        supported_ccp: None,
    })
}

fn temp_path() -> PathBuf {
    std::env::temp_dir().join(format!("ccp-runtime-{}.db", random_id()))
}

#[test]
fn revocation_survives_a_process_restart() {
    let path = temp_path();
    let (_, manifest) = manifest_source(&PROVIDER_SEED);

    {
        let stores = SqliteStores::open(&path).expect("open");
        let mut runtime = runtime_from(stores);
        runtime.grants.add(grant_for(&manifest, "none"));
        runtime.manifests.add(manifest.clone());

        let signal = signal_for(
            &World {
                runtime: Runtime::default(),
                grant: grant_for(&manifest, "none"),
                manifest: manifest.clone(),
                manifest_wire: String::new(),
                audit: Default::default(),
                requester_id: key_id(&REQUESTER_SEED),
                requester_seed: REQUESTER_SEED,
            },
            SignalOptions::default(),
        );
        assert_eq!(
            runtime
                .submit(&signal, &public_key(&REQUESTER_SEED))
                .outcome,
            "authorized"
        );
        runtime
            .revoke_grant("g-1", Some("user asked"))
            .expect("revoked");
    }

    {
        let stores = SqliteStores::open(&path).expect("reopen");
        let mut runtime = runtime_from(stores);
        let world = World {
            runtime: Runtime::default(),
            grant: grant_for(&manifest, "none"),
            manifest: manifest.clone(),
            manifest_wire: String::new(),
            audit: Default::default(),
            requester_id: key_id(&REQUESTER_SEED),
            requester_seed: REQUESTER_SEED,
        };
        let signal = signal_for(
            &world,
            SignalOptions {
                request_id: Some("req-after-restart".to_string()),
                ..SignalOptions::default()
            },
        );
        let decision = runtime.submit(&signal, &public_key(&REQUESTER_SEED));
        assert_eq!(decision.error.as_deref(), Some("grant_revoked"));
        assert_eq!(
            runtime.grants.get("g-1").map(|grant| grant.state),
            Some("revoked".to_string())
        );
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn pending_confirmation_survives_a_restart() {
    let path = temp_path();
    let (_, manifest) = manifest_source(&PROVIDER_SEED);

    let pending_id = {
        let stores = SqliteStores::open(&path).expect("open");
        let mut runtime = runtime_from(stores);
        runtime.grants.add(grant_for(&manifest, "per_action"));
        runtime.manifests.add(manifest.clone());
        let world = World {
            runtime: Runtime::default(),
            grant: grant_for(&manifest, "per_action"),
            manifest: manifest.clone(),
            manifest_wire: String::new(),
            audit: Default::default(),
            requester_id: key_id(&REQUESTER_SEED),
            requester_seed: REQUESTER_SEED,
        };
        let signal = signal_for(&world, SignalOptions::default());
        let decision = runtime.submit(&signal, &public_key(&REQUESTER_SEED));
        assert_eq!(decision.outcome, "confirmation_required");
        decision.pending_id.expect("pending id")
    };

    {
        let stores = SqliteStores::open(&path).expect("reopen");
        let mut runtime = runtime_from(stores);
        let done = runtime.confirm(&pending_id, true);
        assert_eq!(done.outcome, "authorized");
        assert_eq!(
            runtime.limits.counters("g-1").get("calls_per_hour"),
            Some(&1)
        );
        assert!(runtime.pending(&pending_id).is_none());
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn replay_and_limits_are_atomic_stores() {
    let mut stores = SqliteStores::in_memory().expect("stores");

    assert!(stores.replay.mark_if_new("r1"));
    assert!(!stores.replay.mark_if_new("r1"));
    assert!(stores.replay.has("r1"));

    let mut limits = BTreeMap::new();
    limits.insert("calls_per_hour".to_string(), 1);
    assert!(stores.limits.try_reserve("g-1", &limits));
    assert!(!stores.limits.try_reserve("g-1", &limits));
    assert_eq!(
        stores.limits.counters("g-1").get("calls_per_hour"),
        Some(&1)
    );
    stores.limits.release("g-1", &limits);
    assert_eq!(
        stores.limits.counters("g-1").get("calls_per_hour"),
        Some(&0)
    );
}

#[test]
fn manifest_store_round_trips_and_verifies() {
    let mut stores = SqliteStores::in_memory().expect("stores");
    let (_, manifest) = manifest_source(&PROVIDER_SEED);
    stores.manifests.add(manifest.clone());
    let loaded = stores.manifests.get(&manifest.digest).expect("manifest");
    assert_eq!(loaded.digest, manifest.digest);
    assert_eq!(loaded.provider_id, manifest.provider_id);
}

#[test]
fn pending_take_resolves_at_most_once() {
    let mut stores = SqliteStores::in_memory().expect("stores");
    let (_, manifest) = manifest_source(&PROVIDER_SEED);
    let grant = grant_for(&manifest, "per_action");
    let pending = ccp_runtime::PendingRequest {
        id: "p-1".to_string(),
        signal: object(vec![
            ("request_id", ccp_runtime::util::text("r-1")),
            ("intent", ccp_runtime::util::text("example.lookup")),
            ("params", object(vec![])),
        ]),
        grant,
        intent_spec: object(vec![]),
        state: "awaiting_confirmation".to_string(),
    };
    stores.pending.put(pending);
    assert!(stores.pending.get("p-1").is_some());
    assert!(stores.pending.take("p-1").is_some());
    assert!(stores.pending.take("p-1").is_none());
}

#[test]
fn audit_log_is_append_only_and_ordered() {
    let mut stores = SqliteStores::in_memory().expect("stores");
    stores.audit.append(object(vec![
        ("at", ccp_runtime::util::text("2026-10-22T12:00:00Z")),
        ("event", ccp_runtime::util::text("first")),
    ]));
    stores.audit.append(object(vec![
        ("at", ccp_runtime::util::text("2026-10-22T12:00:01Z")),
        ("event", ccp_runtime::util::text("second")),
    ]));
    let events = stores.audit.events();
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].get("event").and_then(Value::as_str),
        Some("first")
    );
    assert_eq!(stores.audit.len(), 2);
}
