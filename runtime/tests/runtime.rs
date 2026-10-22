mod support;

use ccp_runtime::util::{object, text};
use support::*;

fn set_grant_state(world: &mut World, state: &str, reason: Option<&str>) {
    let mut grant = world.grant.clone();
    grant.state = state.to_string();
    grant.state_reason = reason.map(str::to_string);
    world.runtime.grants.add(grant);
}

#[test]
fn authorizes_a_valid_signal() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(&world, SignalOptions::default());
    let decision = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    assert_eq!(decision.outcome, "authorized");
    assert_eq!(
        decision.result,
        Some(object(vec![
            ("item_id", text("item-123")),
            ("name", text("Widget")),
        ]))
    );
    assert_eq!(
        world.runtime.limits.counters("g-1").get("calls_per_hour"),
        Some(&1)
    );
}

#[test]
fn requires_and_executes_confirmation() {
    let mut world = build_world(WorldOptions {
        confirmation: Some("per_action".to_string()),
        ..WorldOptions::default()
    });
    let signal = signal_for(
        &world,
        SignalOptions {
            request_id: Some("req-a".to_string()),
            ..SignalOptions::default()
        },
    );
    let first = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    assert_eq!(first.outcome, "confirmation_required");
    let pending_id = first.pending_id.expect("pending id");
    let done = world.runtime.confirm(&pending_id, true);
    assert_eq!(done.outcome, "authorized");
    assert_eq!(
        done.result,
        Some(object(vec![
            ("item_id", text("item-123")),
            ("name", text("Widget")),
        ]))
    );
}

#[test]
fn cancels_a_denied_confirmation_and_releases_the_limit() {
    let mut world = build_world(WorldOptions {
        confirmation: Some("per_action".to_string()),
        ..WorldOptions::default()
    });
    let signal = signal_for(&world, SignalOptions::default());
    let first = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    let pending_id = first.pending_id.expect("pending id");
    let denied = world.runtime.confirm(&pending_id, false);
    assert_eq!(denied.outcome, "cancelled");
    assert_eq!(
        world.runtime.limits.counters("g-1").get("calls_per_hour"),
        Some(&0)
    );
}

#[test]
fn rejects_a_replay() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .outcome,
        "authorized"
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("replay_detected")
    );
}

#[test]
fn enforces_limits() {
    let mut limits = std::collections::BTreeMap::new();
    limits.insert("calls_per_hour".to_string(), 1);
    let mut world = build_world(WorldOptions {
        limits: Some(limits),
        ..WorldOptions::default()
    });
    let first = signal_for(
        &world,
        SignalOptions {
            request_id: Some("r1".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&first, &public_key(&world.requester_seed))
            .outcome,
        "authorized"
    );
    let second = signal_for(
        &world,
        SignalOptions {
            request_id: Some("r2".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&second, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("limit_exceeded")
    );
}

#[test]
fn rejects_a_bad_signature() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(
        &world,
        SignalOptions {
            signer_seed: Some(STRANGER_SEED),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("unauthenticated")
    );
}

#[test]
fn rejects_a_request_with_no_grant() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(
        &world,
        SignalOptions {
            signer_seed: Some(STRANGER_SEED),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&STRANGER_SEED))
            .error
            .as_deref(),
        Some("no_matching_grant")
    );
}

#[test]
fn rejects_revoked_and_paused_grants() {
    let mut world = build_world(WorldOptions::default());
    set_grant_state(&mut world, "revoked", None);
    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("grant_revoked")
    );

    set_grant_state(&mut world, "paused", None);
    let signal = signal_for(
        &world,
        SignalOptions {
            request_id: Some("p1".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("grant_paused")
    );

    set_grant_state(&mut world, "active", None);
    let signal = signal_for(
        &world,
        SignalOptions {
            request_id: Some("p2".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .outcome,
        "authorized"
    );
}

#[test]
fn rejects_an_expired_grant() {
    let mut world = build_world(WorldOptions {
        expires_at: Some("2026-10-22T11:00:00Z".to_string()),
        ..WorldOptions::default()
    });
    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("grant_expired")
    );
}

#[test]
fn rejects_invalid_params() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(
        &world,
        SignalOptions {
            params: Some(object(vec![])),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn rejects_when_a_capability_is_unavailable() {
    let mut world = build_world(WorldOptions {
        capabilities: Some(vec![]),
        ..WorldOptions::default()
    });
    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("capability_unavailable")
    );
}

#[test]
fn rejects_a_protocol_mismatch() {
    let mut world = build_world(WorldOptions::default());
    let signal = signal_for(
        &world,
        SignalOptions {
            ccp: Some("0.2-draft".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn rejects_malformed_input() {
    let mut world = build_world(WorldOptions::default());
    assert_eq!(
        world
            .runtime
            .submit("not json", &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("invalid_request")
    );
}

#[test]
fn re_checks_grant_state_when_confirming() {
    let mut world = build_world(WorldOptions {
        confirmation: Some("per_action".to_string()),
        ..WorldOptions::default()
    });
    let signal = signal_for(
        &world,
        SignalOptions {
            request_id: Some("req-a".to_string()),
            ..SignalOptions::default()
        },
    );
    let first = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    let pending_id = first.pending_id.expect("pending id");
    set_grant_state(&mut world, "revoked", None);
    assert_eq!(
        world.runtime.confirm(&pending_id, true).error.as_deref(),
        Some("grant_revoked")
    );
}

#[test]
fn revokes_a_grant_through_the_runtime() {
    let mut world = build_world(WorldOptions::default());
    let revoked = world
        .runtime
        .revoke_grant("g-1", Some("user asked"))
        .expect("revoked");
    assert_eq!(revoked.state, "revoked");
    assert_eq!(revoked.state_reason.as_deref(), Some("user asked"));
    assert_eq!(
        world
            .runtime
            .grants
            .get("g-1")
            .map(|grant| grant.state)
            .as_deref(),
        Some("revoked")
    );
    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("grant_revoked")
    );
    assert!(world.audit.has_event("revoked"));
}

#[test]
fn rejects_revoking_an_unknown_grant() {
    let mut world = build_world(WorldOptions::default());
    let error = world.runtime.revoke_grant("missing", None).unwrap_err();
    assert_eq!(error.code, "no_matching_grant");
}

#[test]
fn revocation_invalidates_an_open_confirmation() {
    let mut world = build_world(WorldOptions {
        confirmation: Some("per_action".to_string()),
        ..WorldOptions::default()
    });
    let signal = signal_for(
        &world,
        SignalOptions {
            request_id: Some("req-a".to_string()),
            ..SignalOptions::default()
        },
    );
    let first = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    let pending_id = first.pending_id.expect("pending id");
    world.runtime.revoke_grant("g-1", None).expect("revoked");
    assert_eq!(
        world.runtime.confirm(&pending_id, true).error.as_deref(),
        Some("grant_revoked")
    );
}

#[test]
fn pauses_and_resumes_without_resetting_limits() {
    let mut world = build_world(WorldOptions::default());
    let first = signal_for(
        &world,
        SignalOptions {
            request_id: Some("r1".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&first, &public_key(&world.requester_seed))
            .outcome,
        "authorized"
    );

    world
        .runtime
        .pause_grant("g-1", Some("temporary stop"))
        .expect("paused");
    let second = signal_for(
        &world,
        SignalOptions {
            request_id: Some("r2".to_string()),
            ..SignalOptions::default()
        },
    );
    let paused = world
        .runtime
        .submit(&second, &public_key(&world.requester_seed));
    assert_eq!(paused.error.as_deref(), Some("grant_paused"));
    assert_eq!(paused.detail.as_deref(), Some("temporary stop"));

    let resumed = world.runtime.resume_grant("g-1").expect("resumed");
    assert_eq!(resumed.state, "active");
    let third = signal_for(
        &world,
        SignalOptions {
            request_id: Some("r3".to_string()),
            ..SignalOptions::default()
        },
    );
    assert_eq!(
        world
            .runtime
            .submit(&third, &public_key(&world.requester_seed))
            .outcome,
        "authorized"
    );
    assert_eq!(
        world.runtime.limits.counters("g-1").get("calls_per_hour"),
        Some(&2)
    );
}

#[test]
fn suspends_with_a_reason_and_waits_for_an_explicit_resume() {
    let mut world = build_world(WorldOptions::default());
    world
        .runtime
        .suspend_grant("g-1", Some("requester key changed"))
        .expect("suspended");
    let signal = signal_for(&world, SignalOptions::default());
    let suspended = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    assert_eq!(suspended.error.as_deref(), Some("grant_suspended"));
    assert_eq!(suspended.detail.as_deref(), Some("requester key changed"));
}

#[test]
fn never_resumes_a_revoked_or_expired_grant() {
    let mut world = build_world(WorldOptions::default());
    world.runtime.revoke_grant("g-1", None).expect("revoked");
    assert_eq!(
        world.runtime.resume_grant("g-1").unwrap_err().code,
        "grant_revoked"
    );

    let mut expired = build_world(WorldOptions {
        expires_at: Some("2026-10-22T11:00:00Z".to_string()),
        ..WorldOptions::default()
    });
    expired.runtime.pause_grant("g-1", None).expect("paused");
    assert_eq!(
        expired.runtime.resume_grant("g-1").unwrap_err().code,
        "grant_expired"
    );
}

#[test]
fn suspends_every_grant_bound_to_a_contact() {
    let mut world = build_world(WorldOptions::default());
    let mut second = world.grant.clone();
    second.id = "g-2".to_string();
    world.runtime.grants.add(second);
    assert_eq!(
        world
            .runtime
            .suspend_contact("c-1", Some("identity review")),
        2
    );
    assert_eq!(
        world
            .runtime
            .grants
            .get("g-2")
            .map(|grant| grant.state)
            .as_deref(),
        Some("suspended")
    );
}
