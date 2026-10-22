mod support;

use ccp_runtime::identity::{
    build_admission_policy, build_identity_document, verify_admission_policy, AdmissionPolicyInput,
    IdentityInput, VerifyPolicyOptions,
};
use ccp_runtime::model::{AdmissionRequest, Endpoint, PolicyRule, VerifyContactOptions};
use ccp_runtime::IDENTITY_CHANGED_REASON;
use support::*;

const ISSUED: &str = "2026-10-22T00:00:00Z";
const UNTIL: &str = "2027-10-22T00:00:00Z";
const POLICY_UNTIL: &str = "2027-01-01T00:00:00Z";

fn identity_input(name: &str) -> IdentityInput {
    IdentityInput {
        ccp: None,
        name: Some(name.to_string()),
        roles: Some(vec!["requester".to_string()]),
        endpoints: Some(vec![Endpoint {
            transport: "https".to_string(),
            manifest: Some("https://example.test/manifest".to_string()),
            signal: None,
        }]),
        manifest_digest: None,
        policy_digest: None,
        issued_at: ISSUED.to_string(),
        expires_at: UNTIL.to_string(),
    }
}

fn document(seed: &[u8; 32]) -> String {
    build_identity_document(&identity_input("Peer"), seed).expect("identity document")
}

#[test]
fn verifies_a_matching_document_without_touching_grants() {
    let mut world = build_world(WorldOptions::default());
    let verified = world
        .runtime
        .verify_contact_identity(
            &document(&REQUESTER_SEED),
            &VerifyContactOptions {
                contact_id: "c-1".to_string(),
                now: Some(NOW.to_string()),
                expected_identity: Some(world.requester_id.clone()),
                manifest_digest: None,
                policy_digest: None,
            },
        )
        .expect("verified");
    assert_eq!(verified.identity, world.requester_id);
    assert_eq!(
        world.runtime.grants.get("g-1").map(|grant| grant.state),
        Some("active".to_string())
    );
}

#[test]
fn suspends_the_contacts_grants_when_the_key_changed() {
    let mut world = build_world(WorldOptions::default());
    let other = seed(96);
    let error = world
        .runtime
        .verify_contact_identity(
            &document(&other),
            &VerifyContactOptions {
                contact_id: "c-1".to_string(),
                now: Some(NOW.to_string()),
                expected_identity: Some(world.requester_id.clone()),
                manifest_digest: None,
                policy_digest: None,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "identity_changed");

    let grant = world.runtime.grants.get("g-1").expect("grant");
    assert_eq!(grant.state, "suspended");
    assert_eq!(grant.state_reason.as_deref(), Some(IDENTITY_CHANGED_REASON));
    assert!(world.audit.has_event("identity_changed"));

    let signal = signal_for(&world, SignalOptions::default());
    assert_eq!(
        world
            .runtime
            .submit(&signal, &public_key(&world.requester_seed))
            .error
            .as_deref(),
        Some("grant_suspended")
    );
}

#[test]
fn does_not_let_a_key_change_be_resumed_in_one_click() {
    let mut world = build_world(WorldOptions::default());
    let other = seed(96);
    world
        .runtime
        .verify_contact_identity(
            &document(&other),
            &VerifyContactOptions {
                contact_id: "c-1".to_string(),
                now: Some(NOW.to_string()),
                expected_identity: Some(world.requester_id.clone()),
                manifest_digest: None,
                policy_digest: None,
            },
        )
        .unwrap_err();
    assert_eq!(
        world.runtime.resume_grant("g-1").unwrap_err().code,
        "grant_suspended"
    );
}

#[test]
fn never_suspends_on_a_forged_document() {
    let mut world = build_world(WorldOptions::default());
    let forged = document(&REQUESTER_SEED).replace("Peer", "Evil");
    let error = world
        .runtime
        .verify_contact_identity(
            &forged,
            &VerifyContactOptions {
                contact_id: "c-1".to_string(),
                now: Some(NOW.to_string()),
                expected_identity: Some(world.requester_id.clone()),
                manifest_digest: None,
                policy_digest: None,
            },
        )
        .unwrap_err();
    assert_eq!(error.code, "unauthenticated");
    assert_eq!(
        world.runtime.grants.get("g-1").map(|grant| grant.state),
        Some("active".to_string())
    );
}

#[test]
fn still_allows_a_manual_suspend_to_resume() {
    let mut world = build_world(WorldOptions::default());
    world
        .runtime
        .suspend_grant("g-1", Some("manual review"))
        .expect("suspended");
    assert_eq!(
        world.runtime.resume_grant("g-1").expect("resumed").state,
        "active"
    );
}

#[test]
fn rejects_an_empty_roles_array() {
    let mut input = identity_input("Peer");
    input.roles = Some(vec![]);
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    assert_eq!(world_identity(&document), "invalid_request");
}

#[test]
fn rejects_an_empty_endpoints_array() {
    let mut input = identity_input("Peer");
    input.endpoints = Some(vec![]);
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    assert_eq!(world_identity(&document), "invalid_request");
}

#[test]
fn rejects_an_expired_identity_document() {
    let mut input = identity_input("Peer");
    input.issued_at = "2026-01-01T00:00:00Z".to_string();
    input.expires_at = "2026-02-01T00:00:00Z".to_string();
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    let error = world_identity(&document);
    assert_eq!(error, "identity_expired");
}

#[test]
fn rejects_a_document_that_is_not_yet_valid() {
    let mut input = identity_input("Peer");
    input.issued_at = "2027-01-01T00:00:00Z".to_string();
    input.expires_at = "2028-01-01T00:00:00Z".to_string();
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    let error = world_identity(&document);
    assert_eq!(error, "identity_expired");
}

#[test]
fn reports_a_manifest_digest_mismatch() {
    let mut input = identity_input("Peer");
    input.manifest_digest =
        Some("sha256:abababababababababababababababababababababababababababababababab".to_string());
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    let error = ccp_runtime::verify_identity_document(
        &document,
        &ccp_runtime::VerifyIdentityOptions {
            now: Some(NOW.to_string()),
            manifest_digest: Some(
                "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                    .to_string(),
            ),
            ..ccp_runtime::VerifyIdentityOptions::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "manifest_mismatch");
}

fn world_identity(document: &str) -> String {
    ccp_runtime::verify_identity_document(
        document,
        &ccp_runtime::VerifyIdentityOptions {
            now: Some(NOW.to_string()),
            ..ccp_runtime::VerifyIdentityOptions::default()
        },
    )
    .unwrap_err()
    .code
}

fn rule() -> PolicyRule {
    let mut limits = std::collections::BTreeMap::new();
    limits.insert("calls_per_hour".to_string(), 5);
    PolicyRule {
        id: "r-read".to_string(),
        intents: vec!["example.lookup".to_string()],
        risk: "read".to_string(),
        confirmation: "none".to_string(),
        expires_at: POLICY_UNTIL.to_string(),
        contacts: Some(vec!["c-1".to_string()]),
        requesters: None,
        destinations: None,
        limits: Some(limits),
    }
}

fn policy() -> ccp_runtime::VerifiedPolicy {
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![rule()],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .expect("verified policy")
}

fn request(world: &World, contact: &str) -> AdmissionRequest {
    AdmissionRequest {
        requester_key: world.grant.requester_key.clone(),
        contact_id: contact.to_string(),
        intent: "example.lookup".to_string(),
        risk: "read".to_string(),
        now: NOW.to_string(),
        destination: None,
    }
}

#[test]
fn creates_a_least_authority_grant_and_records_the_rule() {
    let mut world = build_world(WorldOptions::default());
    let policy = policy();
    let request = request(&world, "c-1");
    let manifest = world.manifest.clone();
    let outcome = world.runtime.admit_request(&policy, &request, &manifest);
    assert_eq!(outcome.result.decision, "allow");
    assert_eq!(outcome.result.rule_id.as_deref(), Some("r-read"));
    let grant = outcome.grant.expect("grant");
    assert!(grant.id.starts_with("pg-"));
    assert_eq!(grant.id.len(), 35);
    assert_eq!(grant.requester_key, world.grant.requester_key);
    assert_eq!(grant.contact_id, "c-1");
    assert_eq!(grant.intents, vec!["example.lookup".to_string()]);
    assert_eq!(grant.limits.get("calls_per_hour"), Some(&5));
    assert_eq!(
        grant.confirmation.get("example.lookup").map(String::as_str),
        Some("none")
    );
    assert!(world.audit.has_event("admitted"));
    let admitted = world
        .audit
        .events()
        .into_iter()
        .find(|event| event.get("event").and_then(ccp_kernel::Value::as_str) == Some("admitted"))
        .expect("admitted event");
    assert_eq!(
        admitted.get("rule_id").and_then(ccp_kernel::Value::as_str),
        Some("r-read")
    );
}

#[test]
fn reuses_the_deterministic_grant_instead_of_widening_it() {
    let mut world = build_world(WorldOptions::default());
    let policy = policy();
    let request = request(&world, "c-1");
    let manifest = world.manifest.clone();
    let first = world
        .runtime
        .admit_request(&policy, &request, &manifest)
        .grant
        .expect("first grant");
    let second = world
        .runtime
        .admit_request(&policy, &request, &manifest)
        .grant
        .expect("second grant");
    assert_eq!(first.id, second.id);
    assert_eq!(first.created_at, second.created_at);
    let matches = world
        .runtime
        .grants
        .all()
        .into_iter()
        .filter(|grant| grant.id == first.id)
        .count();
    assert_eq!(matches, 1);
}

#[test]
fn refuses_to_recreate_a_revoked_grant() {
    let mut world = build_world(WorldOptions::default());
    let policy = policy();
    let request = request(&world, "c-1");
    let manifest = world.manifest.clone();
    let first = world
        .runtime
        .admit_request(&policy, &request, &manifest)
        .grant
        .expect("grant");
    world
        .runtime
        .revoke_grant(&first.id, None)
        .expect("revoked");

    let again = world.runtime.admit_request(&policy, &request, &manifest);
    assert_eq!(again.result.decision, "deny");
    assert_eq!(again.result.reason, "grant_revoked");
    assert!(again.grant.is_none());
}

#[test]
fn does_not_create_a_grant_when_the_policy_defers_to_the_user() {
    let mut world = build_world(WorldOptions::default());
    let policy = policy();
    let request = request(&world, "c-other");
    let manifest = world.manifest.clone();
    let outcome = world.runtime.admit_request(&policy, &request, &manifest);
    assert_eq!(outcome.result.decision, "confirm");
    assert!(outcome.grant.is_none());
}

#[test]
fn produces_a_grant_the_runtime_can_then_authorize() {
    let mut world = build_world(WorldOptions::default());
    let policy = policy();
    let request = request(&world, "c-1");
    let manifest = world.manifest.clone();
    world.runtime.grants.remove("g-1");
    let grant = world
        .runtime
        .admit_request(&policy, &request, &manifest)
        .grant
        .expect("grant");
    let signal = signal_for(&world, SignalOptions::default());
    let decision = world
        .runtime
        .submit(&signal, &public_key(&world.requester_seed));
    assert_eq!(decision.outcome, "authorized");
    assert_eq!(
        world
            .runtime
            .limits
            .counters(&grant.id)
            .get("calls_per_hour"),
        Some(&1)
    );
}

#[test]
fn skips_a_grant_that_does_not_enable_the_intent() {
    let mut world = build_world(WorldOptions::default());
    let mut other = world.grant.clone();
    other.id = "g-other".to_string();
    other.intents = vec!["other.intent".to_string()];
    let mut good = world.grant.clone();
    good.id = "g-good".to_string();
    world.runtime.grants.remove("g-1");
    world.runtime.grants.add(other);
    world.runtime.grants.add(good);

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
            .limits
            .counters("g-good")
            .get("calls_per_hour"),
        Some(&1)
    );
}

#[test]
fn rejects_a_policy_whose_host_is_not_the_expected_one() {
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![rule()],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let error = verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: Some(key_id(&seed(100))),
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "identity_changed");
}

#[test]
fn rejects_a_disclose_rule_without_destinations() {
    let mut bad = rule();
    bad.risk = "disclose".to_string();
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![bad],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let error = verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn rejects_a_read_rule_that_pins_destinations() {
    let mut bad = rule();
    bad.destinations = Some(vec!["wallet:acct-9".to_string()]);
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![bad],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let error = verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn rejects_a_rule_that_expires_after_the_policy() {
    let mut bad = rule();
    bad.expires_at = "2028-01-01T00:00:00Z".to_string();
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![bad],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let error = verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "invalid_request");
}

#[test]
fn rejects_an_expired_policy() {
    let host_seed = seed(96);
    let mut expired_rule = rule();
    expired_rule.expires_at = "2025-12-01T00:00:00Z".to_string();
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "confirm".to_string(),
            rules: vec![expired_rule],
            issued_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: "2025-12-31T00:00:00Z".to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let error = verify_admission_policy(
        &document,
        &VerifyPolicyOptions {
            now: Some(NOW.to_string()),
            expected_host: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "policy_expired");
}

#[test]
fn builds_and_verifies_a_document_with_digests() {
    let mut input = identity_input("Peer");
    input.manifest_digest =
        Some("sha256:abababababababababababababababababababababababababababababababab".to_string());
    input.policy_digest =
        Some("sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".to_string());
    let document = build_identity_document(&input, &REQUESTER_SEED).expect("identity document");
    let verified = ccp_runtime::verify_identity_document(
        &document,
        &ccp_runtime::VerifyIdentityOptions {
            now: Some(NOW.to_string()),
            expected_identity: Some(key_id(&REQUESTER_SEED)),
            manifest_digest: input.manifest_digest.clone(),
            policy_digest: input.policy_digest.clone(),
        },
    )
    .expect("verified");
    assert_eq!(verified.manifest_digest, input.manifest_digest);
    assert_eq!(verified.policy_digest, input.policy_digest);
    assert_eq!(verified.name.as_deref(), Some("Peer"));
    assert_eq!(verified.roles, vec!["requester".to_string()]);
    assert_eq!(verified.endpoints.len(), 1);
}

#[test]
fn signs_a_policy_document() {
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: None,
            version: 1,
            default: "deny".to_string(),
            rules: vec![rule()],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let parsed = ccp_kernel::parse_strict(&document).expect("parse");
    assert_eq!(
        parsed.get("host").and_then(|value| value.as_str()),
        Some(key_id(&host_seed).as_str())
    );
    assert!(parsed.get("signature").is_some());
}

#[test]
fn policy_defaults_to_confirm_or_deny() {
    let host_seed = seed(96);
    for fallback in ["confirm", "deny"] {
        let document = build_admission_policy(
            &AdmissionPolicyInput {
                ccp: None,
                version: 1,
                default: fallback.to_string(),
                rules: vec![rule()],
                issued_at: ISSUED.to_string(),
                expires_at: POLICY_UNTIL.to_string(),
            },
            &host_seed,
        )
        .expect("policy");
        let policy = verify_admission_policy(
            &document,
            &VerifyPolicyOptions {
                now: Some(NOW.to_string()),
                expected_host: None,
            },
        )
        .expect("verified");
        assert_eq!(policy.default, fallback);
    }
}

#[test]
fn builds_a_policy_value_with_rules() {
    let host_seed = seed(96);
    let document = build_admission_policy(
        &AdmissionPolicyInput {
            ccp: Some("0.4-draft".to_string()),
            version: 2,
            default: "confirm".to_string(),
            rules: vec![rule()],
            issued_at: ISSUED.to_string(),
            expires_at: POLICY_UNTIL.to_string(),
        },
        &host_seed,
    )
    .expect("policy");
    let parsed = ccp_kernel::parse_strict(&document).expect("parse");
    assert_eq!(
        parsed.get("ccp").and_then(|value| value.as_str()),
        Some("0.4-draft")
    );
    assert_eq!(parsed.get("version").and_then(|value| value.as_str()), None);
    assert!(parsed
        .get("rules")
        .and_then(|value| value.as_array())
        .is_some());
    assert_eq!(
        parsed
            .get("rules")
            .and_then(|value| value.as_array())
            .map(|items| items.len()),
        Some(1)
    );
}

#[test]
fn uses_canonical_values_in_a_built_document() {
    let document = build_identity_document(&identity_input("Peer"), &REQUESTER_SEED)
        .expect("identity document");
    assert!(document.contains("\"type\":\"ccp.identity.v1\""));
}
