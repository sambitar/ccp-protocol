//! The kernel-level CCP decision, runnable.
//!
//! Run with `cargo run --example quickstart --manifest-path kernel/Cargo.toml`.
//!
//! This is the kernel, not a runtime: it verifies and decides over values you
//! pass in. Grant persistence, replay, limits, confirmation, and host
//! mediation live in the TypeScript and Python runtimes.

use std::collections::{HashMap, HashSet};

use ccp_kernel::{decision::decide, parse_strict, serialize};

const GRANT: &str = r#"{
  "id": "g-1",
  "requester_key": "key:ed25519:requester",
  "manifest_digest": "sha256:demo",
  "intents": ["example.lookup"],
  "limits": {"calls_per_hour": 5},
  "expires_at": "2030-01-01T00:00:00Z",
  "capabilities": ["store.read"],
  "confirmation": {"example.lookup": "none"},
  "state": "active"
}"#;

const SIGNAL: &str = r#"{
  "ccp": "0.5-draft",
  "request_id": "req-1",
  "grant_digest": "sha256:demo",
  "intent": "example.lookup",
  "params": {"item_id": "item-123"},
  "issued_at": "2026-10-22T11:59:00Z",
  "expires_at": "2026-10-22T12:01:00Z"
}"#;

const INTENT_SPEC: &str = r#"{
  "required_capabilities": ["store.read"],
  "confirmation": "none"
}"#;

const PARAMS_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {"item_id": {"type": "string"}},
  "required": ["item_id"],
  "additionalProperties": false
}"#;

fn decide_with(grant_text: &str) -> String {
    let grant = parse_strict(grant_text).expect("grant");
    let signal = parse_strict(SIGNAL).expect("signal");
    let intent_spec = parse_strict(INTENT_SPEC).expect("intent spec");
    let params_schema = parse_strict(PARAMS_SCHEMA).expect("params schema");
    let seen: HashSet<String> = HashSet::new();
    let counters: HashMap<String, num_bigint::BigUint> = HashMap::new();

    decide(
        Some(&grant),
        &signal,
        "key:ed25519:requester",
        "2026-10-22T12:00:00Z",
        &seen,
        &counters,
        Some(&intent_spec),
        Some(&params_schema),
        &["0.5-draft", "0.4-draft"],
    )
}

fn main() {
    let grant = parse_strict(GRANT).expect("grant");
    println!("canonical grant: {}", serialize(&grant).expect("serialize"));

    println!("decision: {}", decide_with(GRANT));

    let revoked = GRANT.replace("\"state\": \"active\"", "\"state\": \"revoked\"");
    println!("after revoke: {}", decide_with(&revoked));
}
