//! Deterministic property tests for the canonical parser and the decision.

use std::collections::{HashMap, HashSet};

use ccp_kernel::decision::decide;
use ccp_kernel::json::{parse_strict, serialize};
use ccp_kernel::schema;
use ccp_kernel::Value;
use num_bigint::BigUint;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next() % bound
        }
    }
}

const STRINGS: &[char] = &[
    'a',
    'Z',
    '0',
    ' ',
    '\u{e9}',
    '\u{301}',
    '\u{1f600}',
    '\u{0}',
    '\u{1f}',
    '"',
    '\\',
    '/',
    '~',
    '\u{4f8b}',
];

const ERROR_CODES: &[&str] = &["malformed", "duplicate", "negative", "float", "constant"];

fn random_string(rng: &mut Rng, maximum: usize) -> String {
    let length = rng.below(maximum as u64 + 1) as usize;
    (0..length)
        .map(|_| STRINGS[rng.below(STRINGS.len() as u64) as usize])
        .collect()
}

fn random_value(rng: &mut Rng, depth: usize) -> Value {
    let choices = if depth >= 3 { 4 } else { 6 };
    match rng.below(choices) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 1),
        2 => {
            if rng.below(10) == 0 {
                Value::Int(BigUint::parse_bytes(b"18446744073709551616", 10).unwrap())
            } else {
                Value::Int(BigUint::from(rng.below(1_000_000)))
            }
        }
        3 => Value::Str(random_string(rng, 8)),
        4 => Value::Array(
            (0..rng.below(4))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut entries = Vec::new();
            for index in 0..rng.below(4) {
                let key = format!("{}{}", random_string(rng, 4), index);
                entries.push((key, random_value(rng, depth + 1)));
            }
            Value::Object(entries)
        }
    }
}

#[test]
fn canonical_round_trip_is_idempotent() {
    let mut rng = Rng(0x2026_1022);
    for _ in 0..500 {
        let value = random_value(&mut rng, 0);
        let canonical = serialize(&value).unwrap();
        let parsed = parse_strict(&canonical).unwrap();
        assert_eq!(serialize(&parsed).unwrap(), canonical);
    }
}

#[test]
fn parser_never_panics_on_random_text() {
    const POOL: &[char] = &[
        '{',
        '}',
        '[',
        ']',
        '"',
        '\\',
        ':',
        ',',
        '0',
        '1',
        '-',
        '.',
        'e',
        'E',
        'N',
        'I',
        't',
        'f',
        'n',
        'u',
        'a',
        ' ',
        '\n',
        '\t',
        '\u{e9}',
        '\u{1f600}',
        '\u{0}',
    ];
    let mut rng = Rng(7);
    for _ in 0..500 {
        let length = rng.below(20) as usize;
        let text: String = (0..length)
            .map(|_| POOL[rng.below(POOL.len() as u64) as usize])
            .collect();
        match parse_strict(&text) {
            Ok(value) => {
                let canonical = serialize(&value).unwrap();
                let reparsed = parse_strict(&canonical).unwrap();
                assert_eq!(serialize(&reparsed).unwrap(), canonical);
            }
            Err(code) => assert!(ERROR_CODES.contains(&code.as_str()), "{code}"),
        }
    }
}

const BASE_GRANT: &str = r#"{"id":"g-1","requester_key":"key:ed25519:requester","contact_id":"c-1","manifest_digest":"sha256:digest","manifest_version":1,"intents":["example.lookup"],"limits":{"calls_per_hour":10},"created_at":"2026-10-22T10:00:00Z","expires_at":"2026-10-22T13:00:00Z","confirmation":{"example.lookup":"none"},"capabilities":["store.read"],"placement":["local"],"egress":{"network":false},"state":"active","state_reason":null}"#;
const BASE_SIGNAL: &str = r#"{"ccp":"0.4-draft","request_id":"req-1","grant_digest":"sha256:digest","intent":"example.lookup","params":{"item_id":"item-123"},"issued_at":"2026-10-22T12:00:00Z","expires_at":"2026-10-22T12:01:00Z"}"#;
const INTENT_SPEC: &str =
    r#"{"confirmation":"grant-policy","required_capabilities":["store.read"]}"#;
const PARAMS_SCHEMA: &str = r#"{"additionalProperties":false,"properties":{"item_id":{"type":"string"}},"required":["item_id"],"type":"object"}"#;

const OUTCOMES: &[&str] = &[
    "authorized",
    "confirmation_required",
    "invalid_request",
    "unauthenticated",
    "no_matching_grant",
    "intent_not_allowed",
    "grant_expired",
    "grant_revoked",
    "grant_paused",
    "grant_suspended",
    "request_expired",
    "replay_detected",
    "limit_exceeded",
    "capability_unavailable",
];

#[test]
fn decision_is_deterministic_and_known() {
    let grant_base = parse_strict(BASE_GRANT).unwrap();
    let signal_base = parse_strict(BASE_SIGNAL).unwrap();
    let intent_spec = parse_strict(INTENT_SPEC).unwrap();
    let params_schema = parse_strict(PARAMS_SCHEMA).unwrap();
    let states = ["active", "paused", "suspended", "revoked", "expired"];
    let times = [
        "2026-10-22T11:00:00Z",
        "2026-10-22T12:00:30Z",
        "2026-10-22T13:00:00Z",
    ];
    let mut rng = Rng(99);

    for _ in 0..500 {
        let mut grant = grant_base.clone();
        grant.set(
            "state",
            Value::Str(states[rng.below(5) as usize].to_string()),
        );
        grant.set(
            "expires_at",
            Value::Str(times[rng.below(3) as usize].to_string()),
        );
        grant.set(
            "limits",
            Value::Object(vec![(
                "calls_per_hour".to_string(),
                Value::Int(BigUint::from(rng.below(15))),
            )]),
        );

        let mut signal = signal_base.clone();
        signal.set(
            "expires_at",
            Value::Str(times[rng.below(3) as usize].to_string()),
        );
        if rng.below(5) == 0 {
            signal.set("params", Value::Object(vec![]));
        }
        if rng.below(10) == 0 {
            signal.set("intent", Value::Str("files.search".to_string()));
        }

        let seen = if rng.below(5) == 0 {
            HashSet::from(["req-1".to_string()])
        } else {
            HashSet::new()
        };
        let counters =
            HashMap::from([("calls_per_hour".to_string(), BigUint::from(rng.below(15)))]);
        let now = times[rng.below(3) as usize];
        let signer = if rng.below(10) == 0 {
            "key:ed25519:other"
        } else {
            "key:ed25519:requester"
        };

        let first = decide(
            Some(&grant),
            &signal,
            signer,
            now,
            &seen,
            &counters,
            Some(&intent_spec),
            Some(&params_schema),
            &["0.5-draft", "0.4-draft"],
        );
        let second = decide(
            Some(&grant),
            &signal,
            signer,
            now,
            &seen,
            &counters,
            Some(&intent_spec),
            Some(&params_schema),
            &["0.5-draft", "0.4-draft"],
        );
        assert_eq!(first, second);
        assert!(OUTCOMES.contains(&first.as_str()), "{first}");
    }
}

#[test]
fn schema_portability_fixes() {
    let length = parse_strict(r#"{"maxLength":1,"minLength":1,"type":"string"}"#).unwrap();
    assert!(schema::is_valid(
        &Value::Str("\u{1f600}".to_string()),
        &length
    ));

    let multiple = parse_strict(r#"{"multipleOf":2,"type":"integer"}"#).unwrap();
    let huge = Value::Int(BigUint::parse_bytes(b"18446744073709551616", 10).unwrap());
    assert!(schema::is_valid(&huge, &multiple));
}
