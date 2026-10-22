#!/usr/bin/env python3
"""
CCP signal-validation reference + conformance test-vector generator.

Implements the grant-matching and validation-decision rules from
CCP_Working_Draft_v0.5.md §10.3 and §26.1 as a pure, deterministic
function, and writes `validation.json`.

Scope: the DECISION layer. Signature verification is the crypto layer's
job (see ed25519.json); here `signer` is the already-authenticated
requester key. Parsing is likewise assumed done: malformed documents are
covered by canonical-json.json.

Pure standard library; no third-party dependencies.

Run:  python3 validation.py
Exit: 0 when every vector passes its self-check.
"""

import copy
import json
import os

CCP_VERSION = "0.4-draft"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))
SUPPORTED_PROTOCOL = "0.4"

# Intent parameter schemas (a minimal §25.3 JSON Schema subset).
SCHEMAS = {
    "example.lookup": {
        "type": "object",
        "properties": {"item_id": {"type": "string"}},
        "required": ["item_id"],
        "additionalProperties": False,
    },
}

# Host capabilities each intent requires (§26.4).
REQUIRED_CAPS = {
    "example.lookup": ["store.read"],
}


def _schema_check(value, schema):
    """Minimal JSON Schema subset checker (§25.3).

    Supports the subset used by these vectors: object/properties/required/
    additionalProperties, array/items, string, integer, boolean, enum,
    const. Unknown keywords are ignored; this is a reference, not a full
    validator.
    """
    t = schema.get("type")
    if t == "object":
        if not isinstance(value, dict):
            return False
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            if not set(value.keys()).issubset(set(props.keys())):
                return False
        for name, sub in props.items():
            if name in value and not _schema_check(value[name], sub):
                return False
        for name in schema.get("required", []):
            if name not in value:
                return False
        return True
    if t == "array":
        if not isinstance(value, list):
            return False
        items = schema.get("items")
        if items is not None:
            return all(_schema_check(v, items) for v in value)
        return True
    if t == "string":
        return isinstance(value, str)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "boolean":
        return isinstance(value, bool)
    if "enum" in schema:
        return value in schema["enum"]
    if "const" in schema:
        return value == schema["const"]
    return True


def validate(now, grant, signal, signer, seen, counters):
    """Return the §10.3 decision for one signal.

    Success is `authorized` or `confirmation_required`; anything else is
    a rejection error code. The order of checks mirrors §10.3 so that the
    precedence between simultaneous failures is pinned too.
    """
    # 3. protocol compatibility
    if not signal.get("ccp", "").startswith(SUPPORTED_PROTOCOL + "-"):
        return "invalid_request"

    # 4. find an active grant matching requester + digest
    if grant is None:
        return "no_matching_grant"

    # 2. authenticate sender against the grant's requester
    if signer != grant.get("requester_key"):
        return "unauthenticated"

    if signal.get("grant_digest") != grant.get("manifest_digest"):
        return "no_matching_grant"

    # 5. grant state and expiry
    state = grant.get("state", "active")
    if state == "revoked":
        return "grant_revoked"
    if state == "paused":
        return "grant_paused"
    if state == "suspended":
        return "grant_suspended"
    if state == "expired" or now > grant.get("expires_at", ""):
        return "grant_expired"

    # 6. intent enabled
    if signal.get("intent") not in grant.get("intents", []):
        return "intent_not_allowed"

    # 7. params validated against the intent schema
    schema = SCHEMAS.get(signal.get("intent"))
    if schema is not None and not _schema_check(signal.get("params"), schema):
        return "invalid_request"

    # 8. request expiry and replay
    if now > signal.get("expires_at", ""):
        return "request_expired"
    if signal.get("request_id") in seen:
        return "replay_detected"

    # 9. cumulative limits
    for name, maxv in grant.get("limits", {}).items():
        if counters.get(name, 0) + 1 > maxv:
            return "limit_exceeded"

    # 10. required host capabilities
    required = REQUIRED_CAPS.get(signal.get("intent"), [])
    if not set(required).issubset(set(grant.get("capabilities", []))):
        return "capability_unavailable"

    # 11. confirmation policy
    policy = grant.get("confirmation", {}).get(signal.get("intent"), "per_action")
    if policy == "per_action":
        return "confirmation_required"

    return "authorized"


# ---------------------------------------------------------------------------
# Vectors
# ---------------------------------------------------------------------------

# Opaque identifiers; the crypto behind them is tested in ed25519.json.
KEY = "key:ed25519:AAAABBBBCCCCDDDDEEEEFFFF0000111122223333"
OTHER_KEY = "key:ed25519:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
DIGEST = "sha256:" + ("ab" * 32)


def _base():
    return {
        "grant": {
            "id": "g-0001",
            "requester_key": KEY,
            "contact_id": "c-0001",
            "manifest_digest": DIGEST,
            "manifest_version": 1,
            "intents": ["example.lookup"],
            "limits": {"calls_per_hour": 10},
            "created_at": "2026-10-22T10:00:00Z",
            "expires_at": "2026-10-22T13:00:00Z",
            "confirmation": {"example.lookup": "none"},
            "capabilities": ["store.read"],
            "placement": ["local"],
            "egress": {"network": False},
            "state": "active",
            "state_reason": None,
        },
        "signal": {
            "ccp": "0.4-draft",
            "request_id": "req-0001",
            "grant_digest": DIGEST,
            "intent": "example.lookup",
            "params": {"item_id": "item-123"},
            "issued_at": "2026-10-22T12:00:00Z",
            "expires_at": "2026-10-22T12:01:00Z",
        },
        "signer": KEY,
        "context": {
            "now": "2026-10-22T12:00:30Z",
            "seen": [],
            "counters": {"calls_per_hour": 0},
        },
    }


# (id, name, expected, overrides). `overrides` replaces top-level keys
# grant/signal/signer/context; grant and signal/context are shallow-merged
# onto the base so a single mutated field is isolated per case.
CASES = [
    ("v-001", "authorized (read, no confirmation)", "authorized", {}),
    ("v-002", "confirmation required", "confirmation_required",
     {"grant": {"confirmation": {"example.lookup": "per_action"}}}),
    ("v-003", "unsupported protocol version", "invalid_request",
     {"signal": {"ccp": "0.2-draft"}}),
    ("v-004", "no matching grant", "no_matching_grant", {"grant": None}),
    ("v-005", "unauthenticated signer", "unauthenticated", {"signer": OTHER_KEY}),
    ("v-006", "grant digest mismatch", "no_matching_grant",
     {"signal": {"grant_digest": "sha256:" + ("cd" * 32)}}),
    ("v-007", "grant revoked", "grant_revoked", {"grant": {"state": "revoked"}}),
    ("v-008", "grant paused", "grant_paused", {"grant": {"state": "paused"}}),
    ("v-009", "grant suspended", "grant_suspended",
     {"grant": {"state": "suspended"}}),
    ("v-010", "grant expired", "grant_expired",
     {"grant": {"expires_at": "2026-10-22T11:00:00Z"}}),
    ("v-011", "intent not allowed", "intent_not_allowed",
     {"signal": {"intent": "files.search"}}),
    ("v-012", "params invalid (missing required)", "invalid_request",
     {"signal": {"params": {}}}),
    ("v-013", "params invalid (wrong type)", "invalid_request",
     {"signal": {"params": {"item_id": 123}}}),
    ("v-014", "params invalid (extra property)", "invalid_request",
     {"signal": {"params": {"item_id": "item-123", "extra": 1}}}),
    ("v-015", "request expired", "request_expired",
     {"signal": {"expires_at": "2026-10-22T12:00:00Z"}}),
    ("v-016", "replay detected", "replay_detected",
     {"context": {"seen": ["req-0001"]}}),
    ("v-017", "limit exceeded", "limit_exceeded",
     {"context": {"counters": {"calls_per_hour": 10}}}),
    ("v-018", "capability unavailable", "capability_unavailable",
     {"grant": {"capabilities": []}}),
]


def build_vectors():
    vectors = []
    for cid, name, expected, overrides in CASES:
        b = _base()
        if "grant" in overrides:
            if overrides["grant"] is None:
                b["grant"] = None
            else:
                b["grant"] = copy.deepcopy(b["grant"])
                b["grant"].update(overrides["grant"])
        if "signal" in overrides:
            b["signal"] = copy.deepcopy(b["signal"])
            b["signal"].update(overrides["signal"])
        if "signer" in overrides:
            b["signer"] = overrides["signer"]
        if "context" in overrides:
            b["context"] = copy.deepcopy(b["context"])
            b["context"].update(overrides["context"])

        got = validate(b["context"]["now"], b["grant"], b["signal"],
                       b["signer"], set(b["context"]["seen"]),
                       b["context"]["counters"])
        assert got == expected, (cid, got, expected)

        vectors.append({
            "id": cid,
            "name": name,
            "grant": b["grant"],
            "signal": b["signal"],
            "signer": b["signer"],
            "context": b["context"],
            "expected": expected,
        })
    return vectors


def main():
    data = {
        "ccp": CCP_VERSION,
        "rule": "signal validation (§10.3) and grant matching (§26.1)",
        "vectors": build_vectors(),
    }
    with open(os.path.join(OUT_DIR, "validation.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote validation.json  (%d vectors)" % len(data["vectors"]))
    print("self-check OK")


if __name__ == "__main__":
    main()
