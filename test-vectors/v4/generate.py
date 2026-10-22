#!/usr/bin/env python3
"""Generate and self-check the v4 conformance vectors.

v4 pins §25.8: identity documents (25.8.1) and admission policies (25.8.3).
Introduction is prose-only (§25.8.2). Every vector is signed with a fixed
seed so the file is reproducible.

Usage: /usr/bin/python3 test-vectors/v4/generate.py
"""

import base64
import hashlib
import importlib.util
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2", "generate.py")

spec = importlib.util.spec_from_file_location("ccp_v2_for_v4", V2)
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)

CCP_VERSION = "0.5-draft"
NOW = "2026-10-22T12:00:00Z"
ISSUED = "2026-10-22T00:00:00Z"
UNTIL = "2027-10-22T00:00:00Z"
POLICY_UNTIL = "2027-01-01T00:00:00Z"
DIGEST = "sha256:" + ("ab" * 32)
OTHER_DIGEST = "sha256:" + ("cd" * 32)

HOST_SEED = bytes(range(32))
REQUESTER_SEED = bytes(range(32, 64))
OTHER_SEED = bytes(range(64, 96))


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_pair(seed):
    private = Ed25519PrivateKey.from_private_bytes(seed)
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, "key:ed25519:" + b64url_encode(raw)


HOST_PRIVATE, HOST_KEY = key_pair(HOST_SEED)
REQUESTER_PRIVATE, REQUESTER_KEY = key_pair(REQUESTER_SEED)
OTHER_PRIVATE, OTHER_KEY = key_pair(OTHER_SEED)
KNOWN_KEYS = {
    HOST_KEY: HOST_PRIVATE,
    REQUESTER_KEY: REQUESTER_PRIVATE,
    OTHER_KEY: OTHER_PRIVATE,
}


def sign(body, private):
    body = {key: value for key, value in body.items() if key != "signature"}
    body["signature"] = "ed25519:" + b64url_encode(
        private.sign(v2.serialize(body).encode("utf-8")))
    return v2.serialize(body)


def verify_wire(document):
    """Check the signature against the key the document names."""
    body = v2.parse_strict(document)
    identity = body["identity"] if "identity" in body else body["host"]
    private = KNOWN_KEYS.get(identity)
    if private is None:
        raise AssertionError("vector uses an unknown identity")
    message = v2.serialize(
        {key: value for key, value in body.items() if key != "signature"}
    ).encode("utf-8")
    signature = body["signature"]
    assert signature.startswith("ed25519:")
    private.public_key().verify(b64url_decode(signature[len("ed25519:"):]),
                                message)


# ---------------------------------------------------------------------------
# identity documents
# ---------------------------------------------------------------------------

def base_identity(**overrides):
    body = {
        "ccp": CCP_VERSION,
        "type": "ccp.identity.v1",
        "identity": HOST_KEY,
        "name": "Example Service",
        "roles": ["provider"],
        "endpoints": [{
            "transport": "https",
            "manifest": "https://example.com/manifest",
            "signal": "https://example.com/ccp",
        }],
        "manifest_digest": DIGEST,
        "policy_digest": OTHER_DIGEST,
        "issued_at": ISSUED,
        "expires_at": UNTIL,
    }
    body.update(overrides)
    return body


IDENTITY_CASES = [
    ("id-001", "full document", base_identity(), HOST_PRIVATE, "valid", {}),
    ("id-002", "minimal document",
     {"ccp": CCP_VERSION, "type": "ccp.identity.v1", "identity": HOST_KEY,
      "issued_at": ISSUED, "expires_at": UNTIL},
     HOST_PRIVATE, "valid", {}),
    ("id-003", "expired",
     base_identity(issued_at="2025-01-01T00:00:00Z",
                   expires_at="2025-06-01T00:00:00Z"),
     HOST_PRIVATE, "identity_expired", {}),
    ("id-004", "not yet valid",
     base_identity(issued_at="2027-06-01T00:00:00Z",
                   expires_at="2028-01-01T00:00:00Z"),
     HOST_PRIVATE, "identity_expired", {}),
    ("id-005", "signature by another key",
     base_identity(), OTHER_PRIVATE, "unauthenticated", {}),
    ("id-006", "known contact has another key",
     base_identity(), HOST_PRIVATE, "identity_changed",
     {"expected_identity": OTHER_KEY}),
    ("id-007", "manifest digest mismatch",
     base_identity(), HOST_PRIVATE, "manifest_mismatch",
     {"manifest_digest": OTHER_DIGEST}),
    ("id-008", "policy digest mismatch",
     base_identity(), HOST_PRIVATE, "policy_mismatch",
     {"policy_digest": DIGEST}),
    ("id-009", "unknown role",
     base_identity(roles=["provider", "admin"]),
     HOST_PRIVATE, "invalid_request", {}),
    ("id-010", "endpoint without a uri",
     base_identity(endpoints=[{"transport": "https"}]),
     HOST_PRIVATE, "invalid_request", {}),
    ("id-011", "expiry before issue",
     base_identity(issued_at=UNTIL, expires_at=ISSUED),
     HOST_PRIVATE, "invalid_request", {}),
    ("id-012", "wrong document type",
     base_identity(type="ccp.manifest.v1"),
     HOST_PRIVATE, "invalid_request", {}),
    ("id-013", "unsupported label",
     base_identity(ccp="0.6-draft"),
     HOST_PRIVATE, "invalid_request", {}),
    ("id-014", "identity key is not a key id",
     base_identity(identity="key:rsa:abc"),
     HOST_PRIVATE, "invalid_request", {}),
]


def build_identity_vectors():
    vectors = []
    for cid, name, body, private, expected, options in IDENTITY_CASES:
        document = sign(body, private)
        if expected == "valid":
            verify_wire(document)
        vector = {
            "id": cid,
            "name": name,
            "document": document,
            "now": NOW,
            "expected": expected,
        }
        vector.update(options)
        vectors.append(vector)
    return vectors


# ---------------------------------------------------------------------------
# policies
# ---------------------------------------------------------------------------

def base_rule(**overrides):
    rule = {
        "id": "r-read",
        "contacts": ["c-agent-1"],
        "intents": ["files.search", "calendar.read"],
        "risk": "read",
        "limits": {"calls_per_hour": 60},
        "confirmation": "none",
        "expires_at": POLICY_UNTIL,
    }
    rule.update(overrides)
    for name in [key for key, value in rule.items() if value is None]:
        del rule[name]
    return rule


PAY_RULE = {
    "id": "r-pay",
    "requesters": [REQUESTER_KEY],
    "intents": ["payment.address.resolve"],
    "risk": "disclose",
    "destinations": ["wallet:acct-9"],
    "confirmation": "none",
    "expires_at": POLICY_UNTIL,
}


def base_policy(**overrides):
    body = {
        "ccp": CCP_VERSION,
        "type": "ccp.admission-policy.v1",
        "host": HOST_KEY,
        "version": 1,
        "default": "confirm",
        "rules": [base_rule(), dict(PAY_RULE)],
        "issued_at": ISSUED,
        "expires_at": POLICY_UNTIL,
    }
    body.update(overrides)
    return body


POLICY_CASES = [
    ("pol-001", "read and disclose rules",
     base_policy(), HOST_PRIVATE, "valid", {}),
    ("pol-002", "default allow",
     base_policy(default="allow"), HOST_PRIVATE, "invalid_request", {}),
    ("pol-003", "rule names neither contacts nor requesters",
     base_policy(rules=[base_rule(contacts=None)]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-004", "write risk is not admittable",
     base_policy(rules=[base_rule(risk="write")]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-005", "disclose without destinations",
     base_policy(rules=[base_rule(risk="disclose", destinations=None)]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-006", "duplicate rule ids",
     base_policy(rules=[base_rule(), base_rule()]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-007", "rule outlives the policy",
     base_policy(rules=[base_rule(expires_at="2028-01-01T00:00:00Z")]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-008", "expired policy",
     base_policy(issued_at="2025-01-01T00:00:00Z",
                 expires_at="2025-06-01T00:00:00Z",
                 rules=[base_rule(expires_at="2025-06-01T00:00:00Z")]),
     HOST_PRIVATE, "policy_expired", {}),
    ("pol-009", "signature by another key",
     base_policy(), OTHER_PRIVATE, "unauthenticated", {}),
    ("pol-010", "host differs from the known identity",
     base_policy(), HOST_PRIVATE, "identity_changed",
     {"expected_host": OTHER_KEY}),
    ("pol-011", "confirmation must be none",
     base_policy(rules=[base_rule(confirmation="per_action")]),
     HOST_PRIVATE, "invalid_request", {}),
    ("pol-012", "short-lived rule inside a longer policy",
     base_policy(expires_at="2028-01-01T00:00:00Z",
                 rules=[base_rule(expires_at="2026-12-01T00:00:00Z")]),
     HOST_PRIVATE, "valid", {}),
    ("pol-013", "default deny",
     base_policy(default="deny"), HOST_PRIVATE, "valid", {}),
]


def build_policy_vectors():
    vectors = []
    for cid, name, body, private, expected, options in POLICY_CASES:
        document = sign(body, private)
        if expected == "valid":
            verify_wire(document)
        vector = {
            "id": cid,
            "name": name,
            "document": document,
            "now": NOW,
            "expected": expected,
        }
        vector.update(options)
        vectors.append(vector)
    return vectors


# ---------------------------------------------------------------------------
# admissions
# ---------------------------------------------------------------------------

ADMISSION_CASES = [
    ("adm-001", "contact rule matches", "pol-001", "allow", "r-read", {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "files.search", "risk": "read"}),
    ("adm-002", "unknown contact falls back to the default", "pol-001",
     "confirm", None, {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-stranger",
      "intent": "files.search", "risk": "read"}),
    ("adm-003", "intent not listed falls back", "pol-001", "confirm", None, {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "contacts.read", "risk": "read"}),
    ("adm-004", "write risk is never admitted", "pol-001", "deny", None, {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "files.search", "risk": "write"}),
    ("adm-005", "expired rule is skipped", "pol-012", "confirm", None,
     {"now": "2026-12-15T00:00:00Z"},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "files.search", "risk": "read"}),
    ("adm-006", "requester rule matches by key", "pol-001", "allow", "r-pay", {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-anyone",
      "intent": "payment.address.resolve", "risk": "disclose",
      "destination": "wallet:acct-9"}),
    ("adm-007", "requester rule rejects another key", "pol-001",
     "confirm", None, {},
     {"requester_key": OTHER_KEY, "contact_id": "c-anyone",
      "intent": "payment.address.resolve", "risk": "disclose",
      "destination": "wallet:acct-9"}),
    ("adm-008", "unpinned destination is not admitted", "pol-001",
     "confirm", None, {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-anyone",
      "intent": "payment.address.resolve", "risk": "disclose",
      "destination": "wallet:acct-1"}),
    ("adm-009", "default deny refuses the fallback", "pol-013",
     "deny", None, {},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-stranger",
      "intent": "files.search", "risk": "read"}),
    ("adm-010", "policy expired at evaluation time", "pol-001",
     "deny", None, {"verify_now": NOW, "now": "2027-06-01T00:00:00Z"},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "files.search", "risk": "read"}),
    ("adm-011", "a revoked grant is not re-created", "pol-001",
     "deny", "r-read",
     {"revoked_rule": "r-read", "expected_reason": "grant_revoked"},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-agent-1",
      "intent": "files.search", "risk": "read"}),
    ("adm-012", "revocation is scoped to one rule", "pol-001",
     "allow", "r-pay", {"revoked_rule": "r-read"},
     {"requester_key": REQUESTER_KEY, "contact_id": "c-anyone",
      "intent": "payment.address.resolve", "risk": "disclose",
      "destination": "wallet:acct-9"}),
]


ADMITTABLE_RISK = {"read", "disclose"}


def policy_digest_of(document):
    body = v2.parse_strict(document)
    body.pop("signature", None)
    return "sha256:" + hashlib.sha256(
        v2.serialize(body).encode("utf-8")).hexdigest()


def grant_id(document, rule_id, request):
    material = v2.serialize({
        "intent": request["intent"],
        "policy": policy_digest_of(document),
        "requester": request["requester_key"],
        "rule": rule_id,
    }).encode("utf-8")
    return "pg-" + hashlib.sha256(material).hexdigest()[:32]


def reference_admit(document, policy, request, revoked=()):
    if request["now"] > policy["expires_at"]:
        return "deny", None, "policy_expired"
    if request["risk"] not in ADMITTABLE_RISK:
        return "deny", None, "risk_not_admittable"
    for rule in policy["rules"]:
        if request["now"] > rule["expires_at"]:
            continue
        if request["intent"] not in rule["intents"]:
            continue
        if rule["risk"] != request["risk"]:
            continue
        if "contacts" in rule and request["contact_id"] not in rule["contacts"]:
            continue
        if ("requesters" in rule
                and request["requester_key"] not in rule["requesters"]):
            continue
        if rule["risk"] == "disclose":
            if (request.get("destination") is None
                    or request["destination"] not in rule["destinations"]):
                continue
        if revoked and grant_id(document, rule["id"], request) in revoked:
            return "deny", rule["id"], "grant_revoked"
        return "allow", rule["id"], "rule_matched"
    if policy["default"] == "deny":
        return "deny", None, "default_deny"
    return "confirm", None, "default_confirm"


def build_admission_vectors(policies):
    vectors = []
    for cid, name, policy_id, expected, rule, options, request in ADMISSION_CASES:
        request = dict(request)
        request["now"] = options.get("now", NOW)
        document = policies[policy_id]
        policy = v2.parse_strict(document)

        revoked = []
        if "revoked_rule" in options:
            revoked.append(grant_id(document, options["revoked_rule"], request))

        got, rule_id, reason = reference_admit(document, policy, request, revoked)
        assert (got, rule_id) == (expected, rule), (cid, got, rule_id)
        if "expected_reason" in options:
            assert reason == options["expected_reason"], (cid, reason)

        vector = {
            "id": cid,
            "name": name,
            "policy": document,
            "verify_now": options.get("verify_now", NOW),
            "request": request,
            "expected": expected,
        }
        if rule is not None:
            vector["expected_rule"] = rule
        if revoked:
            vector["revoked"] = revoked
        if "expected_reason" in options:
            vector["expected_reason"] = options["expected_reason"]
        vectors.append(vector)
    return vectors


# ---------------------------------------------------------------------------

def _write(name, data):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("wrote %s  (%d vectors)"
          % (name, len(data["identities"]) + len(data["policies"])
             + len(data["admissions"])))


def main():
    identities = build_identity_vectors()
    policies = build_policy_vectors()
    valid = {
        vector["id"]: vector["document"]
        for vector in policies
        if vector["expected"] == "valid"
    }
    admissions = build_admission_vectors(valid)

    _write("identity.json", {
        "ccp": CCP_VERSION,
        "rule": "identity documents, admission policies, and admission "
                "decisions (§25.8)",
        "identities": identities,
        "policies": policies,
        "admissions": admissions,
    })
    print("self-check OK")


if __name__ == "__main__":
    main()
