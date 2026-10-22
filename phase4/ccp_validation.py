"""Signal-validation decision per CCP Working Draft v0.3 §10.3, §26.1, §10.4.

Implements the fail-closed validation sequence from prose, returning either
``authorized``, ``confirmation_required``, or one of the §10.4 rejection
codes.

The decision layer is downstream of parsing and signature verification: the
vector file supplies an already-authenticated ``signer`` key and a parsed
``signal``. The grant record is the §26.1 local authorization record.

IMPORTANT — inferred profile registry: the prose never gives the concrete
content of the ``example.lookup`` schema. §8.2 only references it by URI
(``schema:example.lookup.params.v1``), and the grant's ``capabilities``
field carries the consumer-selected capabilities rather than the manifest's
``required_capabilities``. To perform steps 7 (schema validation) and 10
(required host capabilities) I had to reconstruct the manifest metadata that
is not present anywhere in prose or vectors:

    example.lookup.required_capabilities = ["store.read"]        (from §8.2)
    example.lookup.params_schema = object with required string
        ``item_id`` and ``additionalProperties: false``           (inferred
        from vectors v-012/v-013/v-014 and the §10.2 example)

See REPORT.md for the full ambiguity discussion.
"""

from __future__ import annotations

SUPPORTED_CCP = "0.3-draft"

# Minimal manifest registry, reconstructed as described above.
PROFILE = {
    "example.lookup": {
        "required_capabilities": ["store.read"],
        "params_schema": {
            "type": "object",
            "properties": {"item_id": {"type": "string"}},
            "required": ["item_id"],
            "additionalProperties": False,
        },
    },
}


def _schema_valid(value, schema) -> bool:
    """Minimal frozen JSON Schema (Draft 2020-12) subset validation."""
    if schema is None:
        return True
    stype = schema.get("type")
    if stype == "object":
        if not isinstance(value, dict):
            return False
        if schema.get("additionalProperties") is False:
            allowed = set(schema.get("properties", {}).keys())
            if any(k not in allowed for k in value):
                return False
        for req in schema.get("required", []):
            if req not in value:
                return False
        for k, subschema in schema.get("properties", {}).items():
            if k in value and not _schema_valid(value[k], subschema):
                return False
        return True
    if stype == "string":
        return isinstance(value, str)
    if stype == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if stype == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if stype == "boolean":
        return isinstance(value, bool)
    if stype == "null":
        return value is None
    if stype == "array":
        if not isinstance(value, list):
            return False
        item_schema = schema.get("items")
        return all(_schema_valid(item, item_schema) for item in value)
    return True


def decide(grant, signal, signer, context) -> str:
    """Return the validation decision for one signal against one grant."""
    now = context.get("now")

    # §10.3 step 3 — protocol compatibility.
    if signal.get("ccp") != SUPPORTED_CCP:
        return "invalid_request"

    # §10.3 step 4 — an active grant matching the requester + digest.
    if grant is None:
        return "no_matching_grant"

    # §10.3 step 2 — authenticate the sender against the grant's key.
    if signer != grant.get("requester_key"):
        return "unauthenticated"

    # §10.3 step 4 — grant/manifest digest match.
    if signal.get("grant_digest") != grant.get("manifest_digest"):
        return "no_matching_grant"

    # §10.3 step 5 — grant not revoked/expired (and the §9.4 lifecycle states).
    state = grant.get("state")
    if state == "revoked":
        return "grant_revoked"
    if state == "paused":
        return "grant_paused"
    if state == "suspended":
        return "grant_suspended"
    if state == "expired" or grant.get("expires_at") <= now:
        return "grant_expired"

    # §10.3 step 6 — requested intent is enabled.
    intent = signal.get("intent")
    if intent not in grant.get("intents", []):
        return "intent_not_allowed"

    # §10.3 step 7 — validate parameters against the approved schema.
    params_schema = PROFILE.get(intent, {}).get("params_schema")
    if not _schema_valid(signal.get("params"), params_schema):
        return "invalid_request"

    # §10.3 step 8 — request expiry and replay protection.
    expires_at = signal.get("expires_at")
    if expires_at is not None and expires_at <= now:
        return "request_expired"
    if signal.get("request_id") in context.get("seen", []):
        return "replay_detected"

    # §10.3 step 9 — cumulative limits (reserve atomically).
    for name, limit in grant.get("limits", {}).items():
        if context.get("counters", {}).get(name, 0) >= limit:
            return "limit_exceeded"

    # §10.3 step 10 — required host capabilities match the grant.
    required = PROFILE.get(intent, {}).get("required_capabilities", [])
    have = set(grant.get("capabilities", []))
    if any(cap not in have for cap in required):
        return "capability_unavailable"

    # §10.3 step 11 — confirmation policy.
    policy = grant.get("confirmation", {}).get(intent, "none")
    if policy == "per_action":
        return "confirmation_required"

    return "authorized"
