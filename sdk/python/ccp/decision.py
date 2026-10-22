"""The pure §10.3 validation decision.

Separated from the runtime so it can be tested directly against the frozen
validation vectors without performing side effects. The runtime calls this
and then applies the side effects (replay marking, limit reservation,
confirmation, execution) atomically.
"""

from . import schema

DEFAULT_SUPPORTED_CCP = ("0.5-draft", "0.4-draft")


def _is_supported(value, supported):
    labels = (supported,) if isinstance(supported, str) else tuple(supported)
    return value in labels


def decide(grant, signal, signer, now, seen, counters, *,
           intent_spec=None, params_schema=None,
           supported_ccp=DEFAULT_SUPPORTED_CCP):
    """Return the §10.3 decision: ``authorized``,
    ``confirmation_required``, or a rejection code."""
    # 3. protocol compatibility
    if not _is_supported(signal.get("ccp"), supported_ccp):
        return "invalid_request"

    # 4. locate the grant
    if grant is None:
        return "no_matching_grant"

    # 2. authenticate the sender against the grant's requester
    if signer != grant.requester_key:
        return "unauthenticated"
    if signal.get("grant_digest") != grant.manifest_digest:
        return "no_matching_grant"

    # 5. grant state and expiry (explicit lifecycle states first)
    if grant.state == "revoked":
        return "grant_revoked"
    if grant.state == "paused":
        return "grant_paused"
    if grant.state == "suspended":
        return "grant_suspended"
    if grant.state == "expired" or now >= grant.expires_at:
        return "grant_expired"

    # 6. intent enabled
    intent = signal.get("intent")
    if intent not in grant.intents:
        return "intent_not_allowed"

    # 7. parameters against the approved schema
    if intent_spec is None or params_schema is None:
        return "capability_unavailable"
    if not schema.is_valid(signal.get("params"), params_schema):
        return "invalid_request"

    # 8. request expiry and replay
    if now >= signal.get("expires_at", ""):
        return "request_expired"
    if signal.get("request_id") in seen:
        return "replay_detected"

    # 9. cumulative limits
    for name, maximum in (grant.limits or {}).items():
        if counters.get(name, 0) + 1 > maximum:
            return "limit_exceeded"

    # 10. required host capabilities
    required = intent_spec.get("required_capabilities", [])
    if not set(required).issubset(set(grant.capabilities or [])):
        return "capability_unavailable"

    # 11. confirmation policy
    if confirmation_policy(grant, intent_spec, intent) == "per_action":
        return "confirmation_required"

    return "authorized"


def confirmation_policy(grant, intent_spec, intent_name):
    policy = (grant.confirmation or {}).get(intent_name)
    if policy in ("none", "per_action"):
        return policy
    policy = intent_spec.get("confirmation")
    if policy in ("none", "per_action"):
        return policy
    return "per_action"
