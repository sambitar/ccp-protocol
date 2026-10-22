"""Least-authority grant construction (§9.1, §9.2, §26.1).

The helper only ever narrows what a manifest declares: limits cannot exceed
the suggested ceilings, confirmation cannot be relaxed to ``none`` unless an
admission policy admitted the grant, and capabilities, placement, and egress
are derived from the approved intents.
"""

import re
import uuid

from . import crypto
from .audit import utcnow
from .consumer import verify_manifest
from .errors import CCPError
from .model import Grant

CONFIRMATION_POLICIES = frozenset({"none", "per_action"})
GRANT_STATES = frozenset({"active", "paused", "suspended", "revoked", "expired"})
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _timestamp(value, name):
    if not isinstance(value, str) or not _TIMESTAMP.match(value):
        raise CCPError("invalid_request",
                       "%s must be RFC 3339 UTC with second precision" % name)
    return value


def _limit(name, value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CCPError("invalid_request",
                       "limit %s must be a non-negative integer" % name)
    return value


def _requester_key(value):
    try:
        raw = crypto.public_bytes_from_key_id(value)
    except (crypto.CryptoError, ValueError):
        raise CCPError("invalid_request", "requesterKey is not a key id") from None
    if len(raw) != 32:
        raise CCPError("invalid_request", "requesterKey is not 32 bytes")
    return value


def _resolve_limits(definitions, requested):
    suggested = {}
    for definition in definitions:
        for name, value in (definition.get("suggested_limits") or {}).items():
            value = _limit(name, value)
            suggested[name] = (value if name not in suggested
                               else min(suggested[name], value))

    limits = dict(suggested)
    for name, value in (requested or {}).items():
        value = _limit(name, value)
        ceiling = suggested.get(name)
        if ceiling is not None and value > ceiling:
            raise CCPError(
                "invalid_request",
                "limit %s (%d) exceeds the manifest suggestion (%d)"
                % (name, value, ceiling))
        limits[name] = value
    return limits


def _resolve_confirmation(intents, definitions, requested, admitted_by):
    overrides = requested or {}
    for intent in overrides:
        if intent not in intents:
            raise CCPError(
                "invalid_request",
                "confirmation override for an intent that is not enabled: %s"
                % (intent,))

    confirmation = {}
    for intent, definition in zip(intents, definitions):
        base = definition.get("confirmation")
        if base not in CONFIRMATION_POLICIES:
            base = "per_action"
        override = overrides.get(intent)
        if override is None:
            confirmation[intent] = base
            continue
        if override not in CONFIRMATION_POLICIES:
            raise CCPError("invalid_request",
                           "unknown confirmation policy: %s" % (override,))
        if base == "per_action" and override == "none" and admitted_by is None:
            raise CCPError(
                "invalid_request",
                "confirmation for %s cannot be relaxed to none" % (intent,))
        confirmation[intent] = override
    return confirmation


def _resolve_capabilities(definitions, requested):
    required = set()
    for definition in definitions:
        required.update(definition.get("required_capabilities") or [])
    if requested is None:
        return sorted(required)

    supplied = set(requested)
    missing = required - supplied
    if missing:
        raise CCPError("capability_unavailable",
                       "grant is missing required capability: %s"
                       % (",".join(sorted(missing)),))
    extra = supplied - required
    if extra:
        raise CCPError(
            "invalid_request",
            "capability is not required by the enabled intents: %s"
            % (",".join(sorted(extra)),))
    return sorted(supplied)


def _resolve_placement(definitions, requested):
    declared = {definition.get("placement") or "local"
                for definition in definitions}
    if requested is None:
        return sorted(declared)
    requested = list(requested)
    if not requested:
        raise CCPError("invalid_request", "placement must not be empty")
    for placement in requested:
        if placement not in declared:
            raise CCPError(
                "invalid_request",
                "placement is not declared by the enabled intents: %s"
                % (placement,))
    return list(dict.fromkeys(requested))


def _resolve_egress(definitions, requested):
    requested = dict(requested or {})
    network = any((definition.get("data_egress") or {}).get("network") is True
                  for definition in definitions)
    fields = set()
    for definition in definitions:
        fields.update((definition.get("data_egress") or {}).get("fields") or [])

    if "network" in requested and not isinstance(requested["network"], bool):
        raise CCPError("invalid_request", "egress.network must be a boolean")
    if requested.get("network") is True and not network:
        raise CCPError(
            "invalid_request",
            "egress network is not declared by the enabled intents")

    supplied = requested.get("fields")
    if supplied is not None:
        if (not isinstance(supplied, list)
                or any(not isinstance(field, str) for field in supplied)):
            raise CCPError("invalid_request", "egress.fields must be strings")
        for field in supplied:
            if field not in fields:
                raise CCPError(
                    "invalid_request",
                    "egress field is not declared by the enabled intents: %s"
                    % (field,))

    requested["network"] = requested.get("network", network)
    requested["fields"] = list(supplied) if supplied is not None else sorted(fields)
    return requested


def create_grant(*, contact_id, requester_key, manifest, intents, expires_at,
                 grant_id=None, limits=None, confirmation=None,
                 capabilities=None, placement=None, egress=None,
                 created_at=None, state="active", state_reason=None,
                 admitted_by=None):
    """Build a least-authority grant from an approved manifest."""
    verified = verify_manifest(manifest) if isinstance(manifest, str) else manifest

    if not intents:
        raise CCPError("invalid_request",
                       "grant must enable at least one intent")
    intents = list(dict.fromkeys(intents))
    definitions = []
    for intent in intents:
        definition = (verified.intents or {}).get(intent)
        if definition is None:
            raise CCPError("intent_not_allowed",
                           "intent %s is not in the manifest" % (intent,))
        definitions.append(definition)

    _requester_key(requester_key)
    if not isinstance(contact_id, str) or contact_id == "":
        raise CCPError("invalid_request", "contactId is required")

    version = verified.version
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise CCPError("invalid_request",
                       "manifest version must be an integer")

    created_at = _timestamp(created_at or utcnow(), "createdAt")
    _timestamp(expires_at, "expiresAt")
    if expires_at <= created_at:
        raise CCPError("invalid_request", "expiresAt must be after createdAt")

    if state not in GRANT_STATES:
        raise CCPError("invalid_request", "unknown grant state: %s" % (state,))
    if state != "active" and not state_reason:
        raise CCPError(
            "invalid_request",
            "stateReason is required when the grant is not active")

    return Grant(
        id=grant_id or uuid.uuid4().hex,
        requester_key=requester_key,
        contact_id=contact_id,
        manifest_digest=verified.digest,
        manifest_version=version,
        intents=intents,
        limits=_resolve_limits(definitions, limits),
        created_at=created_at,
        expires_at=expires_at,
        confirmation=_resolve_confirmation(
            intents, definitions, confirmation, admitted_by),
        capabilities=_resolve_capabilities(definitions, capabilities),
        placement=_resolve_placement(definitions, placement),
        egress=_resolve_egress(definitions, egress),
        state=state,
        state_reason=state_reason,
    )
