"""Identity documents and admission policies (CCP §25.8).

The identity layer is deliberately separate from the §10.4 decision layer:
these checks happen while a contact is established, before any signal
exists, and their codes must never be returned as a signal outcome.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import canonical, crypto
from .signing import sign_document

IDENTITY_TYPE = "ccp.identity.v1"
POLICY_TYPE = "ccp.admission-policy.v1"
CLOCK_SKEW_SECONDS = 120

_SUPPORTED_LABELS = frozenset({"0.5-draft", "0.4-draft"})
_ROLES = frozenset({"provider", "requester", "consumer"})
_ADMITTABLE_RISK = frozenset({"read", "disclose"})
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class IdentityError(ValueError):
    """An identity-layer result (§25.8), distinct from §10.4 codes."""

    def __init__(self, code, message=""):
        self.code = code
        self.message = message
        super().__init__("%s: %s" % (code, message) if message else code)


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_seconds(timestamp, seconds):
    normalized = (timestamp[:-1] + "+00:00"
                  if timestamp.endswith("Z") else timestamp)
    try:
        moment = datetime.fromisoformat(normalized)
    except ValueError:
        raise IdentityError("invalid_request", "invalid timestamp") from None
    shifted = moment + timedelta(seconds=seconds)
    return shifted.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _string(obj, key, what):
    value = obj.get(key)
    if not isinstance(value, str) or value == "":
        raise IdentityError("invalid_request", "%s.%s is required" % (what, key))
    return value


def _optional_string(obj, key, what):
    if key not in obj:
        return None
    return _string(obj, key, what)


def _strings(obj, key, what):
    value = obj.get(key)
    if not isinstance(value, list) or not value:
        raise IdentityError("invalid_request", "%s.%s is required" % (what, key))
    for item in value:
        if not isinstance(item, str) or item == "":
            raise IdentityError(
                "invalid_request",
                "%s.%s must contain non-empty strings" % (what, key),
            )
    return list(value)


def _optional_strings(obj, key, what):
    if key not in obj:
        return None
    return _strings(obj, key, what)


def _timestamp(obj, key, what):
    value = _string(obj, key, what)
    if not _TIMESTAMP.match(value):
        raise IdentityError(
            "invalid_request",
            "%s.%s must be RFC 3339 UTC with second precision" % (what, key),
        )
    return value


def _assert_digest(value, name):
    if value is not None and not _DIGEST.match(value):
        raise IdentityError("invalid_request", "%s is not a digest" % (name,))


def _assert_key_id(identity):
    try:
        raw = crypto.public_bytes_from_key_id(identity)
    except (crypto.CryptoError, ValueError):
        raise IdentityError("invalid_request", "identity is not a key id") from None
    if len(raw) != 32:
        raise IdentityError("invalid_request", "identity key is not 32 bytes")


def _assert_label(obj):
    label = _string(obj, "ccp", "document")
    if label not in _SUPPORTED_LABELS:
        raise IdentityError("invalid_request", "unsupported ccp label")


def _assert_signature(obj, identity, document):
    signature = obj.get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise IdentityError("invalid_request", "signature is required")
    key = crypto.VerifyingKey.from_key_id(identity)
    if not key.verify(canonical.signing_bytes(document), signature):
        raise IdentityError("unauthenticated", "signature is invalid")


@dataclass
class VerifiedIdentity:
    document: str
    identity: str
    issued_at: str
    expires_at: str
    name: str | None = None
    roles: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    manifest_digest: str | None = None
    policy_digest: str | None = None


@dataclass
class PolicyRule:
    id: str
    intents: list
    risk: str
    confirmation: str
    expires_at: str
    contacts: list | None = None
    requesters: list | None = None
    destinations: list | None = None
    limits: dict | None = None


@dataclass
class VerifiedPolicy:
    document: str
    host: str
    version: int
    default: str
    rules: list
    issued_at: str
    expires_at: str
    digest: str


@dataclass
class AdmissionRequest:
    requester_key: str
    contact_id: str
    intent: str
    risk: str
    now: str
    destination: str | None = None


@dataclass
class AdmissionResult:
    decision: str
    reason: str
    rule_id: str | None = None


@dataclass
class AdmittedGrant:
    id: str
    intent: str
    limits: dict
    expires_at: str


def admitted_grant_id(policy, rule_id, request):
    """Deterministic grant id for a policy rule and requester (§25.8.3).

    Reusing the id is what makes revocation durable: the host stores one
    record, the consumer revokes it, and every later admission of the same
    rule resolves to that revoked record.
    """
    material = canonical.serialize({
        "intent": request.intent,
        "policy": policy.digest,
        "requester": request.requester_key,
        "rule": rule_id,
    }).encode("utf-8")
    digest = canonical.digest_bytes(material)
    return "pg-" + digest[len("sha256:"):][:32]


def identity_digest(document):
    """`sha256:<hex>` over the signing bytes of an identity document."""
    return canonical.digest_bytes(canonical.signing_bytes(document))


def policy_digest(document):
    """`sha256:<hex>` over the signing bytes of an admission policy."""
    return canonical.digest_bytes(canonical.signing_bytes(document))


def build_identity_document(claims, signing_key):
    """Build and sign an identity document; the identity comes from the key."""
    value = {
        "ccp": claims.get("ccp", "0.5-draft"),
        "type": IDENTITY_TYPE,
        "identity": signing_key.key_id,
        "issued_at": claims["issued_at"],
        "expires_at": claims["expires_at"],
    }
    for name in ("name",):
        if name in claims:
            value[name] = claims[name]
    if "roles" in claims:
        value["roles"] = list(claims["roles"])
    if "endpoints" in claims:
        endpoints = []
        for endpoint in claims["endpoints"]:
            entry = {"transport": endpoint["transport"]}
            if "manifest" in endpoint:
                entry["manifest"] = endpoint["manifest"]
            if "signal" in endpoint:
                entry["signal"] = endpoint["signal"]
            endpoints.append(entry)
        value["endpoints"] = endpoints
    if "manifest_digest" in claims:
        value["manifest_digest"] = claims["manifest_digest"]
    if "policy_digest" in claims:
        value["policy_digest"] = claims["policy_digest"]
    return sign_document(value, signing_key)


def verify_identity_document(document, now=None, expected_identity=None,
                             manifest_digest=None, policy_digest=None):
    """Parse and verify an identity document (§25.8.1)."""
    obj = canonical.parse_strict(document)
    if not isinstance(obj, dict):
        raise IdentityError("invalid_request", "identity document must be an object")
    _assert_label(obj)

    if _string(obj, "type", "identity") != IDENTITY_TYPE:
        raise IdentityError("invalid_request", "type is not an identity")

    identity = _string(obj, "identity", "identity")
    _assert_key_id(identity)
    _assert_signature(obj, identity, document)

    if expected_identity is not None and expected_identity != identity:
        raise IdentityError(
            "identity_changed", "identity key differs from the known contact"
        )

    issued_at = _timestamp(obj, "issued_at", "identity")
    expires_at = _timestamp(obj, "expires_at", "identity")
    if expires_at <= issued_at:
        raise IdentityError(
            "invalid_request", "expires_at must sort after issued_at"
        )

    now = now or utcnow()
    if issued_at > _add_seconds(now, CLOCK_SKEW_SECONDS):
        raise IdentityError(
            "identity_expired", "identity document is not yet valid"
        )
    if now > expires_at:
        raise IdentityError("identity_expired", "identity document expired")

    roles = []
    if "roles" in obj:
        roles = _strings(obj, "roles", "identity")
        for role in roles:
            if role not in _ROLES:
                raise IdentityError("invalid_request", "unknown role: %s" % (role,))
        if len(set(roles)) != len(roles):
            raise IdentityError("invalid_request", "roles must be unique")

    endpoints = []
    if "endpoints" in obj:
        raw = obj["endpoints"]
        if not isinstance(raw, list) or not raw:
            raise IdentityError(
                "invalid_request", "endpoints must be a non-empty array"
            )
        for item in raw:
            if not isinstance(item, dict):
                raise IdentityError("invalid_request", "endpoint must be an object")
            entry = {"transport": _string(item, "transport", "endpoint")}
            manifest = _optional_string(item, "manifest", "endpoint")
            signal = _optional_string(item, "signal", "endpoint")
            if manifest is None and signal is None:
                raise IdentityError(
                    "invalid_request", "endpoint must carry manifest or signal"
                )
            if manifest is not None:
                entry["manifest"] = manifest
            if signal is not None:
                entry["signal"] = signal
            endpoints.append(entry)

    doc_manifest = _optional_string(obj, "manifest_digest", "identity")
    _assert_digest(doc_manifest, "manifest_digest")
    if (manifest_digest is not None and doc_manifest is not None
            and manifest_digest != doc_manifest):
        raise IdentityError(
            "manifest_mismatch", "manifest digest does not match the document"
        )

    doc_policy = _optional_string(obj, "policy_digest", "identity")
    _assert_digest(doc_policy, "policy_digest")
    if (policy_digest is not None and doc_policy is not None
            and policy_digest != doc_policy):
        raise IdentityError(
            "policy_mismatch", "policy digest does not match the document"
        )

    return VerifiedIdentity(
        document=document,
        identity=identity,
        issued_at=issued_at,
        expires_at=expires_at,
        name=_optional_string(obj, "name", "identity"),
        roles=roles,
        endpoints=endpoints,
        manifest_digest=doc_manifest,
        policy_digest=doc_policy,
    )


def build_admission_policy(policy, signing_key):
    """Build and sign an admission policy; the host comes from the key."""
    rules = []
    for rule in policy["rules"]:
        entry = {
            "id": rule["id"],
            "intents": list(rule["intents"]),
            "risk": rule["risk"],
            "confirmation": rule["confirmation"],
            "expires_at": rule["expires_at"],
        }
        for name in ("contacts", "requesters", "destinations"):
            if name in rule:
                entry[name] = list(rule[name])
        if "limits" in rule:
            entry["limits"] = dict(rule["limits"])
        rules.append(entry)

    value = {
        "ccp": policy.get("ccp", "0.5-draft"),
        "type": POLICY_TYPE,
        "host": signing_key.key_id,
        "version": policy["version"],
        "default": policy["default"],
        "rules": rules,
        "issued_at": policy["issued_at"],
        "expires_at": policy["expires_at"],
    }
    return sign_document(value, signing_key)


def _read_limits(obj):
    if "limits" not in obj:
        return None
    raw = obj["limits"]
    if not isinstance(raw, dict):
        raise IdentityError("invalid_request", "rule.limits must be an object")
    limits = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise IdentityError(
                "invalid_request", "rule.limits values must be integers"
            )
        if value < 0:
            raise IdentityError("invalid_request", "rule.limits must be non-negative")
        limits[key] = value
    return limits


def _read_rule(value, policy_expires_at):
    if not isinstance(value, dict):
        raise IdentityError("invalid_request", "rule must be an object")
    rule_id = _string(value, "id", "rule")
    intents = _strings(value, "intents", "rule")
    risk = _string(value, "risk", "rule")
    if risk not in _ADMITTABLE_RISK:
        raise IdentityError(
            "invalid_request", "a policy may only admit read or disclose intents"
        )

    contacts = _optional_strings(value, "contacts", "rule")
    requesters = _optional_strings(value, "requesters", "rule")
    if contacts is None and requesters is None:
        raise IdentityError(
            "invalid_request", "a rule must name contacts or requesters"
        )

    destinations = _optional_strings(value, "destinations", "rule")
    if risk == "disclose" and destinations is None:
        raise IdentityError(
            "invalid_request", "a disclose rule must pin destinations"
        )
    if risk == "read" and destinations is not None:
        raise IdentityError(
            "invalid_request", "only a disclose rule may pin destinations"
        )

    confirmation = _string(value, "confirmation", "rule")
    if confirmation != "none":
        raise IdentityError("invalid_request", "rule.confirmation must be none")

    expires_at = _timestamp(value, "expires_at", "rule")
    if expires_at > policy_expires_at:
        raise IdentityError("invalid_request", "rule expires after the policy")

    return PolicyRule(
        id=rule_id,
        intents=intents,
        risk=risk,
        confirmation="none",
        expires_at=expires_at,
        contacts=contacts,
        requesters=requesters,
        destinations=destinations,
        limits=_read_limits(value),
    )


def verify_admission_policy(document, now=None, expected_host=None):
    """Parse and verify an admission policy (§25.8.3)."""
    obj = canonical.parse_strict(document)
    if not isinstance(obj, dict):
        raise IdentityError("invalid_request", "policy must be an object")
    _assert_label(obj)

    if _string(obj, "type", "policy") != POLICY_TYPE:
        raise IdentityError("invalid_request", "type is not a policy")

    host = _string(obj, "host", "policy")
    _assert_key_id(host)
    _assert_signature(obj, host, document)

    if expected_host is not None and expected_host != host:
        raise IdentityError(
            "identity_changed", "policy host differs from the known identity"
        )

    version = obj.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise IdentityError("invalid_request", "version must be an integer")
    if version < 1:
        raise IdentityError("invalid_request", "version is out of range")

    fallback = _string(obj, "default", "policy")
    if fallback not in ("confirm", "deny"):
        raise IdentityError("invalid_request", "default must be confirm or deny")

    issued_at = _timestamp(obj, "issued_at", "policy")
    expires_at = _timestamp(obj, "expires_at", "policy")
    if expires_at <= issued_at:
        raise IdentityError(
            "invalid_request", "expires_at must sort after issued_at"
        )

    raw_rules = obj.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise IdentityError("invalid_request", "rules must be a non-empty array")

    rules = []
    seen = set()
    for value in raw_rules:
        rule = _read_rule(value, expires_at)
        if rule.id in seen:
            raise IdentityError("invalid_request", "rule ids must be unique")
        seen.add(rule.id)
        rules.append(rule)

    now = now or utcnow()
    if now > expires_at:
        raise IdentityError("policy_expired", "admission policy expired")

    return VerifiedPolicy(
        document=document,
        host=host,
        version=version,
        default=fallback,
        rules=rules,
        issued_at=issued_at,
        expires_at=expires_at,
        digest=canonical.digest_bytes(canonical.signing_bytes(document)),
    )


def admit(policy, request, revoked=None):
    """Evaluate a verified policy against one request (§25.8.3).

    ``revoked`` is a collection of grant ids the consumer has revoked. A
    matching rule whose deterministic id is in it is refused with
    ``grant_revoked``; the policy cannot resurrect it.

    ``allow`` is not an execution: use :func:`admitted_grant` to create the
    record and then proceed through §10.3.
    """
    if request.now > policy.expires_at:
        return AdmissionResult("deny", "policy_expired")
    if request.risk not in _ADMITTABLE_RISK:
        return AdmissionResult("deny", "risk_not_admittable")

    for rule in policy.rules:
        if request.now > rule.expires_at:
            continue
        if request.intent not in rule.intents:
            continue
        if rule.risk != request.risk:
            continue
        if rule.contacts is not None and request.contact_id not in rule.contacts:
            continue
        if (rule.requesters is not None
                and request.requester_key not in rule.requesters):
            continue
        if rule.risk == "disclose":
            if (request.destination is None or rule.destinations is None
                    or request.destination not in rule.destinations):
                continue
        if revoked is not None:
            if admitted_grant_id(policy, rule.id, request) in revoked:
                return AdmissionResult("deny", "grant_revoked", rule.id)
        return AdmissionResult("allow", "rule_matched", rule.id)

    if policy.default == "deny":
        return AdmissionResult("deny", "default_deny")
    return AdmissionResult("confirm", "default_confirm")


def admitted_grant(policy, request, result):
    """The grant record a match may create, or ``None`` if not admitted."""
    if result.decision != "allow" or result.rule_id is None:
        return None
    rule = next((entry for entry in policy.rules if entry.id == result.rule_id),
                None)
    if rule is None:
        return None
    expires_at = min(rule.expires_at, policy.expires_at)
    return AdmittedGrant(
        id=admitted_grant_id(policy, rule.id, request),
        intent=request.intent,
        limits=dict(rule.limits or {}),
        expires_at=expires_at,
    )
