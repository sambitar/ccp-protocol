"""
Independent re-implementation of the CCP initial interoperable profile,
derived strictly from the prose of CCP_Working_Draft_v0.3.md.

Covers:
  - §25.1  strict canonical JSON
  - §25.2  Ed25519 + key/signature encoding
  - §26.3  side-effect state machine
  - §10.3 + §26.1 + §10.4  signal-validation decision

No vector data is embedded here; this module is pure rules. The runner
(verify.py) feeds the frozen vectors in.
"""

from __future__ import annotations

import base64
import hashlib
import unicodedata

# ---------------------------------------------------------------------------
# §25.1 — strict canonical JSON
# ---------------------------------------------------------------------------

class CanonicalError(Exception):
    """Raised when a document cannot be canonicalized.

    `kind` is one of: float, negative, duplicate, constant, syntax.
    """

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


_WHITESPACE = " \t\n\r"


def parse_document(text: str):
    """Parse a JSON document, enforcing §25.1 parse-time rules.

    Returns a Python value (dict/list/str/int/bool/None).  Raises
    CanonicalError for floats, negative numbers, duplicate keys, and the
    NaN/Infinity constants.  All strings (keys and values) are NFC
    normalized as they are read.
    """
    n = len(text)
    i = 0

    def error(kind):
        raise CanonicalError(kind)

    def ws():
        nonlocal i
        while i < n and text[i] in _WHITESPACE:
            i += 1

    def parse_string():
        nonlocal i
        # text[i] == '"'
        i += 1
        chars = []
        while i < n:
            c = text[i]
            if c == '"':
                i += 1
                return unicodedata.normalize("NFC", "".join(chars))
            if c == "\\":
                i += 1
                if i >= n:
                    error("syntax")
                e = text[i]
                i += 1
                if e == '"':
                    chars.append('"')
                elif e == "\\":
                    chars.append("\\")
                elif e == "/":
                    chars.append("/")
                elif e == "b":
                    chars.append("\b")
                elif e == "f":
                    chars.append("\f")
                elif e == "n":
                    chars.append("\n")
                elif e == "r":
                    chars.append("\r")
                elif e == "t":
                    chars.append("\t")
                elif e == "u":
                    if i + 4 > n:
                        error("syntax")
                    hexpart = text[i:i + 4]
                    try:
                        cp = int(hexpart, 16)
                    except ValueError:
                        error("syntax")
                    i += 4
                    if 0xD800 <= cp <= 0xDBFF:
                        if i + 6 <= n and text[i] == "\\" and text[i + 1] == "u":
                            try:
                                lo = int(text[i + 2:i + 6], 16)
                            except ValueError:
                                error("syntax")
                            if 0xDC00 <= lo <= 0xDFFF:
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
                                i += 6
                                chars.append(chr(cp))
                            else:
                                error("syntax")
                        else:
                            error("syntax")
                    elif 0xDC00 <= cp <= 0xDFFF:
                        error("syntax")
                    else:
                        chars.append(chr(cp))
                else:
                    error("syntax")
            else:
                if ord(c) < 0x20:
                    # Unescaped control character.
                    error("syntax")
                chars.append(c)
                i += 1
        error("syntax")

    def parse_number():
        nonlocal i
        start = i
        if text[i] == "-":
            # A leading minus sign MUST NOT appear (§25.1).
            if text.startswith("-Infinity", i):
                error("constant")
            # consume the rest of the number so error reporting is stable,
            # but the classification is negative.
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] in ".eE+-"):
                j += 1
            i = j
            error("negative")
        j = i
        while j < n and (text[j].isdigit() or text[j] in ".eE+-"):
            j += 1
        token = text[i:j]
        if any(ch in token for ch in ".eE"):
            error("float")
        i = j
        return int(token)

    def parse_object():
        nonlocal i
        # text[i] == '{'
        i += 1
        result = {}
        ws()
        if i < n and text[i] == "}":
            i += 1
            return result
        while True:
            ws()
            if i >= n or text[i] != '"':
                error("syntax")
            key = parse_string()
            ws()
            if i >= n or text[i] != ":":
                error("syntax")
            i += 1
            value = parse_value()
            if key in result:
                error("duplicate")
            result[key] = value
            ws()
            if i < n and text[i] == ",":
                i += 1
                continue
            if i < n and text[i] == "}":
                i += 1
                return result
            error("syntax")

    def parse_array():
        nonlocal i
        # text[i] == '['
        i += 1
        result = []
        ws()
        if i < n and text[i] == "]":
            i += 1
            return result
        while True:
            result.append(parse_value())
            ws()
            if i < n and text[i] == ",":
                i += 1
                continue
            if i < n and text[i] == "]":
                i += 1
                return result
            error("syntax")

    def parse_value():
        nonlocal i
        ws()
        if i >= n:
            error("syntax")
        c = text[i]
        if c == "{":
            return parse_object()
        if c == "[":
            return parse_array()
        if c == '"':
            return parse_string()
        if text.startswith("true", i):
            i += 4
            return True
        if text.startswith("false", i):
            i += 5
            return False
        if text.startswith("null", i):
            i += 4
            return None
        if text.startswith("NaN", i) or text.startswith("Infinity", i):
            error("constant")
        if c == "-" or c.isdigit():
            return parse_number()
        error("syntax")

    value = parse_value()
    ws()
    if i != n:
        error("syntax")
    return value


def _escape_string(s: str) -> str:
    """Emit a string using the §25.1 minimal escape set."""
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif c == "\b":
            out.append("\\b")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\f":
            out.append("\\f")
        elif c == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def _serialize(value, top_level: bool) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(x, False) for x in value) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        keys.sort()  # ascending Unicode code point
        if top_level and "signature" in keys:
            # signature MUST be the final field, after the sorted fields.
            keys = [k for k in keys if k != "signature"] + ["signature"]
        return "{" + ",".join(
            _escape_string(k) + ":" + _serialize(value[k], False) for k in keys
        ) + "}"
    raise CanonicalError("syntax")


def canonicalize(value) -> str:
    """Canonical byte string of a JSON value (§25.1).

    For a top-level object containing `signature`, the signature field is
    placed last per §25.1.  Nested objects are sorted normally.
    """
    return _serialize(value, True)


def signing_bytes(obj: dict) -> str:
    """Canonical bytes of the signed object with `signature` removed."""
    obj = {k: v for k, v in obj.items() if k != "signature"}
    return canonicalize(obj)


def wire_form(obj: dict) -> str:
    """Wire form: canonical, with `signature` forced to final position."""
    return canonicalize(obj)


# ---------------------------------------------------------------------------
# §25.2 — Ed25519 + base64url + key/signature encoding
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def b64url(raw: bytes) -> str:
    """RFC 4648 §5 base64url, padding omitted."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def derive_public_key(seed: bytes) -> bytes:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    return sk.sign(message)


def key_id(public_key: bytes) -> str:
    return "key:ed25519:" + b64url(public_key)


def signature_field(signature: bytes) -> str:
    return "ed25519:" + b64url(signature)


# ---------------------------------------------------------------------------
# §26.3 — side-effect state machine
# ---------------------------------------------------------------------------

TRANSITIONS = {
    ("start", "arrive"): "received",
    ("received", "validate_ok"): "authorized",
    ("authorized", "confirmation_required"): "awaiting_confirmation",
    ("authorized", "no_confirmation"): "executing",
    ("awaiting_confirmation", "approved"): "executing",
    ("awaiting_confirmation", "denied"): "cancelled",
    ("executing", "succeeded"): "completed",
    ("executing", "failed"): "failed",
    ("executing", "cancelled"): "cancelled",
    ("executing", "outcome_lost"): "outcome_unknown",
}


def transition(from_state: str, event: str) -> str:
    return TRANSITIONS[(from_state, event)]


# ---------------------------------------------------------------------------
# §10.3 + §26.1 + §10.4 — signal validation decision
# ---------------------------------------------------------------------------

# Required host capabilities for the single core intent in the initial
# profile, taken from the illustrative manifest in §8.2 (and echoed by the
# host capability catalogue in §26.4).
_REQUIRED_CAPABILITIES = {
    "example.lookup": ["store.read"],
}

# params schema for `example.lookup`, pinned by §25.3: an object with one
# required string property `item_id`, additionalProperties false.
def _params_valid(intent: str, params) -> bool:
    if intent == "example.lookup":
        if not isinstance(params, dict):
            return False
        if set(params.keys()) != {"item_id"}:
            return False
        if not isinstance(params.get("item_id"), str):
            return False
        return True
    # Unknown intents are rejected earlier by the intent-enabled check.
    return True


def validate_signal(grant, signal, signer, context) -> str:
    """Return one of the §10.4 decision codes.

    `grant` may be None (no matching grant record exists). `signal` is a
    parsed dict. `signer` is the authenticated requester key identifier.
    `context` carries `now`, `seen` (list of request_ids), and `counters`
    (cumulative limit counters).
    """
    now = context["now"]
    seen = set(context.get("seen", []))
    counters = context.get("counters", {})

    # §10.3 step 3 — protocol compatibility.
    if signal.get("ccp") != "0.3-draft":
        return "invalid_request"

    # §10.3 step 4 — find the active grant.  No grant at all -> no match.
    if grant is None:
        return "no_matching_grant"

    # §10.3 step 2 — the authenticated sender must be the grant's requester.
    if signer != grant.get("requester_key"):
        return "unauthenticated"

    # §10.3 step 4 (continued) — the grant digest must match.
    if signal.get("grant_digest") != grant.get("manifest_digest"):
        return "no_matching_grant"

    # §10.3 step 5 + §26.1 — expiry (derived, regardless of stored state),
    # then the explicit lifecycle states.
    if now >= grant.get("expires_at"):
        return "grant_expired"
    state = grant.get("state")
    if state == "revoked":
        return "grant_revoked"
    if state == "paused":
        return "grant_paused"
    if state == "suspended":
        return "grant_suspended"

    # §10.3 step 6 — intent enabled.
    intent = signal.get("intent")
    if intent not in grant.get("intents", []):
        return "intent_not_allowed"

    # §10.3 step 7 — params validated against the approved schema.
    if not _params_valid(intent, signal.get("params")):
        return "invalid_request"

    # §10.3 step 8 — request expiry, then replay.
    if signal.get("expires_at") <= now:
        return "request_expired"
    if signal.get("request_id") in seen:
        return "replay_detected"

    # §10.3 step 9 + §9.2 — cumulative limits (counter >= limit).
    for name, limit in grant.get("limits", {}).items():
        if counters.get(name, 0) >= limit:
            return "limit_exceeded"

    # §10.3 step 10 + §26.1 — required capabilities present in the grant.
    grant_caps = set(grant.get("capabilities", []))
    for cap in _REQUIRED_CAPABILITIES.get(intent, []):
        if cap not in grant_caps:
            return "capability_unavailable"

    # §10.3 step 11 + §26.1/§26.2 — confirmation policy.
    confirmation = grant.get("confirmation", {}).get(intent, "none")
    if confirmation == "per_action":
        return "confirmation_required"
    return "authorized"
