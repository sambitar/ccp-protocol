#!/usr/bin/env python3
"""CCP v2 conformance-vector generator.

The v1 set (`../*.json`) is frozen. This generator adds the adversarial
cases that pin §25.1's canonical edges and §10.3's boundary/precedence
rules:

* canonical-json.json: NFC key collisions, unpaired surrogates, astral sort,
  top-level-only `signature`, prototype-shaped keys, `-0`.
* validation.json: equality at expiry and limit boundaries, plus check-order
  precedence.

The script is a self-checking reference: every vector is verified as it is
produced. It exits 0 only when all checks pass.

Pure standard library.

Run:  /usr/bin/python3 test-vectors/v2/generate.py
"""

import json
import os
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
CCP_VERSION = "0.4-draft"


class CanonicalError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


# ---------------------------------------------------------------------------
# Corrected canonical reference (§25.1)
# ---------------------------------------------------------------------------

_SHORT = {"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _require_well_formed(text):
    for char in text:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise CanonicalError("malformed")


def quote(text):
    _require_well_formed(text)
    text = unicodedata.normalize("NFC", text)
    out = ['"']
    for char in text:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char in _SHORT:
            out.append(_SHORT[char])
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def serialize(value, _top=True):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return quote(value)
    if isinstance(value, int):
        if value < 0:
            raise CanonicalError("negative")
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("float")
    if isinstance(value, list):
        return "[" + ",".join(serialize(item, _top=False) for item in value) + "]"
    if isinstance(value, dict):
        if _top and "signature" in value:
            regular = {k: v for k, v in value.items() if k != "signature"}
        else:
            regular = value
        folded = {}
        for key, item in regular.items():
            nfc = unicodedata.normalize("NFC", key)
            if nfc in folded:
                raise CanonicalError("duplicate")
            folded[nfc] = item
        parts = [quote(key) + ":" + serialize(folded[key], _top=False)
                 for key in sorted(folded)]
        if _top and "signature" in value:
            parts.append(quote("signature") + ":"
                         + serialize(value["signature"], _top=False))
        return "{" + ",".join(parts) + "}"
    raise TypeError("unsupported type %r" % (type(value),))


def _reject_dupes(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise CanonicalError("duplicate")
        seen[key] = value
    return seen


def _reject_constant(_name):
    raise CanonicalError("constant")


def _parse_int(text):
    if text.startswith("-"):
        raise CanonicalError("negative")
    return int(text)


def _parse_float(text):
    if text.startswith("-"):
        raise CanonicalError("negative")
    raise CanonicalError("float")


def _check(value):
    if isinstance(value, str):
        _require_well_formed(value)
    elif isinstance(value, list):
        for item in value:
            _check(item)
    elif isinstance(value, dict):
        seen = set()
        for key, item in value.items():
            _require_well_formed(key)
            folded = unicodedata.normalize("NFC", key)
            if folded in seen:
                raise CanonicalError("duplicate")
            seen.add(folded)
            _check(item)


def parse_strict(document):
    try:
        value = json.loads(
            document,
            object_pairs_hook=_reject_dupes,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise CanonicalError("malformed") from exc
    _check(value)
    return value


def canonicalize(document):
    return serialize(parse_strict(document))


# ---------------------------------------------------------------------------
# Canonical vectors
# ---------------------------------------------------------------------------

EMOJI = "\U0001f600"

CANONICAL_CASES = [
    ("cj2-001", "sort by code point across the astral plane",
     '{"\\ud83d\\ude00":1,"\\uffff":2,"a":3}',
     '{"a":3,"\uffff":2,"%s":1}' % EMOJI, None),
    ("cj2-002", "NFD key normalizes to NFC",
     '{"e\\u0301":1}', '{"\u00e9":1}', None),
    ("cj2-003", "NFD value normalizes to NFC",
     '{"a":"e\\u0301"}', '{"a":"\u00e9"}', None),
    ("cj2-004", "keys that collapse under NFC are duplicates",
     '{"e\\u0301":1,"\\u00e9":2}', None, "duplicate"),
    ("cj2-005", "escaped key duplicate",
     '{"a":1,"\\u0061":2}', None, "duplicate"),
    ("cj2-006", "negative zero is negative",
     '{"n":-0}', None, "negative"),
    ("cj2-007", "negative zero float is negative",
     '{"n":-0.0}', None, "negative"),
    ("cj2-008", "lone high surrogate",
     '{"a":"\\ud800"}', None, "malformed"),
    ("cj2-009", "lone low surrogate",
     '{"a":"\\udc00"}', None, "malformed"),
    ("cj2-010", "high surrogate followed by a non-low code",
     '{"a":"\\ud800\\u0041"}', None, "malformed"),
    ("cj2-011", "valid surrogate pair becomes one literal character",
     '{"a":"\\ud83d\\ude00"}', '{"a":"%s"}' % EMOJI, None),
    ("cj2-012", "nested signature is sorted normally",
     '{"outer":{"z":1,"signature":"x"}}',
     '{"outer":{"signature":"x","z":1}}', None),
    ("cj2-013", "top-level signature is last",
     '{"signature":"x","b":1,"a":2}',
     '{"a":2,"b":1,"signature":"x"}', None),
    ("cj2-014", "prototype-shaped key is ordinary data",
     '{"__proto__":{"x":1},"a":2}',
     '{"__proto__":{"x":1},"a":2}', None),
    ("cj2-015", "integer beyond 2^64 round-trips exactly",
     '{"n":18446744073709551616}',
     '{"n":18446744073709551616}', None),
    ("cj2-016", "exponent is a float",
     '{"n":1e3}', None, "float"),
    ("cj2-017", "control escapes use lowercase hex",
     '{"a":"\\u001F"}', '{"a":"\\u001f"}', None),
    ("cj2-018", "solidus is literal",
     '{"a":"\\"\\\\\\/"}', '{"a":"\\"\\\\/"}', None),
    ("cj2-019", "U+007F is literal",
     '{"a":"\\u007f"}', '{"a":"\u007f"}', None),
    ("cj2-020", "leading BOM is malformed",
     '\ufeff{"a":1}', None, "malformed"),
    ("cj2-021", "sort normalized keys by code point",
     '{"e\\u0301":1,"f":2}', '{"f":2,"\u00e9":1}', None),
]


def build_canonical_vectors():
    vectors = []
    for cid, name, document, expected, error in CANONICAL_CASES:
        try:
            got = canonicalize(document)
        except CanonicalError as exc:
            assert error == exc.code, (cid, exc.code, error)
        else:
            assert error is None, (cid, "expected error", error)
            assert got == expected, (cid, got, expected)
        vector = {"id": cid, "name": name, "document": document}
        if error is not None:
            vector["expect_error"] = error
        else:
            vector["expected_canonical"] = expected
        vectors.append(vector)
    return vectors


# ---------------------------------------------------------------------------
# Validation reference and vectors (§10.3, §26.1)
# ---------------------------------------------------------------------------

SCHEMAS = {
    "example.lookup": {
        "type": "object",
        "properties": {"item_id": {"type": "string"}},
        "required": ["item_id"],
        "additionalProperties": False,
    },
}
REQUIRED_CAPS = {"example.lookup": ["store.read"]}
SUPPORTED_PROTOCOL = "0.4"


def _schema_check(value, schema):
    kind = schema.get("type")
    if kind == "object":
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
    if kind == "array":
        if not isinstance(value, list):
            return False
        items = schema.get("items")
        return all(_schema_check(v, items) for v in value) if items else True
    if kind == "string":
        return isinstance(value, str)
    if kind == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "boolean":
        return isinstance(value, bool)
    if "enum" in schema:
        return value in schema["enum"]
    if "const" in schema:
        return value == schema["const"]
    return True


def validate(grant, signal, signer, now, seen, counters):
    if not signal.get("ccp", "").startswith(SUPPORTED_PROTOCOL + "-"):
        return "invalid_request"
    if grant is None:
        return "no_matching_grant"
    if signer != grant.get("requester_key"):
        return "unauthenticated"
    if signal.get("grant_digest") != grant.get("manifest_digest"):
        return "no_matching_grant"

    state = grant.get("state", "active")
    if state == "revoked":
        return "grant_revoked"
    if state == "paused":
        return "grant_paused"
    if state == "suspended":
        return "grant_suspended"
    if state == "expired" or now >= grant.get("expires_at", ""):
        return "grant_expired"

    intent = signal.get("intent")
    if intent not in grant.get("intents", []):
        return "intent_not_allowed"

    schema = SCHEMAS.get(intent)
    if schema is not None and not _schema_check(signal.get("params"), schema):
        return "invalid_request"

    if now >= signal.get("expires_at", ""):
        return "request_expired"
    if signal.get("request_id") in seen:
        return "replay_detected"

    for name, maximum in grant.get("limits", {}).items():
        if counters.get(name, 0) + 1 > maximum:
            return "limit_exceeded"

    required = REQUIRED_CAPS.get(intent, [])
    if not set(required).issubset(set(grant.get("capabilities", []))):
        return "capability_unavailable"

    policy = grant.get("confirmation", {}).get(intent, "per_action")
    if policy == "per_action":
        return "confirmation_required"
    return "authorized"


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
            "ccp": CCP_VERSION,
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


VALIDATION_CASES = [
    ("v2-001", "grant expires exactly now", "grant_expired",
     {"context": {"now": "2026-10-22T13:00:00Z"}}),
    ("v2-002", "signal expires exactly now", "request_expired",
     {"signal": {"expires_at": "2026-10-22T12:00:30Z"}}),
    ("v2-003", "one second before both expiries", "authorized",
     {"signal": {"expires_at": "2026-10-22T12:00:31Z"}}),
    ("v2-004", "counter one below the limit", "authorized",
     {"context": {"counters": {"calls_per_hour": 9}}}),
    ("v2-005", "counter equals the limit", "limit_exceeded",
     {"context": {"counters": {"calls_per_hour": 10}}}),
    ("v2-006", "counter above the limit", "limit_exceeded",
     {"context": {"counters": {"calls_per_hour": 11}}}),
    ("v2-007", "expired request beats replay", "request_expired",
     {"signal": {"expires_at": "2026-10-22T12:00:30Z"},
      "context": {"seen": ["req-0001"]}}),
    ("v2-008", "revoked beats expiry", "grant_revoked",
     {"grant": {"state": "revoked",
                "expires_at": "2026-10-22T11:00:00Z"}}),
    ("v2-009", "paused beats expiry", "grant_paused",
     {"grant": {"state": "paused",
                "expires_at": "2026-10-22T11:00:00Z"}}),
    ("v2-010", "suspended beats expiry", "grant_suspended",
     {"grant": {"state": "suspended",
                "expires_at": "2026-10-22T11:00:00Z"}}),
    ("v2-011", "explicit expired state with a future timestamp",
     "grant_expired",
     {"grant": {"state": "expired",
                "expires_at": "2026-10-22T23:00:00Z"}}),
    ("v2-012", "capability check precedes confirmation",
     "capability_unavailable",
     {"grant": {"capabilities": [],
                "confirmation": {"example.lookup": "per_action"}}}),
    ("v2-013", "grant state precedes intent check", "grant_revoked",
     {"grant": {"state": "revoked"},
      "signal": {"intent": "files.search"}}),
    ("v2-014", "params check precedes request expiry", "invalid_request",
     {"signal": {"params": {},
                 "expires_at": "2026-10-22T12:00:30Z"}}),
    ("v2-015", "two limits, one at the boundary", "limit_exceeded",
     {"grant": {"limits": {"calls_per_hour": 10, "bytes_per_day": 100}},
      "context": {"counters": {"calls_per_hour": 0,
                               "bytes_per_day": 100}}}),
    ("v2-016", "empty limits", "authorized",
     {"grant": {"limits": {}}, "context": {"counters": {}}}),
    ("v2-017", "now equals issued_at", "authorized",
     {"context": {"now": "2026-10-22T12:00:00Z"}}),
]


def build_validation_vectors():
    vectors = []
    for cid, name, expected, overrides in VALIDATION_CASES:
        case = _base()
        if "grant" in overrides:
            case["grant"] = dict(case["grant"], **overrides["grant"])
        if "signal" in overrides:
            case["signal"] = dict(case["signal"], **overrides["signal"])
        if "signer" in overrides:
            case["signer"] = overrides["signer"]
        if "context" in overrides:
            case["context"] = dict(case["context"], **overrides["context"])

        got = validate(case["grant"], case["signal"], case["signer"],
                       case["context"]["now"], set(case["context"]["seen"]),
                       case["context"]["counters"])
        assert got == expected, (cid, got, expected)
        vectors.append({
            "id": cid,
            "name": name,
            "grant": case["grant"],
            "signal": case["signal"],
            "signer": case["signer"],
            "context": case["context"],
            "expected": expected,
        })
    return vectors


def _write(name, data):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("wrote %s  (%d vectors)" % (name, len(data["vectors"])))


def main():
    canonical = {
        "ccp": CCP_VERSION,
        "rule": "strict canonical JSON, adversarial edges (§25.1)",
        "vectors": build_canonical_vectors(),
    }
    validation = {
        "ccp": CCP_VERSION,
        "rule": "validation boundaries and precedence (§10.3, §26.1)",
        "vectors": build_validation_vectors(),
    }
    _write("canonical-json.json", canonical)
    _write("validation.json", validation)
    print("self-check OK")


if __name__ == "__main__":
    main()
