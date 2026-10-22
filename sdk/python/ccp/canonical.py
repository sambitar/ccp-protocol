"""Strict canonical JSON per CCP §25.1.

The canonical form is deterministic and byte-exact:

* numbers: only non-negative integers; floats, exponents, negatives, NaN,
  Infinity and -Infinity are rejected;
* strings: UTF-8, NFC-normalized (keys and values), minimal escaping;
* objects: keys other than ``signature`` sorted by Unicode code point;
  duplicate keys rejected; ``signature`` always emitted last;
* arrays: order preserved; no insignificant whitespace;
* any JSON value is supported, including top-level scalars.
"""

import hashlib
import json
import unicodedata


class CanonicalError(ValueError):
    """Raised when a value cannot be represented in canonical form."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


_SHORT_ESCAPES = {
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _require_well_formed(text):
    """Reject strings containing unpaired surrogates (§25.1 UTF-8)."""
    for char in text:
        if 0xD800 <= ord(char) <= 0xDFFF:
            raise CanonicalError("malformed")


def quote(s):
    """Encode one string using the minimal escape set."""
    _require_well_formed(s)
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def serialize(value, _top=True):
    """Serialize a parsed JSON value in canonical form."""
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
        return "[" + ",".join(serialize(v, _top=False) for v in value) + "]"
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
        parts = [quote(k) + ":" + serialize(folded[k], _top=False)
                 for k in sorted(folded)]
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
    """Validate decoded strings and NFC key uniqueness."""
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
    """Parse a JSON document with duplicate-key and NaN/Infinity rejection."""
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
    """Canonicalize a JSON document string."""
    return serialize(parse_strict(document))


def signing_bytes(document):
    """Canonical bytes signed for a document; ``signature`` excluded."""
    obj = parse_strict(document)
    obj.pop("signature", None)
    return serialize(obj).encode("utf-8")


def signing_bytes_of(value):
    """Canonical bytes signed for an already-parsed value."""
    obj = dict(value)
    obj.pop("signature", None)
    return serialize(obj).encode("utf-8")


def signed_wire(document, signature_b64url):
    """Wire form: canonical document with ``signature`` appended last."""
    obj = parse_strict(document)
    obj["signature"] = "ed25519:" + signature_b64url
    return serialize(obj)


def digest_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(document):
    """`sha256:<hex>` over the canonical signing bytes of a document."""
    return digest_bytes(signing_bytes(document))
