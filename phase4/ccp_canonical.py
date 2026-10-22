"""Strict canonical JSON per CCP Working Draft v0.3 §25.1.

Implements, from prose alone:

* numbers: only non-negative integers; floats, exponents, negatives, NaN,
  and Infinity are rejected;
* strings: valid UTF-8, normalized to NFC;
* objects: keys other than ``signature`` sorted in ascending Unicode code
  point order; duplicate keys rejected; ``signature`` (if present) always
  emitted last, exempt from sort order;
* arrays: order preserved;
* whitespace: canonical output has no insignificant whitespace;
* escaping: minimal escape set (``"``, ``\\``, and U+0000..U+001F);
  non-ASCII emitted literally.

The error names mirror the vector file's ``expect_error`` vocabulary:
``float``, ``negative``, ``duplicate``, ``constant``.
"""

from __future__ import annotations

import json
import unicodedata


class CanonicalError(Exception):
    """Raised when a document violates strict canonical JSON rules."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def _reject_duplicates(pairs):
    """object_pairs_hook: reject duplicate object keys."""
    out = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError("duplicate")
        out[key] = value
    return out


def _reject_constant(name: str):
    """parse_constant hook: NaN / Infinity / -Infinity are forbidden."""
    raise CanonicalError("constant")


def _normalize(value):
    """Recursively NFC-normalize strings and enforce the number rules."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            norm_key = unicodedata.normalize("NFC", key)
            if norm_key in out:
                # Two distinct spellings that collide after NFC are also a
                # duplicate-key violation.
                raise CanonicalError("duplicate")
            out[norm_key] = _normalize(item)
        return out
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value < 0:
            raise CanonicalError("negative")
        return value
    if isinstance(value, float):
        # Includes 1.0, 1e3, and any other non-integral number.
        raise CanonicalError("float")
    if value is None:
        return value
    raise CanonicalError("float")


def parse_strict(text: str):
    """Parse *text* as strict canonical JSON, returning a normalized object.

    Raises :class:`CanonicalError` with the matching error kind on violation.
    """
    obj = json.loads(
        text,
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )
    return _normalize(obj)


def _escape(s: str) -> str:
    """Minimal JSON string escaping per §25.1."""
    parts = []
    for ch in s:
        if ch == '"':
            parts.append('\\"')
        elif ch == "\\":
            parts.append("\\\\")
        else:
            code = ord(ch)
            if code < 0x20:
                if ch == "\b":
                    parts.append("\\b")
                elif ch == "\t":
                    parts.append("\\t")
                elif ch == "\n":
                    parts.append("\\n")
                elif ch == "\f":
                    parts.append("\\f")
                elif ch == "\r":
                    parts.append("\\r")
                else:
                    parts.append("\\u%04x" % code)
            else:
                parts.append(ch)
    return "".join(parts)


def _serialize(obj) -> str:
    """Serialize an object to its strict canonical JSON form."""
    if isinstance(obj, bool):
        return "true" if obj else "false"
    if obj is None:
        return "null"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return '"' + _escape(obj) + '"'
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(item) for item in obj) + "]"
    if isinstance(obj, dict):
        keys = [k for k in obj if k != "signature"]
        keys.sort()  # Python str ordering is by Unicode code point
        parts = [_serialize(k) + ":" + _serialize(obj[k]) for k in keys]
        if "signature" in obj:
            parts.append('"signature":' + _serialize(obj["signature"]))
        return "{" + ",".join(parts) + "}"
    raise TypeError("unserializable value: %r" % (obj,))


def canonicalize(obj) -> str:
    """Return the canonical JSON byte string for *obj* (already parsed)."""
    return _serialize(obj)


def canonicalize_text(text: str) -> str:
    """Parse *text* strictly and return its canonical JSON form."""
    return _serialize(parse_strict(text))
