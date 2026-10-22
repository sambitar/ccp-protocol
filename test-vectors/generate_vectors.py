#!/usr/bin/env python3
"""
CCP reference canonicalizer + conformance test-vector generator.

Implements, as executable rules, the parts of the initial interoperable
profile that must be byte-exact:

  * strict canonical JSON (CCP_Working_Draft_v0.5.md §25.1)
  * Ed25519 key and signature encoding (RFC 8032 + §25.2)
  * the side-effecting state machine (§26.3, encoded as a transition table)

Writes three machine-readable vector files next to this script:

  canonical-json.json, ed25519.json, state-machine.json

The script is self-checking: every vector is verified as it is produced,
and the RFC 8032 Ed25519 known-answer tests are validated against the
`cryptography` library. It exits 0 on success and non-zero on any failure.

Requirements: Python 3.8+, `cryptography`.
"""

import base64
import hashlib
import json
import os
import unicodedata

from cryptography.exceptions import InvalidSignature  # noqa: F401
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

CCP_VERSION = "0.4-draft"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Strict canonical JSON (§25.1)
# ---------------------------------------------------------------------------

def quote(s):
    """Encode one string using the minimal escape set, NFC-normalized."""
    s = unicodedata.normalize("NFC", s)
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\b':
            out.append('\\b')
        elif ch == '\f':
            out.append('\\f')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)  # literal, including non-ASCII (UTF-8)
    out.append('"')
    return ''.join(out)


def serialize(value):
    """Canonicalize a parsed JSON value.

    Keys other than `signature` are sorted ascending by Unicode code point;
    `signature`, when present, is always the final field.
    """
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, str):
        return quote(value)
    if isinstance(value, int):
        if value < 0:
            raise ValueError('negative')
        return str(value)
    if isinstance(value, float):
        raise ValueError('float')
    if isinstance(value, list):
        return '[' + ','.join(serialize(v) for v in value) + ']'
    if isinstance(value, dict):
        regular = {k: v for k, v in value.items() if k != 'signature'}
        parts = [quote(k) + ':' + serialize(regular[k])
                 for k in sorted(regular.keys())]
        if 'signature' in value:
            parts.append(quote('signature') + ':' + serialize(value['signature']))
        return '{' + ','.join(parts) + '}'
    raise TypeError('unsupported type %r' % type(value))


def _reject_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError('duplicate')
        d[k] = v
    return d


def _reject_constant(c):
    raise ValueError('constant')


def parse_strict(document):
    return json.loads(document, object_pairs_hook=_reject_dupes,
                      parse_constant=_reject_constant)


def canonicalize(document):
    """Canonicalize a JSON document string."""
    return serialize(parse_strict(document))


def signing_bytes(document):
    """Canonical bytes that are signed; `signature` is excluded."""
    obj = parse_strict(document)
    obj.pop('signature', None)
    return serialize(obj).encode('utf-8')


def signed_wire(document, signature_b64url):
    """Wire form: canonical object with `signature` appended last."""
    obj = parse_strict(document)
    obj['signature'] = 'ed25519:' + signature_b64url
    return serialize(obj)


# ---------------------------------------------------------------------------
# Ed25519 helpers (§25.2)
# ---------------------------------------------------------------------------

def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def public_key_hex(sk):
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ).hex()


def key_id_from_hex(pk_hex):
    return 'key:ed25519:' + b64url(bytes.fromhex(pk_hex))


# ---------------------------------------------------------------------------
# Canonical-JSON vectors  (id, name, document, expected_canonical, expect_error)
# ---------------------------------------------------------------------------

CANONICAL_CASES = [
    ("cj-001", "key sort (flat)",
     '{"b":1,"a":2}', '{"a":2,"b":1}', None),
    ("cj-002", "key sort (nested)",
     '{"z":{"m":1,"a":2},"a":[3,2,1]}', '{"a":[3,2,1],"z":{"a":2,"m":1}}', None),
    ("cj-003", "whitespace removed",
     ' { "a" : 1 } ', '{"a":1}', None),
    ("cj-004", "non-ASCII literal",
     '{"a":"é"}', '{"a":"é"}', None),
    ("cj-005", "NFC precomposed",
     '{"a":"\\u00e9"}', '{"a":"é"}', None),
    ("cj-006", "NFC combining",
     '{"a":"e\\u0301"}', '{"a":"é"}', None),
    ("cj-007", "control char minimal escape",
     '{"a":"line\\u000abreak"}', '{"a":"line\\nbreak"}', None),
    ("cj-008", "quote and backslash",
     '{"a":"x\\"y\\\\z"}', '{"a":"x\\"y\\\\z"}', None),
    ("cj-009", "integer preserved",
     '{"amount":1000}', '{"amount":1000}', None),
    ("cj-010", "decimal string preserved",
     '{"amount":"1.00"}', '{"amount":"1.00"}', None),
    ("cj-011", "empty object", '{}', '{}', None),
    ("cj-012", "empty array", '[]', '[]', None),
    ("cj-013", "bool and null",
     '{"a":true,"b":false,"c":null}', '{"a":true,"b":false,"c":null}', None),
    ("cj-014", "reject float", '{"a":1.0}', None, 'float'),
    ("cj-015", "reject exponent", '{"a":1e3}', None, 'float'),
    ("cj-016", "reject negative", '{"a":-1}', None, 'negative'),
    ("cj-017", "reject duplicate key", '{"a":1,"a":2}', None, 'duplicate'),
    ("cj-018", "reject NaN", '{"a":NaN}', None, 'constant'),
]


def build_canonical_vectors():
    vectors = []
    for cid, name, doc, expected, err in CANONICAL_CASES:
        if err is not None:
            try:
                canonicalize(doc)
            except ValueError as e:
                assert str(e) == err, (cid, str(e), err)
            else:
                raise AssertionError('%s: expected error %s' % (cid, err))
            vectors.append({"id": cid, "name": name, "document": doc,
                            "expect_error": err})
        else:
            got = canonicalize(doc)
            assert got == expected, (cid, got, expected)
            vectors.append({"id": cid, "name": name, "document": doc,
                            "expected_canonical": got})
    return vectors


# ---------------------------------------------------------------------------
# Ed25519 vectors
# ---------------------------------------------------------------------------

RFC8032_KATS = [
    {
        "id": "ed-kat-001",
        "name": "RFC 8032 §7.1 TEST 1 (empty message)",
        "secret_key_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public_key_hex": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message_hex": "",
        "signature_hex": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "id": "ed-kat-002",
        "name": "RFC 8032 §7.1 TEST 2 (one byte)",
        "secret_key_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public_key_hex": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message_hex": "72",
        "signature_hex": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "id": "ed-kat-003",
        "name": "RFC 8032 §7.1 TEST 3 (2 bytes)",
        "secret_key_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public_key_hex": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message_hex": "af82",
        "signature_hex": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]

# Deterministic seed (0x00..0x1f) so the protocol-level vectors reproduce.
DEMO_SEED = bytes(range(32))

SIGNAL_DOC = (
    '{"ccp":"0.4-draft",'
    '"request_id":"req-00000001",'
    '"grant_digest":"sha256:' + ("0" * 64) + '",'
    '"intent":"example.lookup",'
    '"params":{"item_id":"item-123"},'
    '"issued_at":"2026-10-22T12:00:00Z",'
    '"expires_at":"2026-10-22T12:01:00Z"}'
)


def _manifest_doc(pk_hex):
    return (
        '{"ccp":"0.4-draft",'
        '"provider":{"id":"key:ed25519:' + b64url(bytes.fromhex(pk_hex)) + '","name":"Example Service"},'
        '"version":1,'
        '"intents":{"example.lookup":{'
        '"description":"Look up one item requested by the consumer",'
        '"params_schema":"schema:example.lookup.params.v1",'
        '"result_schema":"schema:example.lookup.result.v1",'
        '"required_capabilities":["store.read"],'
        '"placement":"local",'
        '"data_egress":{"network":false,"fields":[]},'
        '"suggested_limits":{"calls_per_hour":10,"max_input_bytes":4096},'
        '"confirmation":"grant-policy"}}}'
    )


def build_ed25519_vectors():
    kats = []
    for k in RFC8032_KATS:
        sk = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(k["secret_key_hex"]))
        pk_hex = public_key_hex(sk)
        assert pk_hex == k["public_key_hex"], (k["id"], pk_hex)
        msg = bytes.fromhex(k["message_hex"])
        sig = sk.sign(msg)
        assert sig.hex() == k["signature_hex"], (k["id"], sig.hex())
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(pk_hex)).verify(sig, msg)
        kats.append({
            "id": k["id"], "name": k["name"],
            "secret_key_hex": k["secret_key_hex"],
            "public_key_hex": pk_hex,
            "key_id": key_id_from_hex(pk_hex),
            "message_hex": k["message_hex"],
            "signature_hex": sig.hex(),
            "signature_field": "ed25519:" + b64url(sig),
        })

    signing = []
    sk = Ed25519PrivateKey.from_private_bytes(DEMO_SEED)
    pk_hex = public_key_hex(sk)
    pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex))
    for sid, name, doc in [
        ("ed-sig-001", "sign a signal", SIGNAL_DOC),
        ("ed-sig-002", "sign a manifest", _manifest_doc(pk_hex)),
    ]:
        inp = signing_bytes(doc)
        sig = sk.sign(inp)
        pk.verify(sig, inp)
        sig_b64 = b64url(sig)
        signing.append({
            "id": sid, "name": name,
            "seed_hex": DEMO_SEED.hex(),
            "public_key_hex": pk_hex,
            "key_id": key_id_from_hex(pk_hex),
            "document": doc,
            "signing_input": inp.decode('utf-8'),
            "signing_input_sha256": hashlib.sha256(inp).hexdigest(),
            "signature_hex": sig.hex(),
            "signature_field": "ed25519:" + sig_b64,
            "wire": signed_wire(doc, sig_b64),
        })

    return {"kat_vectors": kats, "signing_vectors": signing}


# ---------------------------------------------------------------------------
# State-machine vectors (§26.3)
# ---------------------------------------------------------------------------

STATE_MACHINE = [
    ("sm-001", "start", "arrive", "received"),
    ("sm-002", "received", "validate_ok", "authorized"),
    ("sm-003", "authorized", "confirmation_required", "awaiting_confirmation"),
    ("sm-004", "authorized", "no_confirmation", "executing"),
    ("sm-005", "awaiting_confirmation", "approved", "executing"),
    ("sm-006", "awaiting_confirmation", "denied", "cancelled"),
    ("sm-007", "executing", "succeeded", "completed"),
    ("sm-008", "executing", "failed", "failed"),
    ("sm-009", "executing", "cancelled", "cancelled"),
    ("sm-010", "executing", "outcome_lost", "outcome_unknown"),
]


def build_state_machine_vectors():
    return [{"id": i, "from": f, "event": e, "to": t}
            for (i, f, e, t) in STATE_MACHINE]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    canonical = {"ccp": CCP_VERSION,
                 "rule": "strict canonical JSON (§25.1)",
                 "vectors": build_canonical_vectors()}
    ed = {"ccp": CCP_VERSION,
          "rule": "Ed25519 (RFC 8032) + CCP key/signature encoding (§25.2)"}
    ed.update(build_ed25519_vectors())
    sm = {"ccp": CCP_VERSION,
          "rule": "side-effect state machine (§26.3)",
          "vectors": build_state_machine_vectors()}

    files = {
        "canonical-json.json": canonical,
        "ed25519.json": ed,
        "state-machine.json": sm,
    }
    for name, data in files.items():
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")

    print("wrote canonical-json.json  (%d vectors)"
          % len(canonical["vectors"]))
    print("wrote ed25519.json        (%d kat, %d signing)"
          % (len(ed["kat_vectors"]), len(ed["signing_vectors"])))
    print("wrote state-machine.json  (%d vectors)" % len(sm["vectors"]))
    print("self-check OK")


if __name__ == "__main__":
    main()
