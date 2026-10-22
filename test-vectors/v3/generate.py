#!/usr/bin/env python3
"""Generate and self-check the v3 conformance vectors.

v3 pins the 0.5 revision's dual-label compatibility: `0.5-draft` is the
current label and `0.4-draft` remains accepted. Canonicalization is
version-independent; the validation cases exercise the accepted set.

Usage: /usr/bin/python3 test-vectors/v3/generate.py
"""

import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
V2 = os.path.join(os.path.dirname(HERE), "v2", "generate.py")

spec = importlib.util.spec_from_file_location("ccp_v2_for_v3", V2)
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)

CCP_VERSION = "0.5-draft"
SUPPORTED = ("0.5-draft", "0.4-draft")
v2.CCP_VERSION = CCP_VERSION


CANONICAL_CASES = [
    ("cj3-001", "key sort (flat)",
     '{"b":1,"a":2}', {"expected_canonical": '{"a":2,"b":1}'}),
    ("cj3-002", "reject duplicate",
     '{"a":1,"a":2}', {"expect_error": "duplicate"}),
    ("cj3-003", "reject float",
     '{"a":1.5}', {"expect_error": "float"}),
]


def build_canonical_vectors():
    vectors = []
    for cid, name, document, expected in CANONICAL_CASES:
        if "expect_error" in expected:
            try:
                v2.canonicalize(document)
            except v2.CanonicalError as exc:
                assert exc.code == expected["expect_error"], (cid, exc.code)
            else:
                raise AssertionError((cid, "expected an error"))
        else:
            assert (v2.canonicalize(document)
                    == expected["expected_canonical"]), cid
        vectors.append({
            "id": cid,
            "name": name,
            "document": document,
            **expected,
        })
    return vectors


VALIDATION_CASES = [
    ("v3-001", "current 0.5-draft is accepted", "authorized", {}),
    ("v3-002", "legacy 0.4-draft is accepted", "authorized",
     {"signal": {"ccp": "0.4-draft"}}),
    ("v3-003", "unknown label is rejected", "invalid_request",
     {"signal": {"ccp": "0.6-draft"}}),
    ("v3-004", "replay under 0.5-draft", "replay_detected",
     {"context": {"seen": ["req-0001"]}}),
    ("v3-005", "expired grant under 0.5-draft", "grant_expired",
     {"context": {"now": "2026-10-22T13:00:00Z"}}),
]


def _validate(case):
    label = case["signal"]["ccp"]
    if label not in SUPPORTED:
        return "invalid_request"
    # The v2 reference checks a protocol prefix; point it at this label.
    original = v2.SUPPORTED_PROTOCOL
    v2.SUPPORTED_PROTOCOL = label.split("-")[0]
    try:
        return v2.validate(
            case["grant"], case["signal"], case["signer"],
            case["context"]["now"], set(case["context"]["seen"]),
            case["context"]["counters"],
        )
    finally:
        v2.SUPPORTED_PROTOCOL = original


def build_validation_vectors():
    vectors = []
    for cid, name, expected, overrides in VALIDATION_CASES:
        case = v2._base()
        if "signal" in overrides:
            case["signal"] = dict(case["signal"], **overrides["signal"])
        if "context" in overrides:
            case["context"] = dict(case["context"], **overrides["context"])
        got = _validate(case)
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
        "rule": "0.5 revision: canonical JSON stays version-independent (§25.1)",
        "vectors": build_canonical_vectors(),
    }
    validation = {
        "ccp": CCP_VERSION,
        "rule": "0.5 revision: dual-label compatibility and 0.5 decisions "
                "(§19.1, §10.3)",
        "vectors": build_validation_vectors(),
    }
    _write("canonical-json.json", canonical)
    _write("validation.json", validation)
    print("self-check OK")


if __name__ == "__main__":
    main()
