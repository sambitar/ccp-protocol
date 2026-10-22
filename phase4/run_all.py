"""Run all four CCP conformance vector sets against this implementation.

Reads the frozen vectors from ../test-vectors/ and reports matched/total for
each set, plus every mismatch. It deliberately does NOT read the reference
implementations (generate_vectors.py, validation.py).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ccp_canonical import CanonicalError, canonicalize, parse_strict
from ccp_ed25519 import derive_public_key, key_id, sign, signature_field
from ccp_state_machine import transition
from ccp_validation import decide

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS = os.path.join(HERE, "..", "test-vectors")


def load(name: str):
    with open(os.path.join(VECTORS, name), encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# canonical-json.json
# --------------------------------------------------------------------------- #
def check_canonical() -> tuple[int, int, list[str]]:
    data = load("canonical-json.json")
    total = matched = 0
    problems = []
    for v in data["vectors"]:
        total += 1
        doc = v["document"]
        if "expect_error" in v:
            try:
                parse_strict(doc)
                got = "NO_ERROR"
            except CanonicalError as exc:
                got = exc.kind
            exp = v["expect_error"]
            ok = got == exp
            if not ok:
                problems.append(f"{v['id']}: expected error {exp!r}, got {got!r}")
        else:
            try:
                got = canonicalize(parse_strict(doc))
            except CanonicalError as exc:
                got = f"<CanonicalError {exc.kind}>"
            ok = got == v["expected_canonical"]
            if not ok:
                problems.append(
                    f"{v['id']}: expected {v['expected_canonical']!r}, got {got!r}"
                )
        matched += ok
    return matched, total, problems


# --------------------------------------------------------------------------- #
# ed25519.json
# --------------------------------------------------------------------------- #
def check_ed25519() -> tuple[int, int, int, int, list[str]]:
    data = load("ed25519.json")
    problems = []

    kat_total = kat_matched = 0
    for v in data["kat_vectors"]:
        kat_total += 1
        ok = True
        pub = derive_public_key(v["secret_key_hex"])
        if pub.hex() != v["public_key_hex"]:
            problems.append(f"{v['id']}: public_key {pub.hex()} != {v['public_key_hex']}")
            ok = False
        if key_id(pub) != v["key_id"]:
            problems.append(f"{v['id']}: key_id {key_id(pub)} != {v['key_id']}")
            ok = False
        sig = sign(v["secret_key_hex"], bytes.fromhex(v["message_hex"]))
        if sig.hex() != v["signature_hex"]:
            problems.append(f"{v['id']}: signature {sig.hex()} != {v['signature_hex']}")
            ok = False
        if signature_field(sig) != v["signature_field"]:
            problems.append(
                f"{v['id']}: signature_field {signature_field(sig)} != {v['signature_field']}"
            )
            ok = False
        kat_matched += ok

    sig_total = sig_matched = 0
    for v in data["signing_vectors"]:
        sig_total += 1
        ok = True
        signing_input = canonicalize(parse_strict(v["document"]))
        if signing_input != v["signing_input"]:
            problems.append(f"{v['id']}: signing_input mismatch\n  got {signing_input}\n  exp {v['signing_input']}")
            ok = False
        sha = hashlib.sha256(signing_input.encode("utf-8")).hexdigest()
        if sha != v["signing_input_sha256"]:
            problems.append(f"{v['id']}: signing_input_sha256 {sha} != {v['signing_input_sha256']}")
            ok = False
        sig = sign(v["seed_hex"], signing_input.encode("utf-8"))
        if sig.hex() != v["signature_hex"]:
            problems.append(f"{v['id']}: signature {sig.hex()} != {v['signature_hex']}")
            ok = False
        sfield = signature_field(sig)
        if sfield != v["signature_field"]:
            problems.append(f"{v['id']}: signature_field {sfield} != {v['signature_field']}")
            ok = False
        # Wire form: canonical fields, then signature last.
        obj = parse_strict(v["document"])
        obj["signature"] = sfield
        wire = canonicalize(obj)
        if wire != v["wire"]:
            problems.append(f"{v['id']}: wire mismatch\n  got {wire}\n  exp {v['wire']}")
            ok = False
        sig_matched += ok

    return kat_matched, kat_total, sig_matched, sig_total, problems


# --------------------------------------------------------------------------- #
# state-machine.json
# --------------------------------------------------------------------------- #
def check_state_machine() -> tuple[int, int, list[str]]:
    data = load("state-machine.json")
    total = matched = 0
    problems = []
    for v in data["vectors"]:
        total += 1
        got = transition(v["from"], v["event"])
        ok = got == v["to"]
        if not ok:
            problems.append(
                f"{v['id']}: ({v['from']}, {v['event']}) -> {got!r}, expected {v['to']!r}"
            )
        matched += ok
    return matched, total, problems


# --------------------------------------------------------------------------- #
# validation.json
# --------------------------------------------------------------------------- #
def check_validation() -> tuple[int, int, list[str]]:
    data = load("validation.json")
    total = matched = 0
    problems = []
    for v in data["vectors"]:
        total += 1
        got = decide(v["grant"], v["signal"], v["signer"], v["context"])
        ok = got == v["expected"]
        if not ok:
            problems.append(f"{v['id']}: expected {v['expected']!r}, got {got!r}")
        matched += ok
    return matched, total, problems


def main() -> int:
    print("== CCP Phase 4 independent-implementation check ==\n")

    cm, ct, cp = check_canonical()
    print(f"canonical-json: {cm}/{ct}")

    km, kt, sm, st, ep = check_ed25519()
    print(f"ed25519: {km}/{kt} kat + {sm}/{st} signing")

    mm, mt, mp = check_state_machine()
    print(f"state-machine: {mm}/{mt}")

    vm, vt, vp = check_validation()
    print(f"validation: {vm}/{vt}")

    all_problems = cp + ep + mp + vp
    if all_problems:
        print("\nMismatches / discrepancies:")
        for p in all_problems:
            print("  - " + p)
    else:
        print("\nAll vectors matched.")

    return 0 if not all_problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
