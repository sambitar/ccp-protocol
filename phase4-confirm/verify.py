"""
Run the independent implementation against the four frozen vector sets
and report matched/total with detailed per-vector mismatches.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import implement


VECTORS = os.path.join(os.path.dirname(__file__), "..", "test-vectors")


def load(name):
    with open(os.path.join(VECTORS, name), "r", encoding="utf-8") as f:
        return json.load(f)


def run_canonical_json():
    data = load("canonical-json.json")
    total = 0
    matched = 0
    failures = []
    for v in data["vectors"]:
        total += 1
        vid = v["id"]
        doc = v["document"]
        if "expect_error" in v:
            expected_err = v["expect_error"]
            try:
                implement.parse_document(doc)
            except implement.CanonicalError as e:
                if e.kind == expected_err:
                    matched += 1
                else:
                    failures.append((vid, f"error {e.kind!r}", f"error {expected_err!r}"))
            except Exception as e:  # noqa: BLE001
                failures.append((vid, f"exception {e!r}", f"error {expected_err!r}"))
            else:
                failures.append((vid, "accepted", f"error {expected_err!r}"))
        else:
            expected = v["expected_canonical"]
            try:
                value = implement.parse_document(doc)
                got = implement.canonicalize(value)
            except Exception as e:  # noqa: BLE001
                failures.append((vid, f"exception {e!r}", expected))
                continue
            if got == expected:
                matched += 1
            else:
                failures.append((vid, got, expected))
    return "canonical-json", matched, total, failures


def run_ed25519():
    data = load("ed25519.json")
    total = 0
    matched = 0
    failures = []

    for v in data["kat_vectors"]:
        total += 1
        vid = v["id"]
        seed = bytes.fromhex(v["secret_key_hex"])
        message = bytes.fromhex(v["message_hex"])
        pub = implement.derive_public_key(seed)
        sig = implement.ed25519_sign(seed, message)

        checks = [
            ("public_key_hex", pub.hex(), v["public_key_hex"]),
            ("key_id", implement.key_id(pub), v["key_id"]),
            ("signature_hex", sig.hex(), v["signature_hex"]),
            ("signature_field", implement.signature_field(sig), v["signature_field"]),
        ]
        bad = [(f, g, e) for (f, g, e) in checks if g != e]
        if not bad:
            matched += 1
        else:
            failures.append((vid, bad))

    for v in data["signing_vectors"]:
        total += 1
        vid = v["id"]
        seed = bytes.fromhex(v["seed_hex"])
        try:
            obj = implement.parse_document(v["document"])
            signing_input = implement.signing_bytes(obj)
            sig = implement.ed25519_sign(seed, signing_input.encode("utf-8"))
            wire = implement.wire_form(
                dict(obj, signature=implement.signature_field(sig))
            )
        except Exception as e:  # noqa: BLE001
            failures.append((vid, f"exception {e!r}", "see vector"))
            continue

        sha = hashlib.sha256(signing_input.encode("utf-8")).hexdigest()
        bad = []
        if signing_input != v["signing_input"]:
            bad.append(("signing_input", signing_input, v["signing_input"]))
        if sha != v["signing_input_sha256"]:
            bad.append(("signing_input_sha256", sha, v["signing_input_sha256"]))
        if sig.hex() != v["signature_hex"]:
            bad.append(("signature_hex", sig.hex(), v["signature_hex"]))
        if implement.signature_field(sig) != v["signature_field"]:
            bad.append(("signature_field", implement.signature_field(sig), v["signature_field"]))
        if wire != v["wire"]:
            bad.append(("wire", wire, v["wire"]))
        if not bad:
            matched += 1
        else:
            failures.append((vid, bad))

    return "ed25519", matched, total, failures


def run_state_machine():
    data = load("state-machine.json")
    total = 0
    matched = 0
    failures = []
    for v in data["vectors"]:
        total += 1
        vid = v["id"]
        try:
            got = implement.transition(v["from"], v["event"])
        except Exception as e:  # noqa: BLE001
            failures.append((vid, f"exception {e!r}", v["to"]))
            continue
        if got == v["to"]:
            matched += 1
        else:
            failures.append((vid, got, v["to"]))
    return "state-machine", matched, total, failures


def run_validation():
    data = load("validation.json")
    total = 0
    matched = 0
    failures = []
    for v in data["vectors"]:
        total += 1
        vid = v["id"]
        got = implement.validate_signal(
            v["grant"], v["signal"], v["signer"], v["context"]
        )
        if got == v["expected"]:
            matched += 1
        else:
            failures.append((vid, got, v["expected"]))
    return "validation", matched, total, failures


def main():
    all_ok = True
    for name, matched, total, failures in (
        run_canonical_json(),
        run_ed25519(),
        run_state_machine(),
        run_validation(),
    ):
        status = "PASS" if matched == total else "FAIL"
        if matched != total:
            all_ok = False
        print(f"{name:16s} {status}  {matched}/{total} matched")
        for vid, got, expected in failures:
            print(f"    {vid}: got {got!r}  expected {expected!r}")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
