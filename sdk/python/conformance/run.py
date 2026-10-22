#!/usr/bin/env python3
"""Language-neutral conformance harness for the Python SDK.

Usage: python3 conformance/run.py <vectors-dir>

Reads whichever of canonical-json.json and validation.json exist in the
directory, prints a JSON summary, and exits 1 if any case fails.
"""

import json
import os
import sys

SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SDK_DIR)

from ccp import canonical  # noqa: E402
from ccp.canonical import CanonicalError  # noqa: E402
from ccp.decision import decide  # noqa: E402
from ccp.model import Grant  # noqa: E402

INTENT_SPEC = {
    "required_capabilities": ["store.read"],
    "confirmation": "grant-policy",
}
PARAMS_SCHEMA = {
    "type": "object",
    "properties": {"item_id": {"type": "string"}},
    "required": ["item_id"],
    "additionalProperties": False,
}


def load(directory, name):
    with open(os.path.join(directory, name), encoding="utf-8") as handle:
        return json.load(handle)


def run_canonical(data):
    failures = []
    for vector in data["vectors"]:
        try:
            got = canonical.canonicalize(vector["document"])
        except CanonicalError as exc:
            got = "error:%s" % exc.code
        except Exception as exc:  # noqa: BLE001 - reported as a failure
            got = "error:%s" % exc
        expected = ("error:%s" % vector["expect_error"]
                    if "expect_error" in vector
                    else vector["expected_canonical"])
        if got != expected:
            failures.append({"id": vector["id"], "expected": expected,
                             "got": got})
    return {
        "passed": len(data["vectors"]) - len(failures),
        "failed": len(failures),
        "failures": failures,
    }


def run_validation(data):
    failures = []
    for vector in data["vectors"]:
        try:
            grant = (Grant.from_dict(vector["grant"])
                     if vector["grant"] else None)
            got = decide(
                grant, vector["signal"], vector["signer"],
                vector["context"]["now"],
                set(vector["context"]["seen"]),
                vector["context"]["counters"],
                intent_spec=INTENT_SPEC,
                params_schema=PARAMS_SCHEMA,
            )
        except Exception as exc:  # noqa: BLE001 - reported as a failure
            got = "error:%s" % exc
        if got != vector["expected"]:
            failures.append({"id": vector["id"],
                             "expected": vector["expected"], "got": got})
    return {
        "passed": len(data["vectors"]) - len(failures),
        "failed": len(failures),
        "failures": failures,
    }


def main():
    if len(sys.argv) != 2:
        print("usage: python3 conformance/run.py <vectors-dir>", file=sys.stderr)
        return 2

    directory = sys.argv[1]
    summary = {}
    if os.path.exists(os.path.join(directory, "canonical-json.json")):
        summary["canonical-json"] = run_canonical(
            load(directory, "canonical-json.json"))
    if os.path.exists(os.path.join(directory, "validation.json")):
        summary["validation"] = run_validation(
            load(directory, "validation.json"))

    print(json.dumps(summary, indent=2))
    return 0 if all(entry["failed"] == 0 for entry in summary.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
