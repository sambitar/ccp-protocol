#!/usr/bin/env python3
"""Cross-language interop: sign a fixed manifest and signal, or verify the
other implementation's output.

Usage:
  python3 conformance/interop.py generate <out.json>
  python3 conformance/interop.py verify <in.json>
"""

import hashlib
import json
import os
import sys

SDK_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SDK_DIR)

from ccp import Requester, SigningKey, canonical  # noqa: E402
from ccp.consumer import verify_manifest, verify_signal  # noqa: E402

PROVIDER_SEED = bytes(range(32))
REQUESTER_SEED = bytes(range(32, 64))

INTENTS = {
    "example.lookup": {
        "description": "Lookup caf\u00e9 e\u0301 \U0001f600",
        "params_schema": "schema:example.lookup.params.v1",
        "result_schema": "schema:example.lookup.result.v1",
        "required_capabilities": ["store.read"],
        "placement": "local",
        "data_egress": {"network": False, "fields": []},
        "suggested_limits": {"calls_per_hour": 10},
        "confirmation": "per_action",
    },
}

PARAMS = {
    "item_id": "caf\u00e9",
    "note": "e\u0301 \U0001f600",
    "count": 18446744073709551616,
}


def generate():
    provider = Requester(SigningKey.from_seed(PROVIDER_SEED))
    requester = Requester(SigningKey.from_seed(REQUESTER_SEED))

    manifest_wire = provider.manifest(
        {"id": provider.key_id, "name": "Example Service \u2014 \u4f8b"},
        1,
        INTENTS,
    )
    digest = verify_manifest(manifest_wire).digest

    signal_wire = requester.signal(
        "interop-1",
        digest,
        "example.lookup",
        PARAMS,
        "2026-10-22T12:00:00Z",
        "2026-10-22T12:01:00Z",
    )

    signing_input = canonical.signing_bytes(signal_wire)
    return {
        "manifest_wire": manifest_wire,
        "manifest_digest": digest,
        "signal_wire": signal_wire,
        "signal_signing_sha256": hashlib.sha256(signing_input).hexdigest(),
    }


def verify(data):
    provider_key = SigningKey.from_seed(PROVIDER_SEED)
    requester_key = SigningKey.from_seed(REQUESTER_SEED)

    manifest = verify_manifest(data["manifest_wire"], provider_key.key_id)
    if manifest.digest != data["manifest_digest"]:
        raise AssertionError("manifest digest mismatch")

    verify_signal(data["signal_wire"], requester_key.verifying_key())

    signing_hash = hashlib.sha256(
        canonical.signing_bytes(data["signal_wire"])).hexdigest()
    if signing_hash != data["signal_signing_sha256"]:
        raise AssertionError("signal signing hash mismatch")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("generate", "verify"):
        print("usage: python3 conformance/interop.py <generate|verify> <path>",
              file=sys.stderr)
        return 2

    mode, path = sys.argv[1], sys.argv[2]
    if mode == "generate":
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(generate(), handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    else:
        with open(path, encoding="utf-8") as handle:
            verify(json.load(handle))
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
