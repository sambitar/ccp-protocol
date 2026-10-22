#!/usr/bin/env python3
"""Generate and self-check the v5 host-contract vectors.

v5 pins §26.4: a host declares its class, risk, confirmation floor,
idempotency behavior, placement, and egress. Extension hosts must declare a
class, and a write, control, compute, or irreversible host can never suppress
confirmation.

Usage: /usr/bin/python3 test-vectors/v5/generate.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CCP_VERSION = "0.5-draft"

CORE_HOSTS = {
    "store.read", "files.read", "files.search",
    "notify", "confirm", "audit.append",
}
CLASSES = {"read", "write", "disclose", "control", "compute"}
RISKS = {"read", "write", "disclose", "irreversible"}
PLACEMENTS = {"local", "remote", "delegated"}
IDEMPOTENCY = {"pure", "caller_key", "atomic", "none"}

DEFAULTS = {
    "read": {"risk": "read", "minConfirmation": "none", "idempotency": "pure"},
    "disclose": {"risk": "disclose", "minConfirmation": "per_action",
                 "idempotency": "pure"},
    "write": {"risk": "write", "minConfirmation": "per_action",
              "idempotency": "caller_key"},
    "control": {"risk": "write", "minConfirmation": "per_action",
                "idempotency": "none"},
    "compute": {"risk": "read", "minConfirmation": "per_action",
                "idempotency": "pure"},
}


def validate(host, profile):
    """Reference implementation: return None when valid, else a code."""
    profile = profile or {}
    if not isinstance(host, str) or not host:
        return "invalid_request"
    declared = profile.get("class")
    if declared is None and host not in CORE_HOSTS:
        return "invalid_request"
    if declared is not None and declared not in CLASSES:
        return "invalid_request"
    host_class = declared or "read"
    defaults = DEFAULTS[host_class]

    risk = profile.get("risk") or defaults["risk"]
    if risk not in RISKS:
        return "invalid_request"

    floor = profile.get("minConfirmation") or defaults["minConfirmation"]
    if floor not in ("none", "per_action"):
        return "invalid_request"
    if floor == "none":
        if host_class not in ("read", "disclose"):
            return "invalid_request"
        if risk == "irreversible":
            return "invalid_request"

    idempotency = profile.get("idempotency") or defaults["idempotency"]
    if idempotency not in IDEMPOTENCY:
        return "invalid_request"

    network = profile.get("network", False)
    if not isinstance(network, bool):
        return "invalid_request"

    placement = profile.get("placement")
    if placement is None:
        placement = ["local"]
    if not isinstance(placement, list) or not placement:
        return "invalid_request"
    seen = set()
    for entry in placement:
        if entry not in PLACEMENTS or entry in seen:
            return "invalid_request"
        seen.add(entry)

    fields = profile.get("fields")
    if fields is None:
        fields = []
    if not isinstance(fields, list):
        return "invalid_request"
    seen_fields = set()
    for field in fields:
        if not isinstance(field, str) or field == "" or field in seen_fields:
            return "invalid_request"
        seen_fields.add(field)
    if network and not fields and host_class == "disclose":
        return "invalid_request"
    return None


# ---------------------------------------------------------------------------
# the catalogue: every profile an SDK may register without further review
# ---------------------------------------------------------------------------

CATALOGUE = [
    ("store.read", {}),
    ("store.write", {"class": "write"}),
    ("files.write", {"class": "write"}),
    ("net.request", {"class": "disclose", "network": True,
                     "placement": ["local", "remote"],
                     "fields": ["url", "method", "body"]}),
    ("model.infer", {"class": "compute", "risk": "disclose",
                     "network": True, "placement": ["local", "remote"],
                     "fields": ["prompt", "response"]}),
    ("device.operation", {"class": "control", "risk": "irreversible"}),
    ("payment.prepare", {"class": "write", "network": True,
                         "fields": ["payee", "amount"]}),
    ("payment.submit", {"class": "write", "risk": "irreversible",
                        "network": True, "fields": ["payment_id"]}),
    ("payment.address.resolve", {"class": "read"}),
    ("calendar.read", {"class": "read"}),
    ("contacts.read", {"class": "read"}),
    ("mail.search", {"class": "read"}),
]

INVALID = [
    ("net.request", {}, "extension host without a class"),
    ("net.request", {"class": "disclose", "network": True},
     "network disclose host without fields"),
    ("store.write", {"class": "write", "minConfirmation": "none"},
     "write host suppressing confirmation"),
    ("payment.submit", {"class": "write", "risk": "irreversible",
                        "minConfirmation": "none"},
     "irreversible host suppressing confirmation"),
    ("device.operation", {"class": "control", "placement": ["edge"]},
     "unknown placement"),
    ("mail.search", {"class": "read", "fields": ["q", "q"]},
     "duplicate field"),
    ("net.request", {"class": "disclose", "network": "yes",
                     "fields": ["url"]},
     "non-boolean network"),
    ("model.infer", {"class": "compute", "minConfirmation": "none"},
     "compute host suppressing confirmation"),
]


def build_vectors():
    vectors = []
    for index, (host, profile) in enumerate(CATALOGUE, start=1):
        assert validate(host, profile) is None, (host, profile)
        vectors.append({
            "id": "host-%03d" % index,
            "name": "%s catalogue profile" % host,
            "host": host,
            "profile": profile,
            "expected": "valid",
        })

    for index, (host, profile, name) in enumerate(INVALID, start=1):
        assert validate(host, profile) == "invalid_request", (host, profile)
        vectors.append({
            "id": "host-bad-%03d" % index,
            "name": name,
            "host": host,
            "profile": profile,
            "expected": "invalid_request",
        })
    return vectors


def main():
    vectors = build_vectors()
    data = {
        "ccp": CCP_VERSION,
        "rule": "host contracts and confirmation floors (§26.4)",
        "vectors": vectors,
    }
    path = os.path.join(HERE, "hosts.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("wrote hosts.json  (%d vectors)" % len(vectors))
    print("self-check OK")


if __name__ == "__main__":
    main()
