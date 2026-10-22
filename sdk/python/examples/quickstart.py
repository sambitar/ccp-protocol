"""The end-to-end CCP loop, runnable.

Run with `python examples/quickstart.py` from `sdk/python`. It signs a
manifest, approves one intent, submits a signed signal, then revokes the
grant and shows the next request being refused.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccp import (  # noqa: E402
    AuditLog,
    GrantStore,
    HostRegistry,
    ManifestStore,
    Runtime,
    SchemaRegistry,
    SigningKey,
    create_grant,
    sign_manifest,
    sign_signal,
    verify_manifest,
)

NOW = "2026-10-22T12:00:00Z"
UNTIL = "2030-01-01T00:00:00Z"

PARAMS_SCHEMA = {
    "type": "object",
    "properties": {"item_id": {"type": "string"}},
    "required": ["item_id"],
    "additionalProperties": False,
}
RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "item_id": {"type": "string"},
        "name": {"type": "string"},
    },
    "required": ["item_id", "name"],
    "additionalProperties": False,
}


def main():
    provider = SigningKey.from_seed(bytes(range(32)))
    requester = SigningKey.from_seed(bytes(range(32, 64)))

    # 1. The provider publishes a signed manifest. Publishing grants nothing.
    manifest = verify_manifest(sign_manifest(
        {"id": provider.key_id, "name": "Example Service"},
        1,
        {
            "example.lookup": {
                "description": "Look up one item the consumer asked for",
                "params_schema": "schema:example.lookup.params.v1",
                "result_schema": "schema:example.lookup.result.v1",
                "required_capabilities": ["store.read"],
                "placement": "local",
                "data_egress": {"network": False, "fields": []},
                "suggested_limits": {"calls_per_hour": 5},
                "confirmation": "none",
            },
        },
        provider,
    ))

    # 2. The consumer approves one intent. This is the only source of authority.
    grant = create_grant(
        contact_id="c-1",
        requester_key=requester.key_id,
        manifest=manifest,
        intents=["example.lookup"],
        created_at="2026-10-22T10:00:00Z",
        expires_at=UNTIL,
    )

    # 3. The runtime owns execution. The host is local and offline.
    hosts = HostRegistry()
    hosts.register_host(
        "store.read",
        lambda item_id: {"item_id": item_id, "name": "Widget"},
    )
    hosts.register_intent(
        "example.lookup",
        lambda params, access: access.call("store.read", params["item_id"]),
    )

    runtime = Runtime(
        grants=GrantStore([grant]),
        manifests=ManifestStore([manifest]),
        schemas=SchemaRegistry({
            "schema:example.lookup.params.v1": PARAMS_SCHEMA,
            "schema:example.lookup.result.v1": RESULT_SCHEMA,
        }),
        hosts=hosts,
        audit=AuditLog(),
        clock=lambda: NOW,
    )

    # 4. The requester signs a signal bound to the manifest digest.
    def signal(request_id):
        return sign_signal(
            request_id, manifest.digest, "example.lookup",
            {"item_id": "item-123"},
            "2026-10-22T11:59:00Z", "2026-10-22T12:01:00Z", requester)

    decision = runtime.submit(signal("req-1"), requester.verifying_key())
    print("decision:", decision.outcome, decision.result)

    # 5. Revocation is local and permanent.
    runtime.revoke_grant(grant.id, "demo revoke")

    after_revoke = runtime.submit(signal("req-2"), requester.verifying_key())
    print("after revoke:", after_revoke.error)


if __name__ == "__main__":
    main()
