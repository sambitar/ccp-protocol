"""Shared end-to-end fixture for runtime, role, and adapter tests."""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SDK_DIR = os.path.dirname(HERE)
if SDK_DIR not in sys.path:
    sys.path.insert(0, SDK_DIR)

from ccp import (  # noqa: E402
    AuditLog,
    Grant,
    GrantStore,
    HostRegistry,
    Manifest,
    ManifestStore,
    Runtime,
    SchemaRegistry,
    SigningKey,
    sign_document,
)

NOW = "2026-10-22T12:00:30Z"

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
INTENTS = {
    "example.lookup": {
        "description": "Look up one item requested by the consumer",
        "params_schema": "schema:example.lookup.params.v1",
        "result_schema": "schema:example.lookup.result.v1",
        "required_capabilities": ["store.read"],
        "placement": "local",
        "data_egress": {"network": False, "fields": []},
        "suggested_limits": {"calls_per_hour": 10},
        "confirmation": "grant-policy",
    }
}
STORE = {"item-123": {"item_id": "item-123", "name": "Widget"}}


def build_world(*, confirmation="none", limits=None, capabilities=None,
                expires_at="2026-10-22T23:00:00Z", grant_state="active",
                now=NOW):
    provider = SigningKey.from_seed(bytes(range(32)))
    requester = SigningKey.from_seed(bytes(range(32, 64)))

    manifest_document = sign_document({
        "ccp": "0.5-draft",
        "provider": {"id": provider.key_id, "name": "Example Service"},
        "version": 1,
        "intents": INTENTS,
    }, provider)
    manifest = Manifest.parse(manifest_document)
    manifest.verify()

    grant = Grant(
        id="g-1",
        requester_key=requester.key_id,
        contact_id="c-1",
        manifest_digest=manifest.digest,
        manifest_version=1,
        intents=["example.lookup"],
        limits={"calls_per_hour": 10} if limits is None else limits,
        created_at="2026-10-22T10:00:00Z",
        expires_at=expires_at,
        confirmation={"example.lookup": confirmation},
        capabilities=["store.read"] if capabilities is None else capabilities,
        placement=["local"],
        egress={"network": False},
        state=grant_state,
    )

    schemas = SchemaRegistry({
        "schema:example.lookup.params.v1": PARAMS_SCHEMA,
        "schema:example.lookup.result.v1": RESULT_SCHEMA,
    })
    hosts = HostRegistry()
    hosts.register_host("store.read", lambda item_id: STORE.get(item_id))
    hosts.register_intent(
        "example.lookup",
        lambda params, access: access.call("store.read", params["item_id"]),
    )

    runtime = Runtime(
        grants=GrantStore([grant]),
        manifests=ManifestStore([manifest]),
        schemas=schemas,
        hosts=hosts,
        audit=AuditLog(),
        clock=lambda: now,
    )
    return {
        "provider": provider,
        "requester": requester,
        "manifest": manifest,
        "grant": grant,
        "runtime": runtime,
    }


def signal_for(world, *, request_id="req-1", params=None,
               intent="example.lookup", expires_at="2026-10-22T12:01:00Z",
               ccp="0.5-draft", signer=None):
    signer = signer or world["requester"]
    return sign_document({
        "ccp": ccp,
        "request_id": request_id,
        "grant_digest": world["manifest"].digest,
        "intent": intent,
        "params": {"item_id": "item-123"} if params is None else params,
        "issued_at": "2026-10-22T12:00:00Z",
        "expires_at": expires_at,
    }, signer)
