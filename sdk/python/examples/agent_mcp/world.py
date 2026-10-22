"""Demo world for the MCP example: one provider runtime, one agent, one grant."""

import os
import sys

SDK_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
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
from ccp.adapters.mcp import McpServer  # noqa: E402
from ccp.agent import Agent  # noqa: E402

# Demo keys are deterministic so restarts keep the same grant.
PROVIDER_SEED = bytes(range(32))
AGENT_SEED = bytes(range(32, 64))

CATALOGUE = {"item-123": {"item_id": "item-123", "name": "Widget"}}
INTENTS = {
    "example.lookup": {
        "description": "Look up one item from the provider's catalogue",
        "params_schema": "schema:example.lookup.params.v1",
        "result_schema": "schema:example.lookup.result.v1",
        "required_capabilities": ["store.read"],
        "placement": "local",
        "data_egress": {"network": False, "fields": []},
        "suggested_limits": {"calls_per_hour": 10},
        "confirmation": "per_action",
    }
}


def create_world(*, confirm=None):
    """Build the demo runtime and bridge; ``confirm`` is the host decision."""
    provider = SigningKey.from_seed(PROVIDER_SEED)
    agent = Agent(SigningKey.from_seed(AGENT_SEED))

    manifest = Manifest.parse(sign_document({
        "ccp": "0.5-draft",
        "provider": {"id": provider.key_id, "name": "Example Service"},
        "version": 1,
        "intents": INTENTS,
    }, provider))
    manifest.verify()

    grant = Grant(
        id="g-agent-demo",
        requester_key=agent.key_id,
        contact_id="c-agent-demo",
        manifest_digest=manifest.digest,
        manifest_version=1,
        intents=["example.lookup"],
        limits={"calls_per_hour": 10},
        created_at="2026-10-22T10:00:00Z",
        expires_at="2030-01-01T00:00:00Z",
        confirmation={"example.lookup": "grant-policy"},
        capabilities=["store.read"],
        placement=["local"],
        egress={"network": False},
    )

    hosts = HostRegistry()
    hosts.register_host("store.read", lambda item_id: CATALOGUE.get(item_id))
    hosts.register_intent(
        "example.lookup",
        lambda params, access: access.call("store.read", params["item_id"]),
    )

    runtime = Runtime(
        grants=GrantStore([grant]),
        manifests=ManifestStore([manifest]),
        schemas=SchemaRegistry({
            "schema:example.lookup.params.v1": {
                "type": "object",
                "properties": {"item_id": {"type": "string"}},
                "required": ["item_id"],
                "additionalProperties": False,
            },
            "schema:example.lookup.result.v1": {
                "type": "object",
                "properties": {
                    "item_id": {"type": "string"},
                    "name": {"type": "string"},
                },
                "required": ["item_id", "name"],
                "additionalProperties": False,
            },
        }),
        hosts=hosts,
        audit=AuditLog(),
    )

    bridge = McpServer(runtime=runtime, agent=agent, grant=grant,
                       confirm=confirm)
    return bridge, runtime
