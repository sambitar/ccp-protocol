"""Runnable CCP provider on FastAPI.

Run with ``python examples/provider_fastapi/server.py``. The provider serves
one signed manifest, accepts signed signals, and confirms through a demo
endpoint; a real provider confirms through its own trusted UI.
"""

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

SDK_DIR = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
sys.path.insert(0, SDK_DIR)

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from ccp import (  # noqa: E402
    AuditLog,
    AUTHORIZED,
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
from ccp.adapters.fastapi import manifest_router, provider_router  # noqa: E402
from ccp.requester import sign_signal  # noqa: E402

PORT = int(os.environ.get("PORT", "8788"))

PROVIDER = SigningKey.from_seed(bytes(range(32)))
REQUESTER = SigningKey.from_seed(bytes(range(32, 64)))

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

manifest = Manifest.parse(sign_document({
    "ccp": "0.5-draft",
    "provider": {"id": PROVIDER.key_id, "name": "Example Service"},
    "version": 1,
    "intents": INTENTS,
}, PROVIDER))
manifest.verify()

grant = Grant(
    id="g-demo",
    requester_key=REQUESTER.key_id,
    contact_id="c-demo",
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

app = FastAPI(title="CCP example provider")
app.include_router(manifest_router(manifest.document))

# The demo knows a single requester. A real provider resolves the key from an
# authenticated channel bound to a stored contact, never from the signal.
app.include_router(provider_router(
    runtime, lambda request: REQUESTER.verifying_key()))


@app.post("/ccp/confirm")
async def confirm(request: Request):
    """DEMO ONLY: a real confirmation comes from the provider's trusted UI."""
    body = await request.json()
    pending_id = body.get("pending_id") if isinstance(body, dict) else None
    approved = body.get("approved") if isinstance(body, dict) else None
    if not isinstance(pending_id, str) or not isinstance(approved, bool):
        return JSONResponse(
            {"outcome": "invalid_request", "error": "invalid_request"},
            status_code=400,
        )

    decision = runtime.confirm(pending_id, approved)
    status = (200 if decision.outcome in (AUTHORIZED, "cancelled")
              else 400 if decision.outcome == "invalid_request" else 409)
    return JSONResponse(
        {name: value for name, value in asdict(decision).items()
         if value is not None},
        status_code=status,
    )


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if __name__ == "__main__":
    now = datetime.now(timezone.utc)
    signal = sign_signal(
        "demo-" + now.strftime("%H%M%S"),
        manifest.digest,
        "example.lookup",
        {"item_id": "item-123"},
        _iso(now),
        _iso(now + timedelta(minutes=5)),
        REQUESTER,
    )

    print("CCP provider listening on http://127.0.0.1:%d" % PORT, flush=True)
    print("manifest digest: %s" % manifest.digest, flush=True)
    print("\n1. Submit this single-use signal:", flush=True)
    print("curl -s http://127.0.0.1:%d/ccp -H 'content-type: application/json'"
          " -d '%s'" % (PORT, json.dumps({"signal": signal})), flush=True)
    print("\n2. Approve the returned pending_id:", flush=True)
    print("curl -s http://127.0.0.1:%d/ccp/confirm"
          " -H 'content-type: application/json'"
          " -d '{\"pending_id\":\"<pending_id>\",\"approved\":true}'" % PORT,
          flush=True)

    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
