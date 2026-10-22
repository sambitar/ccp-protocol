# CCP reference SDK

A Python reference runtime for the Capability Contacts Protocol (draft
v0.5). It implements the protocol primitives and a runtime that validates
signals, enforces local grants, mediates host functions, supports
two-phase confirmation, and keeps a private audit log.

## Layout

| Module | Implements |
| --- | --- |
| `ccp.canonical` | strict canonical JSON (§25.1) |
| `ccp.crypto` | Ed25519 key/signature encoding (§25.2) |
| `ccp.schema` | JSON Schema subset (§25.3) |
| `ccp.model` | `Manifest`, `Grant`, `Signal`, `Decision` |
| `ccp.requester` | build and sign manifests and signals |
| `ccp.consumer` | verify inbound documents, permission cards |
| `ccp.agent` | agent tool calls and attenuation |
| `ccp.stores` | grant/manifest/schema stores, replay, limits |
| `ccp.decision` | the pure §10.3 validation decision |
| `ccp.state_machine` | the §26.3 side-effect transitions |
| `ccp.hosts` | host-function registry and privilege mediation |
| `ccp.runtime` | submission, confirmation, execution, audit |
| `ccp.adapters.fastapi` | provider signal/manifest routes |
| `ccp.adapters.mcp` | transport-neutral MCP tool bridge |

## Quick start

```python
from ccp import (Grant, GrantStore, HostRegistry, Manifest, ManifestStore,
                 Runtime, SchemaRegistry, SigningKey, sign_document)

provider = SigningKey.generate()
requester = SigningKey.generate()

manifest = Manifest.parse(sign_document({
    "ccp": "0.5-draft",
    "provider": {"id": provider.key_id, "name": "Example Service"},
    "version": 1,
    "intents": {
        "example.lookup": {
            "params_schema": "schema:example.lookup.params.v1",
            "result_schema": "schema:example.lookup.result.v1",
            "required_capabilities": ["store.read"],
            "confirmation": "grant-policy",
        }
    },
}, provider))
manifest.verify()

grant = Grant(
    id="g-1",
    requester_key=requester.key_id,
    contact_id="c-1",
    manifest_digest=manifest.digest,
    manifest_version=1,
    intents=["example.lookup"],
    limits={"calls_per_hour": 10},
    created_at="2026-10-22T10:00:00Z",
    expires_at="2026-10-22T23:00:00Z",
    confirmation={"example.lookup": "none"},
    capabilities=["store.read"],
    placement=["local"],
    egress={"network": False},
)

schemas = SchemaRegistry({
    "schema:example.lookup.params.v1": {
        "type": "object",
        "properties": {"item_id": {"type": "string"}},
        "required": ["item_id"],
        "additionalProperties": False,
    },
})
hosts = HostRegistry()
hosts.register_host("store.read", lambda item_id: {"item_id": item_id})
hosts.register_intent(
    "example.lookup",
    lambda params, access: access.call("store.read", params["item_id"]),
)

runtime = Runtime(
    grants=GrantStore([grant]),
    manifests=ManifestStore([manifest]),
    schemas=schemas,
    hosts=hosts,
    clock=lambda: "2026-10-22T12:00:30Z",
)

signal = sign_document({
    "ccp": "0.5-draft",
    "request_id": "req-1",
    "grant_digest": manifest.digest,
    "intent": "example.lookup",
    "params": {"item_id": "item-123"},
    "issued_at": "2026-10-22T12:00:00Z",
    "expires_at": "2026-10-22T12:01:00Z",
}, requester)

decision = runtime.submit(signal, requester.verifying_key())
assert decision.authorized
```

## Confirmation

If a grant's confirmation policy for an intent is `per_action`,
`Runtime.submit` returns a `Decision` with `needs_confirmation` true and a
`pending_id`. The trusted client later calls:

```python
runtime.confirm(decision.pending_id, approved=True)   # or approved=False
```

## Roles

Requester, consumer, and agent mirror the TypeScript surfaces.

```python
from ccp import Requester, SigningKey
from ccp.consumer import permission_card, verify_manifest

requester = Requester(SigningKey.generate())
manifest_wire = requester.manifest(
    {"id": provider.key_id, "name": "Example Service"}, 1, intents)

manifest = verify_manifest(manifest_wire)
card = permission_card(manifest, "example.lookup")

signal_wire = requester.signal(
    "req-1", manifest.digest, "example.lookup", {"item_id": "item-123"},
    "2026-10-22T12:00:00Z", "2026-10-22T12:01:00Z")

from ccp import Agent, attenuates

agent = Agent(agent_key)
tool_signal = agent.signal_for(
    intent="example.lookup", params={"item_id": "item-123"},
    grant=grant, request_id="req-2",
    issued_at="2026-10-22T12:00:00Z", expires_at="2026-10-22T12:01:00Z")
assert attenuates(parent_grant, child_grant)
```

## FastAPI provider

```python
from fastapi import FastAPI
from ccp.adapters.fastapi import manifest_router, provider_router

app = FastAPI()
app.include_router(manifest_router(manifest.document))
app.include_router(provider_router(runtime, key_resolver))
```

`key_resolver(request)` returns the sender's `VerifyingKey`, or `None` for an
unknown sender; it may be sync or async. Statuses match the TypeScript
adapter: 200 authorized/confirmation_required, 400 invalid_request, 401
unknown sender, 403 unauthenticated/no_matching_grant, 409 other refusals.

The adapter only parses `{"signal": "<canonical json>"}`, resolves the key,
and calls `Runtime.submit`. Install with `pip install 'ccp-protocol[fastapi]'`.

## MCP agent bridge

```python
from ccp.adapters.mcp import McpServer

bridge = McpServer(
    runtime=runtime,
    agent=agent,
    grant=grant,
    # Trusted host decision. Omit to surface confirmation_required instead.
    confirm=lambda request: ask_user(request.card, request.params),
)

# Adapt bridge.tools and `await bridge.call_tool(name, args)` in your MCP
# server. The bridge has no MCP dependency and never auto-approves.
```

One bridge serves one grant; tool names are the granted intent names.
Provider descriptions are labelled untrusted, results are returned as JSON
data, and confirmation is the host's decision. Install with
`pip install 'ccp-protocol[mcp]'`. See `examples/agent_mcp/`.

## Identity and admission (§25.8)

Publish a signed identity document, verify one for a known contact, and
let a reviewed policy answer matching requests without a click.

```python
from ccp import (
    AdmissionRequest, build_admission_policy, build_identity_document,
    verify_admission_policy, verify_identity_document,
)

identity = build_identity_document(
    {
        "name": "Example Service",
        "manifest_digest": manifest.digest,
        "issued_at": "2026-10-22T00:00:00Z",
        "expires_at": "2027-10-22T00:00:00Z",
    },
    signing_key,
)

peer = verify_identity_document(
    identity, expected_identity=known_contact_key,
    manifest_digest=manifest.digest,
)

policy = verify_admission_policy(
    build_admission_policy(
        {"version": 1, "default": "confirm", "rules": rules,
         "issued_at": issued_at, "expires_at": expires_at},
        host_key,
    ),
    expected_host=host_key.key_id,
)

outcome = runtime.admit_request(
    policy,
    AdmissionRequest(
        requester_key=requester.key_id,
        contact_id="c-1",
        intent="files.search",
        risk="read",
        now="2026-10-22T12:00:00Z",
    ),
    manifest,
)
# outcome.result.decision is allow | confirm | deny; outcome.grant is set on allow.
```

Accepting an invitation creates a contact, never a grant. `default` must
be `confirm` or `deny`, and only `read`/`disclose` intents can be
admitted. Policy grants use a deterministic id, so a revocation is not
undone by the next matching request. See
[`docs/guides/identity.md`](../../docs/guides/identity.md) and
[`docs/consistency-audit.md`](../../docs/consistency-audit.md).

## Durable stores

`Runtime` accepts any object implementing the store contracts in
`ccp/stores.py`. `ccp.stores_sqlite.SqliteStores` provides SQLite-backed
implementations of all six, using only the standard library:

```python
from ccp import Runtime
from ccp.stores_sqlite import SqliteStores

stores = SqliteStores("ccp.db")  # or ":memory:"
runtime = Runtime(
    grants=stores.grants,
    manifests=stores.manifests,
    replay=stores.replay,
    limits=stores.limits,
    pending=stores.pending,
    audit=stores.audit,
    schemas=schemas,
    hosts=hosts,
)
```

The atomic operations (`try_reserve`, `mark_if_new`, `take`) use
`BEGIN IMMEDIATE` transactions, so they are safe across processes sharing
the database file. See `../../docs/guides/persistence.md` for the contract.

## Examples

- `examples/provider_fastapi/` — HTTP provider (`python examples/provider_fastapi/server.py`)
- `examples/agent_mcp/` — stdio MCP server and in-memory client demo
  (`python examples/agent_mcp/demo.py`)

## Tests

```sh
/usr/bin/python3 -m unittest discover -s tests
```

The suite includes conformance tests that run the frozen vectors in
`../../test-vectors/` through the SDK, plus end-to-end runtime, role, and
adapter tests. The FastAPI and MCP tests need the `dev` extra:

```sh
pip install '.[dev]'
/usr/bin/python3 -m unittest discover -s tests
```

Requires Python 3.10+ and `cryptography` for Ed25519. The MCP extra
requires Python 3.10+.
