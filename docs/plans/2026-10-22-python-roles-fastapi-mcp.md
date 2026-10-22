# Python Role Surfaces + FastAPI/MCP Adapters Plan

**Goal:** bring the Python SDK to parity with the TypeScript role APIs and add runnable FastAPI and MCP integrations, without changing the protocol core.

**Architecture:** Three thin role modules (`requester`, `consumer`, `agent`) sit on the existing primitives (`Manifest`, `Signal`, `Grant`, `sign_document`). Two optional adapters live under `ccp.adapters`: a FastAPI `APIRouter` factory that parses an HTTP envelope and delegates to `Runtime`, and a transport-neutral MCP bridge that signs each tool call and delegates to `Runtime`. Neither adapter makes authorization decisions.

**Tech Stack:** Python 3.10+ core, `cryptography` (existing), `unittest` (existing). Optional extras: `fastapi` + `httpx` for the HTTP adapter and tests, `mcp` 2.x for the Python MCP server example. The installed environment has Python 3.12, `fastapi` 0.160, `httpx` 0.28, and `mcp` 2.2.

**Spec:** `CCP_Working_Draft_v0.5.md` §10.3–10.4, §11.4, §15.1–15.3, §26.6. Contract: `test-vectors/`.

## Global Constraints

- The 20 existing Python tests and all 51 frozen vectors stay green.
- `import ccp` must not import `fastapi` or `mcp`; adapters are opt-in imports.
- Adapters never bypass `Runtime`; they parse, resolve the sender key, and call `submit` / `confirm`.
- The MCP bridge never auto-approves. A trusted host supplies `confirm`; without it, the call surfaces `confirmation_required`.
- Provider text and tool results are untrusted data (§15.3).
- Python API names are snake_case; wire fields stay snake_case.
- One bridge per grant; the grant is the agent's whole authority.
- `test-vectors/`, `phase4/`, and `phase4-confirm/` are untouched.
- Commit only when the user asks.

## File map

| File | Responsibility |
| --- | --- |
| `sdk/python/ccp/requester.py` | `build_manifest`, `sign_manifest`, `build_signal`, `sign_signal`, `Requester` |
| `sdk/python/ccp/consumer.py` | `verify_manifest`, `verify_signal`, `PermissionCard`, `permission_card` |
| `sdk/python/ccp/agent.py` | `Agent`, `attenuates` |
| `sdk/python/ccp/decision.py` | Rename `_confirmation_policy` to public `confirmation_policy` |
| `sdk/python/ccp/adapters/__init__.py` | Marks the optional adapter namespace |
| `sdk/python/ccp/adapters/fastapi.py` | `provider_router`, `signal_endpoint`, `manifest_router`, `manifest_endpoint` |
| `sdk/python/ccp/adapters/mcp.py` | `McpServer`, `McpTool`, `McpToolResult`, `ConfirmationRequest` |
| `sdk/python/tests/test_roles.py` | Requester, consumer, agent, attenuation |
| `sdk/python/tests/test_fastapi_adapter.py` | Real HTTP round trip via `TestClient` |
| `sdk/python/tests/test_mcp_adapter.py` | Bridge behavior (async) |
| `sdk/python/tests/test_mcp_sdk.py` | Real MCP `Client` ↔ `Server` round trip |
| `sdk/python/examples/provider_fastapi/` | Runnable FastAPI provider + README |
| `sdk/python/examples/agent_mcp/` | Stdio MCP server, in-memory demo, README |
| `sdk/python/pyproject.toml` | Optional `fastapi`, `mcp`, `dev` extras |
| `sdk/python/ccp/__init__.py` | Export the role surfaces only |
| `sdk/python/README.md` | Role and adapter quickstarts |

## Design decisions

- **Module-level adapters.** `ccp.adapters.fastapi` and `ccp.adapters.mcp` mirror the TS subpath exports. A package directory per adapter adds nothing yet.
- **Router, not middleware.** Starlette `BaseHTTPMiddleware` complicates request bodies and error handling. An `APIRouter` with endpoint factories is the FastAPI idiom, works in any app, and is trivially testable with `TestClient`.
- **Same status map as TS.** 200 authorized/confirmation_required; 400 invalid_request; 401 unknown sender; 403 unauthenticated/no_matching_grant; 409 other refusals; 500 unexpected.
- **Key resolver may be sync or async.** FastAPI handlers are async; accept either and `await` when inspectable.
- **Async MCP `call_tool`.** Confirmation is a host decision and may await a UI. The rest is synchronous. Results are plain dataclasses so the bridge carries no `mcp` dependency.
- **Exported confirmation policy.** Tool descriptions must agree with the runtime decision; share `confirmation_policy` instead of duplicating the grant/manifest fallback.
- **Optional extras.** Core stays `cryptography` only. `mcp` requires Python 3.10+, so it is never a core dependency.

---

### Task 1: Requester surface

**Files:**
- Create: `sdk/python/ccp/requester.py`
- Create: `sdk/python/tests/test_roles.py`

**Interfaces:**

```python
DEFAULT_CCP = "0.4-draft"

def build_manifest(provider, version, intents, *, ccp=DEFAULT_CCP) -> dict
def sign_manifest(provider, version, intents, signing_key, *, ccp=DEFAULT_CCP) -> str
def build_signal(request_id, grant_digest, intent, params,
                 issued_at, expires_at, *, ccp=DEFAULT_CCP) -> dict
def sign_signal(request_id, grant_digest, intent, params,
                issued_at, expires_at, signing_key, *, ccp=DEFAULT_CCP) -> str

class Requester:
    def __init__(self, signing_key)
    key_id: str
    def manifest(self, provider, version, intents, *, ccp=DEFAULT_CCP) -> str
    def signal(self, request_id, grant_digest, intent, params,
               issued_at, expires_at, *, ccp=DEFAULT_CCP) -> str
```

- [ ] **Step 1: Write failing tests** asserting the manifest/signal parse back as canonical documents, verify against the signer, expose the expected keys, and reject a provider without `id`.
- [ ] **Step 2: Run `/usr/bin/python3 -m unittest discover -s tests` — expect failures** (module missing).
- [ ] **Step 3: Implement** with `sign_document`, raising `CCPError("invalid_request", ...)` when `provider["id"]` is missing.
- [ ] **Step 4: Run the suite — expect the new tests to pass.**

### Task 2: Consumer surface

**Files:**
- Create: `sdk/python/ccp/consumer.py`
- Modify: `sdk/python/tests/test_roles.py`

**Interfaces:**

```python
def verify_manifest(document, expected_provider_id=None) -> Manifest
def verify_signal(document, verifying_key) -> Signal

@dataclass
class PermissionCard:
    who: str
    what: str
    data_read: list[str]
    where: str
    egress: str
    effects: str
    recurrence: str
    revoke: str
    def to_dict(self) -> dict

def permission_card(manifest, intent, *, provider_name=None, data_read=None,
                    where=None, effects=None, recurrence="once",
                    revoke=None) -> PermissionCard
```

- [ ] **Step 1: Write failing tests** for: verification success and tamper failure (`CCPError("unauthenticated")`), unknown intent (`CCPError("intent_not_allowed")`), local placement wording, network egress wording, and `to_dict` keys (`dataRead` stays `data_read` in Python).
- [ ] **Step 2: Run — expect failures.**
- [ ] **Step 3: Implement** by delegating to `Manifest.parse` / `Signal.parse` + `.verify`, and porting the §11.4 field mapping from `sdk/typescript/src/consumer.ts`.
- [ ] **Step 4: Run — expect pass.**

### Task 3: Agent surface and attenuation

**Files:**
- Create: `sdk/python/ccp/agent.py`
- Modify: `sdk/python/tests/test_roles.py`

**Interfaces:**

```python
class Agent:
    def __init__(self, signing_key)
    key_id: str
    verifying_key: VerifyingKey
    def signal_for(self, *, intent, params, grant, request_id,
                   issued_at, expires_at, ccp="0.4-draft") -> str

def attenuates(parent: Grant, child: Grant) -> bool
```

- [ ] **Step 1: Write failing tests** for the signed signal binding (`grant_digest`, `requester_key`), and attenuation parity with TS: narrower child accepted; wider intents, wider limits, longer expiry, weaker confirmation, broader egress rejected.
- [ ] **Step 2: Run — expect failures.**
- [ ] **Step 3: Implement** `signal_for` with `sign_signal`; port `attenuates` from `sdk/typescript/src/agent.ts` (subset intents/capabilities/placement, `expires_at` ordering, limits with missing parent = 0, egress network/fields, `per_action` rank).
- [ ] **Step 4: Run — expect pass.**

### Task 4: Export the confirmation policy

**Files:**
- Modify: `sdk/python/ccp/decision.py`

- [ ] Rename `_confirmation_policy` to `confirmation_policy`, update the call site, and export it from `ccp/__init__.py` only if the adapter needs a public import (the adapter can import `ccp.decision` directly; prefer keeping `__all__` focused).
- [ ] Run the suite — behavior unchanged, 20 existing tests still green.

### Task 5: FastAPI adapter

**Files:**
- Create: `sdk/python/ccp/adapters/__init__.py`
- Create: `sdk/python/ccp/adapters/fastapi.py`
- Create: `sdk/python/tests/test_fastapi_adapter.py`

**Interfaces:**

```python
ASGI-ish key resolver: Callable[[Request], VerifyingKey | None | Awaitable[VerifyingKey | None]]

def signal_endpoint(runtime, key_resolver) -> Callable[[Request], Awaitable[JSONResponse]]
def provider_router(runtime, key_resolver, *, path="/ccp") -> APIRouter
def manifest_endpoint(manifest_wire) -> Callable[[Request], Awaitable[Response]]
def manifest_router(manifest_wire, *, path="/manifest") -> APIRouter
```

**Behavior:** read `{"signal": "<canonical json>"}`; missing/malformed envelope → 400 `invalid_request`; resolver `None` → 401 `unauthenticated`; otherwise `runtime.submit(signal, key)` and map the decision as in the table above. Wrap unexpected exceptions → 500 `outcome_unknown`. Serialize decisions with `dataclasses.asdict`, dropping `None` fields to match the TS wire.

- [ ] **Step 1: Write failing tests** with `FastAPI()` + `TestClient`: authorized 200, tampered 403, missing body 400, unknown sender 401, manifest GET returns the verified wire, an async resolver works, and `GET /ccp` is 405.
- [ ] **Step 2: Run — expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect pass.**

### Task 6: MCP bridge

**Files:**
- Create: `sdk/python/ccp/adapters/mcp.py`
- Create: `sdk/python/tests/test_mcp_adapter.py`

**Interfaces:**

```python
@dataclass
class McpTool: name; description; input_schema; output_schema=None
@dataclass
class McpToolResult: content: list[dict]; structured_content=None; is_error=False
@dataclass
class ConfirmationRequest: pending_id; request_id; intent; params; card

class McpServer:
    def __init__(self, *, runtime, agent, grant, manifest=None, confirm=None,
                 request_ttl_seconds=60, now=None)
    tools: list[McpTool]
    async def call_tool(self, name, args) -> McpToolResult
```

**Behavior:** identical to `sdk/typescript/src/adapters/mcp.ts`, including construction-time validation, verbatim intent names, JSON Schema pass-through, fresh signed signal per call, untrusted-data description, and no auto-approval. `confirm` may be sync or awaitable; a raised callback counts as denial.

- [ ] **Step 1: Write failing tests** (`unittest.IsolatedAsyncioTestCase`) for the same 11 cases as the TS bridge: listing/schemas/description, authorized result + structured content, unknown tool, non-object args, confirmation without host, approval with the exact card, denial, thrown callback, limit, wrong-key binding, revoked grant.
- [ ] **Step 2: Run — expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect pass.**

### Task 7: Real MCP round trip

**Files:**
- Create: `sdk/python/tests/test_mcp_sdk.py`

- [ ] **Step 1: Write a failing async test** using `mcp.server.lowlevel.Server` with `on_list_tools` / `on_call_tool` callbacks and `mcp.client.Client(server)`:

```python
async with Client(server, raise_exceptions=True) as client:
    tools = await client.list_tools()
    result = await client.call_tool("example.lookup", {"item_id": "item-123"})
```

Assert the tool list, an authorized result (`result.isError` false, text parses to the record), and `intent_not_allowed` for an ungranted tool.
- [ ] **Step 2: Run — expect pass after wiring the callbacks to `McpServer`.**
- [ ] **Step 3: Suite green.**

### Task 8: Runnable examples

**Files:**
- Create: `sdk/python/examples/provider_fastapi/{server.py,README.md}`
- Create: `sdk/python/examples/agent_mcp/{server.py,demo.py,README.md}`

- [ ] **Step 1: FastAPI provider** builds a demo runtime (manifest, grant, schemas, hosts), mounts `manifest_router` + `provider_router`, adds a `POST /ccp/confirm` route for the demo's trusted UI, and runs uvicorn on `PORT` (default 8788). Print a ready-to-run `curl` at startup.
- [ ] **Step 2: MCP stdio server** wires `McpServer` into `mcp.server.lowlevel.Server` with `stdio_server()`; all diagnostics go to stderr. The demo `confirm` prints the permission card and approves, with a loud comment and README warning.
- [ ] **Step 3: MCP demo** connects `mcp.client.Client(server)` to the same server in memory, lists the tool, calls it, and shows the `intent_not_allowed` refusal.
- [ ] **Step 4: Run both demos** and capture the output.
- [ ] **Step 5: READMEs** cover run commands, the trust boundary, and the Node/TS counterpart.

### Task 9: Package surface and docs

**Files:**
- Modify: `sdk/python/pyproject.toml`
- Modify: `sdk/python/ccp/__init__.py`
- Modify: `sdk/python/README.md`

- [ ] **Step 1: Extras.**

```toml
[project.optional-dependencies]
fastapi = ["fastapi>=0.110"]
mcp = ["mcp>=2"]
dev = ["fastapi>=0.110", "httpx>=0.27", "mcp>=2"]
```

- [ ] **Step 2: Export** `Requester`, `Agent`, `attenuates`, `permission_card`, `PermissionCard`, `verify_manifest`, `verify_signal`, plus the build/sign helpers. Do not export the adapters.
- [ ] **Step 3: README** adds role quickstarts and adapter sections, and states the optional extras.
- [ ] **Step 4: `python -c "import ccp"` must not import fastapi or mcp** (verify with `sys.modules`).

### Task 10: Full gate

- [ ] `/usr/bin/python3 -m unittest discover -s tests` (20 existing + all new, including the MCP round trip)
- [ ] `python -m compileall -q ccp`
- [ ] FastAPI example: start it, POST an authorized signal, confirm, GET the manifest
- [ ] MCP demo: run `python examples/agent_mcp/demo.py`
- [ ] Re-run the vector suite in `test-vectors/` if any canonical/crypto file was touched (none should be)

## Self-review

- Spec coverage: §10.3 decision delegated to the runtime; §10.4 codes preserved in HTTP bodies and MCP results; §11.4 card shared with the host; §15.2 key binding checked at MCP construction; §15.3 no auto-approval and untrusted provider text/results.
- No placeholders: each task names files, signatures, commands, and expected outcomes.
- Naming consistency: `sign_manifest`, `sign_signal`, `permission_card`, `McpServer`, `call_tool`, `structured_content`, `is_error`.
