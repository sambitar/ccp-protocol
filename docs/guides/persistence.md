# Persistence contract

`Runtime` depends on six stores. The in-memory defaults in
`sdk/typescript/src/stores.ts` implement the same contract; production
deployments replace them with durable ones.

Every method is `Awaitable<T>`, so an implementation may be synchronous (a
synchronous SQLite driver) or asynchronous (Postgres, a remote service).
The runtime always awaits, so a promise-returning store needs no extra
wiring.

| Interface | Methods | Semantics |
| --- | --- | --- |
| `GrantStore` | `add`, `get`, `find`, `remove`, `all` | `find(requesterKey, manifestDigest)` is the authorization lookup. Revocation must be visible to the next call. |
| `ManifestStore` | `add`, `get` | Synchronous by design. Verified manifests are immutable, so a durable store may load them at startup. |
| `ReplayStore` | `has`, `markIfNew` | `markIfNew` must insert atomically and return `false` on a duplicate. |
| `LimitStore` | `tryReserve`, `release`, `counters` | `tryReserve` reserves one unit against every limit or none, in one transaction. `counters` includes in-flight reservations. |
| `PendingStore` | `put`, `get`, `take` | `take` removes and returns atomically, so a confirmation resolves at most once. |
| `AuditStore` | `append` | Append-only. Do not expose update or delete to the runtime's database role. |

## Reference schema

Names are illustrative; only the constraints matter.

```sql
CREATE TABLE ccp_grants (
  id               TEXT PRIMARY KEY,
  requester_key    TEXT NOT NULL,
  contact_id       TEXT NOT NULL,
  manifest_digest  TEXT NOT NULL,
  manifest_version BIGINT NOT NULL,
  intents          JSONB NOT NULL,
  limits           JSONB NOT NULL,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  confirmation     JSONB NOT NULL,
  capabilities     JSONB NOT NULL,
  placement        JSONB NOT NULL,
  egress           JSONB NOT NULL,
  state            TEXT NOT NULL,
  state_reason     TEXT
);

CREATE INDEX ccp_grants_lookup
  ON ccp_grants (requester_key, manifest_digest);

CREATE TABLE ccp_replay (
  request_id TEXT PRIMARY KEY,
  seen_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE ccp_limits (
  grant_id TEXT NOT NULL,
  name     TEXT NOT NULL,
  value    BIGINT NOT NULL CHECK (value >= 0),
  PRIMARY KEY (grant_id, name)
);

CREATE TABLE ccp_pending (
  id         TEXT PRIMARY KEY,
  payload    JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE ccp_audit (
  id    BIGSERIAL PRIMARY KEY,
  at    TEXT NOT NULL,
  event JSONB NOT NULL
);
```

`manifest_version`, limits, and other canonical-profile integers arrive as
`bigint` when parsed from the wire. Store them as integers and convert to
`number` only after a safe-range check.

## Atomic operations

### Replay

```sql
INSERT INTO ccp_replay (request_id, seen_at)
VALUES ($1, now())
ON CONFLICT (request_id) DO NOTHING;
```

`markIfNew` returns true when one row was inserted. Expire rows after the
maximum signal lifetime so the table stays bounded; the runtime writes a
replay row only after a signal passes validation.

### Limits

All limits on a grant are reserved in one transaction:

```sql
BEGIN;

SELECT name, value
FROM ccp_limits
WHERE grant_id = $1 AND name = ANY($2::text[])
FOR UPDATE;

-- Abort and roll back if any value + 1 > ceiling.

INSERT INTO ccp_limits (grant_id, name, value)
VALUES ($1, $3, 1)
ON CONFLICT (grant_id, name)
DO UPDATE SET value = ccp_limits.value + 1;

COMMIT;
```

`release` decrements only after a failed or cancelled execution and must
never go below zero. `tryReserve` returning `true` means the reservation
is durable before work starts (§14, §26.1).

Window semantics (`calls_per_hour`, and reset boundaries) belong to the
store. The in-memory default is a monotonic counter for demos; a durable
store should key counters by window or reset them in the same transaction.

### Pending confirmations

```sql
DELETE FROM ccp_pending WHERE id = $1 RETURNING payload;
```

`take` is this statement. It is the only correct way to resolve a
confirmation in a multi-process deployment; `get` followed by `delete`
allows two approvers to execute twice. Add a TTL sweeper for abandoned
pending requests and release their limit reservations.

### Audit

Insert only:

```sql
INSERT INTO ccp_audit (at, event) VALUES ($1, $2);
```

Grant the runtime role `INSERT` without `UPDATE` or `DELETE`. Audit events
include rejected requests, so the table grows with denied traffic as well.

## Wiring

```ts
import { MemoryManifestStore, Runtime } from "ccp-core";

const runtime = new Runtime({
  grants: postgresGrants,
  manifests: new MemoryManifestStore([manifest]), // immutable
  replay: postgresReplay,
  limits: postgresLimits,
  pending: postgresPending,
  audit: postgresAudit,
  schemas,
  hosts,
});
```

Or spread a store bundle into the options:

```ts
const stores = new MemoryStores({ grants: [grant], manifests: [manifest] });
const runtime = new Runtime({ ...stores, schemas, hosts });
```

### Python (SQLite)

`ccp.stores_sqlite.SqliteStores` implements all six contracts on the
standard-library `sqlite3` module, with no extra dependency:

```python
from ccp import Runtime
from ccp.stores_sqlite import SqliteStores

stores = SqliteStores("ccp.db")  # or ":memory:" for tests
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
try:
    ...
finally:
    stores.close()
```

All six stores share one connection, so `:memory:` works for tests and a
file path works across processes. `tryReserve`, `markIfNew`, and `take` run
in `BEGIN IMMEDIATE` transactions. Call `replay.expire(timestamp)` to bound
the replay table after the maximum signal lifetime.

### TypeScript (Node, SQLite)

`ccp-core/node` exports `SqliteStores`, built on the built-in `node:sqlite`
module (no dependency). It is Node-only and never imported by the browser
core:

```ts
import { Runtime } from "ccp-core";
import { SqliteStores } from "ccp-core/node";

const stores = new SqliteStores("ccp.db"); // or ":memory:"
const runtime = new Runtime({ ...stores, schemas, hosts });
try {
  // ...
} finally {
  stores.close();
}
```

`node:sqlite` requires Node 22.5+ (available without a flag in Node 24, where
it is still marked experimental). The same atomic operations (`tryReserve`,
`markIfNew`, `take`) run in `BEGIN IMMEDIATE` transactions. Call
`replay.expire(timestamp)` to bound the replay table.

## Operational notes

- Memory stores are single-process only. Two instances behind a load
  balancer will each enforce their own replay set and limit counters.
- Grants are consumer-side records. The provider's database must never be
  able to read or modify them (§9.1).
- `ManifestStore` is synchronous because manifests are immutable
  configuration. Refreshing them is a startup or admin operation, not a
  per-request read.
- `PendingStore` payloads contain the full signal and grant. Encrypt at
  rest and apply the same access control as the grant table.
- A limit reservation is released on every refusal the runtime handles.
  If a store call itself throws mid-request, treat it as infrastructure
  failure: the adapter returns `outcome_unknown`, the replay id stays
  marked, and a reconciliation job should release stale reservations
  rather than retrying the side effect.
- The async-store contract is exercised in
  `sdk/typescript/test/runtime-async-stores.test.ts`, including
  at-most-once confirmation and atomic limit reservation under
  concurrency.
