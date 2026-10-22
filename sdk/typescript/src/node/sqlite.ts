/**
 * Node-only durable stores backed by the built-in `node:sqlite` module.
 *
 * This module is deliberately outside the browser-safe core: `src/index.ts`
 * never imports it. Reach it through the `ccp-core/node` subpath. It needs a
 * Node build that provides `node:sqlite` (Node 22.5+; available without a
 * flag in current Node 24 releases, where it is still marked experimental).
 *
 * The operations the runtime relies on for correctness -- replay insertion,
 * limit reservation, and pending removal -- run as single statements or
 * inside `BEGIN IMMEDIATE` transactions, so they stay atomic across
 * processes sharing the database file.
 */

import type {
  DatabaseSync as DatabaseSyncInstance,
  DatabaseSyncConstructor,
} from "node:sqlite";

type DatabaseSync = DatabaseSyncInstance;

// Vite's bundled builtin list predates `node:sqlite`, and it rewrites the
// `node:` specifier into a package lookup. `process.getBuiltinModule` avoids a
// module specifier entirely (Node 22.3+).
const { DatabaseSync } = (
  process as unknown as {
    getBuiltinModule(id: string): unknown;
  }
).getBuiltinModule("node:sqlite") as {
  DatabaseSync: DatabaseSyncConstructor;
};

import type { VerifiedManifest } from "../consumer.js";
import { parseStrict } from "../parse.js";
import type {
  AuditStore,
  Grant,
  GrantStore,
  LimitStore,
  ManifestStore,
  PendingRequest,
  PendingStore,
  ReplayStore,
  RuntimeStores,
} from "../stores.js";
import { utcnow } from "../time.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS ccp_grants (
  id              TEXT PRIMARY KEY,
  requester_key   TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  state           TEXT NOT NULL,
  data            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS ccp_grants_lookup
  ON ccp_grants (requester_key, manifest_digest);

CREATE TABLE IF NOT EXISTS ccp_manifests (
  digest      TEXT PRIMARY KEY,
  document    TEXT NOT NULL,
  provider_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ccp_replay (
  request_id TEXT PRIMARY KEY,
  seen_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ccp_limits (
  grant_id TEXT NOT NULL,
  name     TEXT NOT NULL,
  value    INTEGER NOT NULL CHECK (value >= 0),
  PRIMARY KEY (grant_id, name)
);

CREATE TABLE IF NOT EXISTS ccp_pending (
  id         TEXT PRIMARY KEY,
  payload    TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ccp_audit (
  id    INTEGER PRIMARY KEY AUTOINCREMENT,
  at    TEXT NOT NULL,
  event TEXT NOT NULL
);
`;

function changesOf(result: { changes: number | bigint }): number {
  return Number(result.changes);
}

// The strict parser represents integers as BigInt, which JSON.stringify
// cannot serialize. Tag and restore them so pending signals and manifests
// survive a round trip without losing precision.
const BIGINT_TAG = "__ccp_bigint__";

function encodeJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? { [BIGINT_TAG]: item.toString() } : item
  );
}

function decodeJson(text: string): any {
  return JSON.parse(text, (_key, item) => {
    if (
      item !== null &&
      typeof item === "object" &&
      Object.keys(item).length === 1 &&
      typeof item[BIGINT_TAG] === "string"
    ) {
      return BigInt(item[BIGINT_TAG]);
    }
    return item;
  });
}

/** Local grants (§9.1). Revocation is visible to the next lookup. */
export class SqliteGrantStore implements GrantStore {
  constructor(private readonly db: DatabaseSync) {}

  add(grant: Grant): Grant {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO ccp_grants " +
          "(id, requester_key, manifest_digest, state, data) " +
          "VALUES (?, ?, ?, ?, ?)"
      )
      .run(
        grant.id,
        grant.requester_key,
        grant.manifest_digest,
        grant.state ?? "active",
        encodeJson(grant)
      );
    return grant;
  }

  get(id: string): Grant | undefined {
    const row = this.db
      .prepare("SELECT data FROM ccp_grants WHERE id = ?")
      .get(id) as { data: string } | undefined;
    return row ? (decodeJson(row.data) as Grant) : undefined;
  }

  find(requesterKey: string, manifestDigest: string): Grant | undefined {
    const row = this.db
      .prepare(
        "SELECT data FROM ccp_grants " +
          "WHERE requester_key = ? AND manifest_digest = ? LIMIT 1"
      )
      .get(requesterKey, manifestDigest) as { data: string } | undefined;
    return row ? (decodeJson(row.data) as Grant) : undefined;
  }

  remove(id: string): Grant | undefined {
    const existing = this.get(id);
    if (existing === undefined) return undefined;
    this.db.prepare("DELETE FROM ccp_grants WHERE id = ?").run(id);
    return existing;
  }

  all(): Grant[] {
    const rows = this.db
      .prepare("SELECT data FROM ccp_grants")
      .all() as { data: string }[];
    return rows.map((row) => decodeJson(row.data) as Grant);
  }
}

/** Verified manifests keyed by digest. Immutable and synchronous. */
export class SqliteManifestStore implements ManifestStore {
  constructor(private readonly db: DatabaseSync) {}

  add(manifest: VerifiedManifest): VerifiedManifest {
    this.db
      .prepare(
        "INSERT OR REPLACE INTO ccp_manifests " +
          "(digest, document, provider_id) VALUES (?, ?, ?)"
      )
      .run(manifest.digest, manifest.document, manifest.providerId);
    return manifest;
  }

  get(digest: string): VerifiedManifest | undefined {
    const row = this.db
      .prepare(
        "SELECT document, provider_id FROM ccp_manifests WHERE digest = ?"
      )
      .get(digest) as
      | { document: string; provider_id: string }
      | undefined;
    if (!row) return undefined;
    // Re-parse the canonical wire: the parser restores the BigInt integers
    // that JSON.stringify cannot represent.
    return {
      document: row.document,
      manifest: parseStrict(row.document),
      digest,
      providerId: row.provider_id,
    };
  }
}

/** Replay protection keyed on `request_id` (§10.3 step 8). */
export class SqliteReplayStore implements ReplayStore {
  constructor(private readonly db: DatabaseSync) {}

  has(id: string): boolean {
    return (
      this.db
        .prepare("SELECT 1 FROM ccp_replay WHERE request_id = ?")
        .get(id) !== undefined
    );
  }

  markIfNew(id: string): boolean {
    const result = this.db
      .prepare(
        "INSERT OR IGNORE INTO ccp_replay (request_id, seen_at) VALUES (?, ?)"
      )
      .run(id, utcnow());
    return changesOf(result) === 1;
  }

  /** Delete rows seen before an RFC 3339 timestamp to bound the table. */
  expire(before: string): number {
    const result = this.db
      .prepare("DELETE FROM ccp_replay WHERE seen_at < ?")
      .run(before);
    return changesOf(result);
  }
}

/** Per-grant cumulative counters with atomic reservation (§9.2). */
export class SqliteLimitStore implements LimitStore {
  constructor(private readonly db: DatabaseSync) {}

  tryReserve(grantId: string, limits: Record<string, number>): boolean {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const [name, maximum] of Object.entries(limits)) {
        const row = this.db
          .prepare(
            "SELECT value FROM ccp_limits WHERE grant_id = ? AND name = ?"
          )
          .get(grantId, name) as { value: number | bigint } | undefined;
        const current = row ? Number(row.value) : 0;
        if (current + 1 > maximum) {
          this.db.exec("COMMIT");
          return false;
        }
      }
      for (const name of Object.keys(limits)) {
        this.db
          .prepare(
            "INSERT INTO ccp_limits (grant_id, name, value) " +
              "VALUES (?, ?, 1) " +
              "ON CONFLICT (grant_id, name) DO UPDATE SET value = value + 1"
          )
          .run(grantId, name);
      }
      this.db.exec("COMMIT");
      return true;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  release(grantId: string, limits: Record<string, number>): void {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      for (const name of Object.keys(limits)) {
        this.db
          .prepare(
            "UPDATE ccp_limits SET value = " +
              "CASE WHEN value > 0 THEN value - 1 ELSE 0 END " +
              "WHERE grant_id = ? AND name = ?"
          )
          .run(grantId, name);
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  counters(grantId: string): Record<string, number> {
    const rows = this.db
      .prepare("SELECT name, value FROM ccp_limits WHERE grant_id = ?")
      .all(grantId) as { name: string; value: number | bigint }[];
    const result: Record<string, number> = {};
    for (const row of rows) result[row.name] = Number(row.value);
    return result;
  }
}

/** Pending confirmations. `take` resolves at most once, atomically. */
export class SqlitePendingStore implements PendingStore {
  constructor(private readonly db: DatabaseSync) {}

  put(request: PendingRequest): void {
    const payload = encodeJson({
      signal: request.signal,
      grant: request.grant,
      intentSpec: request.intentSpec,
      state: request.state,
    });
    this.db
      .prepare(
        "INSERT OR REPLACE INTO ccp_pending (id, payload, created_at) " +
          "VALUES (?, ?, ?)"
      )
      .run(request.id, payload, utcnow());
  }

  get(id: string): PendingRequest | undefined {
    const row = this.db
      .prepare("SELECT payload FROM ccp_pending WHERE id = ?")
      .get(id) as { payload: string } | undefined;
    return row ? this.hydrate(id, row.payload) : undefined;
  }

  take(id: string): PendingRequest | undefined {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db
        .prepare("SELECT payload FROM ccp_pending WHERE id = ?")
        .get(id) as { payload: string } | undefined;
      if (!row) {
        this.db.exec("COMMIT");
        return undefined;
      }
      this.db.prepare("DELETE FROM ccp_pending WHERE id = ?").run(id);
      this.db.exec("COMMIT");
      return this.hydrate(id, row.payload);
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  private hydrate(id: string, payload: string): PendingRequest {
    const data = decodeJson(payload);
    return {
      id,
      signal: data.signal,
      grant: data.grant as Grant,
      intentSpec: data.intentSpec,
      state: data.state ?? "awaiting_confirmation",
    };
  }
}

/** Append-only private audit log (§16, §26.1). */
export class SqliteAuditLog implements AuditStore {
  constructor(private readonly db: DatabaseSync) {}

  append(event: Record<string, unknown>): Record<string, unknown> {
    const at = utcnow();
    const record: Record<string, unknown> = { at, ...event };
    this.db
      .prepare("INSERT INTO ccp_audit (at, event) VALUES (?, ?)")
      .run(at, encodeJson(record));
    return record;
  }

  events(): Record<string, unknown>[] {
    const rows = this.db
      .prepare("SELECT event FROM ccp_audit ORDER BY id")
      .all() as { event: string }[];
    return rows.map((row) => decodeJson(row.event));
  }

  get length(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM ccp_audit")
      .get() as { n: number | bigint };
    return Number(row.n);
  }
}

/**
 * All six durable stores over one SQLite database.
 *
 * Pass `":memory:"` for tests or a file path for a durable, multi-process
 * deployment. Call `close()` when finished.
 */
export class SqliteStores implements RuntimeStores {
  readonly grants: SqliteGrantStore;
  readonly manifests: SqliteManifestStore;
  readonly replay: SqliteReplayStore;
  readonly limits: SqliteLimitStore;
  readonly pending: SqlitePendingStore;
  readonly audit: SqliteAuditLog;
  private readonly db: DatabaseSync;

  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout = 5000");
    if (path !== ":memory:") {
      this.db.exec("PRAGMA journal_mode = WAL");
    }
    this.db.exec(SCHEMA);
    this.grants = new SqliteGrantStore(this.db);
    this.manifests = new SqliteManifestStore(this.db);
    this.replay = new SqliteReplayStore(this.db);
    this.limits = new SqliteLimitStore(this.db);
    this.pending = new SqlitePendingStore(this.db);
    this.audit = new SqliteAuditLog(this.db);
  }

  close(): void {
    this.db.close();
  }
}
