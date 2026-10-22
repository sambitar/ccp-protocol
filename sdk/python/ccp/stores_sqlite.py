"""Durable SQLite stores for the CCP runtime.

Implements the six store contracts from ``docs/guides/persistence.md`` using
the Python standard-library ``sqlite3`` module, so no third-party driver is
required.

A single connection is shared by every store, which lets ``":memory:"`` work
for tests and a file path work across processes. The operations the runtime
relies on for correctness -- replay insertion, limit reservation, and pending
confirmation removal -- run as single statements or inside an explicit
``BEGIN IMMEDIATE`` transaction.
"""

import json
import threading

from .audit import utcnow
from .model import Grant, Manifest, Signal
from .stores import Pending

SCHEMA = """
CREATE TABLE IF NOT EXISTS ccp_grants (
  id               TEXT PRIMARY KEY,
  requester_key    TEXT NOT NULL,
  contact_id       TEXT NOT NULL,
  manifest_digest  TEXT NOT NULL,
  manifest_version INTEGER NOT NULL,
  intents          TEXT NOT NULL,
  limits           TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  confirmation     TEXT NOT NULL,
  capabilities     TEXT NOT NULL,
  placement        TEXT NOT NULL,
  egress           TEXT NOT NULL,
  state            TEXT NOT NULL,
  state_reason     TEXT
);

CREATE INDEX IF NOT EXISTS ccp_grants_lookup
  ON ccp_grants (requester_key, manifest_digest);

CREATE TABLE IF NOT EXISTS ccp_manifests (
  digest   TEXT PRIMARY KEY,
  document TEXT NOT NULL
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
"""

_GRANT_COLUMNS = (
    "id",
    "requester_key",
    "contact_id",
    "manifest_digest",
    "manifest_version",
    "intents",
    "limits",
    "created_at",
    "expires_at",
    "confirmation",
    "capabilities",
    "placement",
    "egress",
    "state",
    "state_reason",
)
_JSON_GRANT_FIELDS = frozenset({
    "intents",
    "limits",
    "confirmation",
    "capabilities",
    "placement",
    "egress",
})


def _dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _grant_params(grant):
    data = grant.to_dict()
    return tuple(
        _dumps(data[name]) if name in _JSON_GRANT_FIELDS else data[name]
        for name in _GRANT_COLUMNS
    )


def _grant_from_row(row):
    data = {
        name: (json.loads(value) if name in _JSON_GRANT_FIELDS else value)
        for name, value in zip(_GRANT_COLUMNS, row)
    }
    return Grant.from_dict(data)


def _pending_from_payload(payload, pending_id):
    data = json.loads(payload)
    return Pending(
        pending_id=pending_id,
        signal=Signal.parse(data["signal_document"]),
        grant=Grant.from_dict(data["grant"]),
        intent_spec=data["intent_spec"],
        state=data.get("state", "awaiting_confirmation"),
    )


class _Store:
    """Shared connection, lock, and transaction helper."""

    def __init__(self, connection, lock):
        self._conn = connection
        self._lock = lock

    def _transaction(self, function):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                result = function()
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
            return result


class SqliteGrantStore(_Store):
    """Local grants (§9.1). Revocation is visible to the next lookup."""

    def __init__(self, connection, lock):
        super().__init__(connection, lock)
        self._columns = ", ".join(_GRANT_COLUMNS)
        self._placeholders = ", ".join("?" for _ in _GRANT_COLUMNS)

    def add(self, grant):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ccp_grants (%s) VALUES (%s)"
                % (self._columns, self._placeholders),
                _grant_params(grant),
            )
        return grant

    def get(self, grant_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT %s FROM ccp_grants WHERE id = ?" % self._columns,
                (grant_id,),
            ).fetchone()
        return _grant_from_row(row) if row is not None else None

    def find(self, requester_key, manifest_digest):
        with self._lock:
            row = self._conn.execute(
                "SELECT %s FROM ccp_grants "
                "WHERE requester_key = ? AND manifest_digest = ? LIMIT 1"
                % self._columns,
                (requester_key, manifest_digest),
            ).fetchone()
        return _grant_from_row(row) if row is not None else None

    def remove(self, grant_id):
        def run():
            row = self._conn.execute(
                "SELECT %s FROM ccp_grants WHERE id = ?" % self._columns,
                (grant_id,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute("DELETE FROM ccp_grants WHERE id = ?",
                               (grant_id,))
            return _grant_from_row(row)

        return self._transaction(run)

    def all(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT %s FROM ccp_grants" % self._columns
            ).fetchall()
        return [_grant_from_row(row) for row in rows]


class SqliteManifestStore(_Store):
    """Verified manifests keyed by digest. Immutable and synchronous."""

    def add(self, manifest):
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ccp_manifests (digest, document) "
                "VALUES (?, ?)",
                (manifest.digest, manifest.document),
            )
        return manifest

    def get(self, digest):
        with self._lock:
            row = self._conn.execute(
                "SELECT document FROM ccp_manifests WHERE digest = ?",
                (digest,),
            ).fetchone()
        return Manifest.parse(row[0]) if row is not None else None


class SqliteReplayStore(_Store):
    """Replay protection keyed on ``request_id`` (§10.3 step 8)."""

    def __init__(self, connection, lock):
        super().__init__(connection, lock)

    def seen(self, request_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM ccp_replay WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        return row is not None

    def mark(self, request_id):
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO ccp_replay (request_id, seen_at) "
                "VALUES (?, ?)",
                (request_id, utcnow()),
            )

    def mark_if_new(self, request_id):
        """Insert atomically; return False when the id already exists."""
        with self._lock:
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO ccp_replay (request_id, seen_at) "
                "VALUES (?, ?)",
                (request_id, utcnow()),
            )
            return cursor.rowcount == 1

    def snapshot(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT request_id FROM ccp_replay"
            ).fetchall()
        return {row[0] for row in rows}

    def expire(self, before):
        """Delete replay rows seen before an RFC 3339 timestamp."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM ccp_replay WHERE seen_at < ?", (before,)
            )
            return cursor.rowcount


class SqliteLimitTracker(_Store):
    """Per-grant cumulative counters with atomic reservation (§9.2)."""

    def __init__(self, connection, lock):
        super().__init__(connection, lock)

    def try_reserve(self, grant_id, limits):
        """Reserve one unit against every limit, or none, in one transaction."""

        def run():
            for name, maximum in limits.items():
                row = self._conn.execute(
                    "SELECT value FROM ccp_limits "
                    "WHERE grant_id = ? AND name = ?",
                    (grant_id, name),
                ).fetchone()
                current = row[0] if row is not None else 0
                if current + 1 > maximum:
                    return False
            for name in limits:
                self._conn.execute(
                    "INSERT INTO ccp_limits (grant_id, name, value) "
                    "VALUES (?, ?, 1) "
                    "ON CONFLICT (grant_id, name) "
                    "DO UPDATE SET value = value + 1",
                    (grant_id, name),
                )
            return True

        return self._transaction(run)

    def release(self, grant_id, limits):
        def run():
            for name in limits:
                self._conn.execute(
                    "UPDATE ccp_limits SET value = "
                    "CASE WHEN value > 0 THEN value - 1 ELSE 0 END "
                    "WHERE grant_id = ? AND name = ?",
                    (grant_id, name),
                )

        self._transaction(run)

    def commit(self, grant_id, limits):
        """A reservation becomes permanent; no counter change is needed."""
        return None

    def counters(self, grant_id):
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, value FROM ccp_limits WHERE grant_id = ?",
                (grant_id,),
            ).fetchall()
        return {name: value for name, value in rows}


class SqlitePendingStore(_Store):
    """Pending confirmations. ``take`` resolves at most once, atomically."""

    def __init__(self, connection, lock):
        super().__init__(connection, lock)

    def put(self, pending):
        payload = _dumps({
            "signal_document": pending.signal.document,
            "grant": pending.grant.to_dict(),
            "intent_spec": pending.intent_spec,
            "state": pending.state,
        })
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO ccp_pending (id, payload, created_at) "
                "VALUES (?, ?, ?)",
                (pending.pending_id, payload, utcnow()),
            )

    def get(self, pending_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM ccp_pending WHERE id = ?",
                (pending_id,),
            ).fetchone()
        return _pending_from_payload(row[0], pending_id) if row else None

    def take(self, pending_id):
        def run():
            row = self._conn.execute(
                "SELECT payload FROM ccp_pending WHERE id = ?",
                (pending_id,),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute("DELETE FROM ccp_pending WHERE id = ?",
                               (pending_id,))
            return _pending_from_payload(row[0], pending_id)

        return self._transaction(run)


class SqliteAuditLog(_Store):
    """Append-only private audit log (§16, §26.1)."""

    def __init__(self, connection, lock):
        super().__init__(connection, lock)

    def append(self, event):
        record = dict(event)
        record.setdefault("at", utcnow())
        with self._lock:
            self._conn.execute(
                "INSERT INTO ccp_audit (at, event) VALUES (?, ?)",
                (record["at"], _dumps(record)),
            )
        return record

    def events(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT event FROM ccp_audit ORDER BY id"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def __len__(self):
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM ccp_audit"
            ).fetchone()[0]


class SqliteStores:
    """All six durable stores over one SQLite database.

    Pass ``":memory:"`` for tests or a file path for a durable, multi-process
    deployment. Close the bundle (or use it as a context manager) to release
    the connection.
    """

    def __init__(self, path=":memory:"):
        import sqlite3

        self.path = str(path)
        self._connection = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self._connection.execute("PRAGMA busy_timeout = 5000")
        if self.path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.executescript(SCHEMA)
        self._lock = threading.RLock()

        self.grants = SqliteGrantStore(self._connection, self._lock)
        self.manifests = SqliteManifestStore(self._connection, self._lock)
        self.replay = SqliteReplayStore(self._connection, self._lock)
        self.limits = SqliteLimitTracker(self._connection, self._lock)
        self.pending = SqlitePendingStore(self._connection, self._lock)
        self.audit = SqliteAuditLog(self._connection, self._lock)

    def close(self):
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
