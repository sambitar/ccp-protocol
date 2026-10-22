//! Durable SQLite stores for the runtime (`sqlite` feature).
//!
//! All six stores share one connection held behind a mutex. `:memory:` works
//! for tests and a file path works across process restarts. `try_reserve`,
//! `mark_if_new`, and `take` run inside `BEGIN IMMEDIATE` transactions.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ccp_kernel::{parse_strict, serialize, Value};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::consumer::verify_manifest;
use crate::model::{Grant, PendingRequest, VerifiedManifest};
use crate::stores::{AuditStore, GrantStore, LimitStore, ManifestStore, PendingStore, ReplayStore};
use crate::time::utcnow;
use crate::util::{as_u64, string_list, uint};

const SCHEMA: &str = "
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
";

const GRANT_COLUMNS: &str = "id, requester_key, contact_id, manifest_digest, \
manifest_version, intents, limits, created_at, expires_at, confirmation, \
capabilities, placement, egress, state, state_reason";

/// All six durable stores over one SQLite database.
pub struct SqliteStores {
    pub grants: SqliteGrantStore,
    pub manifests: SqliteManifestStore,
    pub replay: SqliteReplayStore,
    pub limits: SqliteLimitStore,
    pub pending: SqlitePendingStore,
    pub audit: SqliteAuditLog,
    connection: Arc<Mutex<Connection>>,
}

impl SqliteStores {
    /// Open a database at `path` (`:memory:` for an in-process test database).
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path = path.as_ref();
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_millis(5_000))?;
        if path.to_string_lossy() != ":memory:" {
            connection.pragma_update(None, "journal_mode", "WAL")?;
        }
        connection.execute_batch(SCHEMA)?;
        let connection = Arc::new(Mutex::new(connection));
        Ok(Self {
            grants: SqliteGrantStore::new(connection.clone()),
            manifests: SqliteManifestStore::new(connection.clone()),
            replay: SqliteReplayStore::new(connection.clone()),
            limits: SqliteLimitStore::new(connection.clone()),
            pending: SqlitePendingStore::new(connection.clone()),
            audit: SqliteAuditLog::new(connection.clone()),
            connection,
        })
    }

    pub fn in_memory() -> rusqlite::Result<Self> {
        Self::open(":memory:")
    }

    /// Close the underlying connection. Every store clone must also be
    /// dropped before SQLite releases the file handle.
    pub fn close(self) {
        let Self { connection, .. } = self;
        drop(connection);
    }
}

fn shared(connection: &Arc<Mutex<Connection>>) -> Arc<Mutex<Connection>> {
    connection.clone()
}

fn transaction<T>(
    connection: &Arc<Mutex<Connection>>,
    function: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let mut guard = connection.lock().expect("sqlite lock");
    let transaction = guard.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = function(&transaction)?;
    transaction.commit()?;
    Ok(result)
}

// -- grants -------------------------------------------------------------

#[derive(Clone)]
pub struct SqliteGrantStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteGrantStore {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }
}

impl GrantStore for SqliteGrantStore {
    fn add(&mut self, grant: Grant) {
        let guard = self.connection.lock().expect("sqlite lock");
        let values = grant_params(&grant).expect("grant values");
        guard
            .execute(
                &format!(
                    "INSERT OR REPLACE INTO ccp_grants ({GRANT_COLUMNS}) VALUES \
                     (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
                ),
                rusqlite::params_from_iter(values.iter()),
            )
            .expect("insert grant");
    }

    fn get(&self, id: &str) -> Option<Grant> {
        let guard = self.connection.lock().expect("sqlite lock");
        guard
            .query_row(
                &format!("SELECT {GRANT_COLUMNS} FROM ccp_grants WHERE id = ?1"),
                params![id],
                grant_from_row,
            )
            .optional()
            .expect("select grant")
    }

    fn find(&self, requester_key: &str, manifest_digest: &str) -> Option<Grant> {
        let guard = self.connection.lock().expect("sqlite lock");
        guard
            .query_row(
                &format!(
                    "SELECT {GRANT_COLUMNS} FROM ccp_grants \
                     WHERE requester_key = ?1 AND manifest_digest = ?2 LIMIT 1"
                ),
                params![requester_key, manifest_digest],
                grant_from_row,
            )
            .optional()
            .expect("find grant")
    }

    fn remove(&mut self, id: &str) -> Option<Grant> {
        let connection = self.connection.clone();
        transaction(&connection, |tx| {
            let grant = tx
                .query_row(
                    &format!("SELECT {GRANT_COLUMNS} FROM ccp_grants WHERE id = ?1"),
                    params![id],
                    grant_from_row,
                )
                .optional()?;
            if grant.is_some() {
                tx.execute("DELETE FROM ccp_grants WHERE id = ?1", params![id])?;
            }
            Ok(grant)
        })
        .expect("remove grant")
    }

    fn all(&self) -> Vec<Grant> {
        let guard = self.connection.lock().expect("sqlite lock");
        let mut statement = guard
            .prepare(&format!("SELECT {GRANT_COLUMNS} FROM ccp_grants"))
            .expect("prepare grants");
        let rows = statement
            .query_map([], grant_from_row)
            .expect("query grants");
        rows.map(|row| row.expect("grant row")).collect()
    }
}

fn json_text(value: &Value) -> String {
    serialize(value).expect("canonical value")
}

fn grant_params(grant: &Grant) -> rusqlite::Result<Vec<rusqlite::types::Value>> {
    use rusqlite::types::Value as SqlValue;
    let limits = Value::Object(
        grant
            .limits
            .iter()
            .map(|(name, value)| (name.clone(), uint(*value)))
            .collect(),
    );
    let confirmation = Value::Object(
        grant
            .confirmation
            .iter()
            .map(|(name, policy)| (name.clone(), Value::Str(policy.clone())))
            .collect(),
    );
    Ok(vec![
        SqlValue::Text(grant.id.clone()),
        SqlValue::Text(grant.requester_key.clone()),
        SqlValue::Text(grant.contact_id.clone()),
        SqlValue::Text(grant.manifest_digest.clone()),
        SqlValue::Integer(i64::try_from(grant.manifest_version).unwrap_or(i64::MAX)),
        SqlValue::Text(json_text(&crate::util::string_array(&grant.intents))),
        SqlValue::Text(json_text(&limits)),
        SqlValue::Text(grant.created_at.clone()),
        SqlValue::Text(grant.expires_at.clone()),
        SqlValue::Text(json_text(&confirmation)),
        SqlValue::Text(json_text(&crate::util::string_array(&grant.capabilities))),
        SqlValue::Text(json_text(&crate::util::string_array(&grant.placement))),
        SqlValue::Text(json_text(&grant.egress)),
        SqlValue::Text(grant.state.clone()),
        match &grant.state_reason {
            Some(reason) => SqlValue::Text(reason.clone()),
            None => SqlValue::Null,
        },
    ])
}

fn grant_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Grant> {
    let intents: String = row.get(5)?;
    let limits: String = row.get(6)?;
    let confirmation: String = row.get(9)?;
    let capabilities: String = row.get(10)?;
    let placement: String = row.get(11)?;
    let egress: String = row.get(12)?;
    let manifest_version: i64 = row.get(4)?;
    Ok(Grant {
        id: row.get(0)?,
        requester_key: row.get(1)?,
        contact_id: row.get(2)?,
        manifest_digest: row.get(3)?,
        manifest_version: u64::try_from(manifest_version).unwrap_or(0),
        intents: json_strings(&intents),
        limits: json_limits(&limits),
        created_at: row.get(7)?,
        expires_at: row.get(8)?,
        confirmation: json_string_map(&confirmation),
        capabilities: json_strings(&capabilities),
        placement: json_strings(&placement),
        egress: parse_strict(&egress).unwrap_or_else(|_| Value::Object(vec![])),
        state: row.get(13)?,
        state_reason: row.get(14)?,
    })
}

fn json_strings(text: &str) -> Vec<String> {
    parse_strict(text)
        .ok()
        .as_ref()
        .and_then(string_list)
        .unwrap_or_default()
}

fn json_limits(text: &str) -> BTreeMap<String, u64> {
    let mut limits = BTreeMap::new();
    if let Ok(Value::Object(entries)) = parse_strict(text) {
        for (name, value) in entries {
            if let Some(value) = as_u64(&value) {
                limits.insert(name, value);
            }
        }
    }
    limits
}

fn json_string_map(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(Value::Object(entries)) = parse_strict(text) {
        for (name, value) in entries {
            if let Some(value) = value.as_str() {
                map.insert(name, value.to_string());
            }
        }
    }
    map
}

// -- manifests ----------------------------------------------------------

#[derive(Clone)]
pub struct SqliteManifestStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteManifestStore {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }
}

impl ManifestStore for SqliteManifestStore {
    fn add(&mut self, manifest: VerifiedManifest) {
        let guard = self.connection.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT OR REPLACE INTO ccp_manifests (digest, document) VALUES (?1, ?2)",
                params![manifest.digest, manifest.document],
            )
            .expect("insert manifest");
    }

    fn get(&self, digest: &str) -> Option<VerifiedManifest> {
        let guard = self.connection.lock().expect("sqlite lock");
        let document: Option<String> = guard
            .query_row(
                "SELECT document FROM ccp_manifests WHERE digest = ?1",
                params![digest],
                |row| row.get(0),
            )
            .optional()
            .expect("select manifest");
        document.and_then(|document| verify_manifest(&document, None).ok())
    }
}

// -- replay -------------------------------------------------------------

#[derive(Clone)]
pub struct SqliteReplayStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteReplayStore {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }

    /// Delete replay rows older than an RFC 3339 timestamp.
    pub fn expire(&mut self, before: &str) -> rusqlite::Result<usize> {
        let guard = self.connection.lock().expect("sqlite lock");
        guard.execute("DELETE FROM ccp_replay WHERE seen_at < ?1", params![before])
    }
}

impl ReplayStore for SqliteReplayStore {
    fn has(&self, id: &str) -> bool {
        let guard = self.connection.lock().expect("sqlite lock");
        let seen: Option<i64> = guard
            .query_row(
                "SELECT 1 FROM ccp_replay WHERE request_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .expect("select replay");
        seen.is_some()
    }

    fn mark_if_new(&mut self, id: &str) -> bool {
        let guard = self.connection.lock().expect("sqlite lock");
        let changed = guard
            .execute(
                "INSERT OR IGNORE INTO ccp_replay (request_id, seen_at) VALUES (?1, ?2)",
                params![id, utcnow()],
            )
            .expect("insert replay");
        changed == 1
    }
}

// -- limits -------------------------------------------------------------

#[derive(Clone)]
pub struct SqliteLimitStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteLimitStore {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }
}

impl LimitStore for SqliteLimitStore {
    fn try_reserve(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>) -> bool {
        let connection = self.connection.clone();
        transaction(&connection, |tx| {
            for (name, maximum) in limits {
                let current: i64 = tx
                    .query_row(
                        "SELECT value FROM ccp_limits WHERE grant_id = ?1 AND name = ?2",
                        params![grant_id, name],
                        |row| row.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                if u64::try_from(current).unwrap_or(0).saturating_add(1) > *maximum {
                    return Ok(false);
                }
            }
            for name in limits.keys() {
                tx.execute(
                    "INSERT INTO ccp_limits (grant_id, name, value) VALUES (?1, ?2, 1) \
                     ON CONFLICT (grant_id, name) DO UPDATE SET value = value + 1",
                    params![grant_id, name],
                )?;
            }
            Ok(true)
        })
        .expect("reserve limits")
    }

    fn release(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>) {
        let connection = self.connection.clone();
        transaction(&connection, |tx| {
            for name in limits.keys() {
                tx.execute(
                    "UPDATE ccp_limits SET value = CASE WHEN value > 0 THEN value - 1 ELSE 0 END \
                     WHERE grant_id = ?1 AND name = ?2",
                    params![grant_id, name],
                )?;
            }
            Ok(())
        })
        .expect("release limits");
    }

    fn counters(&self, grant_id: &str) -> BTreeMap<String, u64> {
        let guard = self.connection.lock().expect("sqlite lock");
        let mut statement = guard
            .prepare("SELECT name, value FROM ccp_limits WHERE grant_id = ?1")
            .expect("prepare limits");
        let rows = statement
            .query_map(params![grant_id], |row| {
                let name: String = row.get(0)?;
                let value: i64 = row.get(1)?;
                Ok((name, u64::try_from(value).unwrap_or(0)))
            })
            .expect("query limits");
        rows.map(|row| row.expect("limit row")).collect()
    }
}

// -- pending ------------------------------------------------------------

#[derive(Clone)]
pub struct SqlitePendingStore {
    connection: Arc<Mutex<Connection>>,
}

impl SqlitePendingStore {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }
}

impl PendingStore for SqlitePendingStore {
    fn put(&mut self, request: PendingRequest) {
        let payload = pending_payload(&request);
        let guard = self.connection.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT OR REPLACE INTO ccp_pending (id, payload, created_at) \
                 VALUES (?1, ?2, ?3)",
                params![request.id, json_text(&payload), utcnow()],
            )
            .expect("insert pending");
    }

    fn get(&self, id: &str) -> Option<PendingRequest> {
        let guard = self.connection.lock().expect("sqlite lock");
        let payload: Option<String> = guard
            .query_row(
                "SELECT payload FROM ccp_pending WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .expect("select pending");
        payload.and_then(|payload| pending_from_payload(&payload, id))
    }

    fn take(&mut self, id: &str) -> Option<PendingRequest> {
        let connection = self.connection.clone();
        transaction(&connection, |tx| {
            let payload: Option<String> = tx
                .query_row(
                    "SELECT payload FROM ccp_pending WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            if payload.is_some() {
                tx.execute("DELETE FROM ccp_pending WHERE id = ?1", params![id])?;
            }
            Ok(payload.and_then(|payload| pending_from_payload(&payload, id)))
        })
        .expect("take pending")
    }
}

fn pending_payload(request: &PendingRequest) -> Value {
    crate::util::object(vec![
        ("signal", request.signal.clone()),
        ("grant", request.grant.to_value()),
        ("intent_spec", request.intent_spec.clone()),
        ("state", Value::Str(request.state.clone())),
    ])
}

fn pending_from_payload(text: &str, id: &str) -> Option<PendingRequest> {
    let payload = parse_strict(text).ok()?;
    let signal = payload.get("signal")?.clone();
    let grant = grant_from_value(payload.get("grant")?)?;
    let intent_spec = payload.get("intent_spec")?.clone();
    let state = payload
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("awaiting_confirmation")
        .to_string();
    Some(PendingRequest {
        id: id.to_string(),
        signal,
        grant,
        intent_spec,
        state,
    })
}

fn grant_from_value(value: &Value) -> Option<Grant> {
    Some(Grant {
        id: value.get("id")?.as_str()?.to_string(),
        requester_key: value.get("requester_key")?.as_str()?.to_string(),
        contact_id: value.get("contact_id")?.as_str()?.to_string(),
        manifest_digest: value.get("manifest_digest")?.as_str()?.to_string(),
        manifest_version: as_u64(value.get("manifest_version")?)?,
        intents: string_list(value.get("intents")?)?,
        limits: {
            let mut limits = BTreeMap::new();
            if let Value::Object(entries) = value.get("limits")? {
                for (name, value) in entries {
                    limits.insert(name.clone(), as_u64(value)?);
                }
            }
            limits
        },
        created_at: value.get("created_at")?.as_str()?.to_string(),
        expires_at: value.get("expires_at")?.as_str()?.to_string(),
        confirmation: {
            let mut confirmation = BTreeMap::new();
            if let Value::Object(entries) = value.get("confirmation")? {
                for (name, value) in entries {
                    confirmation.insert(name.clone(), value.as_str()?.to_string());
                }
            }
            confirmation
        },
        capabilities: string_list(value.get("capabilities")?)?,
        placement: string_list(value.get("placement")?)?,
        egress: value.get("egress")?.clone(),
        state: value.get("state")?.as_str()?.to_string(),
        state_reason: value
            .get("state_reason")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

// -- audit --------------------------------------------------------------

#[derive(Clone)]
pub struct SqliteAuditLog {
    connection: Arc<Mutex<Connection>>,
}

impl SqliteAuditLog {
    fn new(connection: Arc<Mutex<Connection>>) -> Self {
        Self {
            connection: shared(&connection),
        }
    }

    /// All audit events in insertion order.
    pub fn events(&self) -> Vec<Value> {
        let guard = self.connection.lock().expect("sqlite lock");
        let mut statement = guard
            .prepare("SELECT event FROM ccp_audit ORDER BY id")
            .expect("prepare audit");
        let rows = statement
            .query_map([], |row| {
                let event: String = row.get(0)?;
                Ok(event)
            })
            .expect("query audit");
        rows.filter_map(|row| row.ok().and_then(|text| parse_strict(&text).ok()))
            .collect()
    }

    pub fn len(&self) -> usize {
        let guard = self.connection.lock().expect("sqlite lock");
        let count: i64 = guard
            .query_row("SELECT COUNT(*) FROM ccp_audit", [], |row| row.get(0))
            .expect("count audit");
        usize::try_from(count).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditStore for SqliteAuditLog {
    fn append(&mut self, event: Value) {
        let at = event
            .get("at")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(utcnow);
        let guard = self.connection.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT INTO ccp_audit (at, event) VALUES (?1, ?2)",
                params![at, json_text(&event)],
            )
            .expect("insert audit");
    }
}
