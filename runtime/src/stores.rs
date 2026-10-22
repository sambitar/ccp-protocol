//! The six persistence contracts and their in-memory defaults.
//!
//! The runtime is synchronous and takes `&mut self` for mutations, so callers
//! own concurrency (a single runtime per thread, or an external lock). A
//! durable store must treat `GrantStore::add` as an upsert and must make
//! `ReplayStore::mark_if_new`, `LimitStore::try_reserve`, and
//! `PendingStore::take` atomic.

use std::collections::{BTreeMap, HashMap};

use ccp_kernel::Value;

use crate::model::{Grant, PendingRequest, VerifiedManifest};

/// Authorization records. Revocation must be visible to the next `find`.
pub trait GrantStore: Send {
    fn add(&mut self, grant: Grant);
    fn get(&self, id: &str) -> Option<Grant>;
    fn find(&self, requester_key: &str, manifest_digest: &str) -> Option<Grant>;
    fn remove(&mut self, id: &str) -> Option<Grant>;
    fn all(&self) -> Vec<Grant>;
}

/// Verified manifests, keyed by digest. They are immutable.
pub trait ManifestStore: Send {
    fn add(&mut self, manifest: VerifiedManifest);
    fn get(&self, digest: &str) -> Option<VerifiedManifest>;
}

/// Replay protection. `mark_if_new` inserts atomically and returns false when
/// the id already exists.
pub trait ReplayStore: Send {
    fn has(&self, id: &str) -> bool;
    fn mark_if_new(&mut self, id: &str) -> bool;
}

/// Cumulative limit counters with all-or-none reservation.
pub trait LimitStore: Send {
    fn try_reserve(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>) -> bool;
    fn release(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>);
    fn counters(&self, grant_id: &str) -> BTreeMap<String, u64>;
}

/// Pending confirmations. `take` removes and returns atomically.
pub trait PendingStore: Send {
    fn put(&mut self, request: PendingRequest);
    fn get(&self, id: &str) -> Option<PendingRequest>;
    fn take(&mut self, id: &str) -> Option<PendingRequest>;
}

/// Append-only audit records.
pub trait AuditStore: Send {
    fn append(&mut self, event: Value);
}

/// Default in-process stores. State is lost on restart.
#[derive(Default)]
pub struct MemoryGrantStore {
    grants: Vec<Grant>,
}

impl MemoryGrantStore {
    pub fn new(grants: Vec<Grant>) -> Self {
        let mut store = Self::default();
        for grant in grants {
            store.add(grant);
        }
        store
    }
}

impl GrantStore for MemoryGrantStore {
    fn add(&mut self, grant: Grant) {
        match self.grants.iter_mut().find(|entry| entry.id == grant.id) {
            Some(entry) => *entry = grant,
            None => self.grants.push(grant),
        }
    }

    fn get(&self, id: &str) -> Option<Grant> {
        self.grants.iter().find(|grant| grant.id == id).cloned()
    }

    fn find(&self, requester_key: &str, manifest_digest: &str) -> Option<Grant> {
        self.grants
            .iter()
            .find(|grant| {
                grant.requester_key == requester_key && grant.manifest_digest == manifest_digest
            })
            .cloned()
    }

    fn remove(&mut self, id: &str) -> Option<Grant> {
        let position = self.grants.iter().position(|grant| grant.id == id)?;
        Some(self.grants.remove(position))
    }

    fn all(&self) -> Vec<Grant> {
        self.grants.clone()
    }
}

#[derive(Default)]
pub struct MemoryManifestStore {
    manifests: HashMap<String, VerifiedManifest>,
}

impl MemoryManifestStore {
    pub fn new(manifests: Vec<VerifiedManifest>) -> Self {
        let mut store = Self::default();
        for manifest in manifests {
            store.add(manifest);
        }
        store
    }
}

impl ManifestStore for MemoryManifestStore {
    fn add(&mut self, manifest: VerifiedManifest) {
        self.manifests.insert(manifest.digest.clone(), manifest);
    }

    fn get(&self, digest: &str) -> Option<VerifiedManifest> {
        self.manifests.get(digest).cloned()
    }
}

#[derive(Default)]
pub struct MemoryReplayStore {
    seen: std::collections::HashSet<String>,
}

impl ReplayStore for MemoryReplayStore {
    fn has(&self, id: &str) -> bool {
        self.seen.contains(id)
    }

    fn mark_if_new(&mut self, id: &str) -> bool {
        self.seen.insert(id.to_string())
    }
}

#[derive(Default)]
pub struct MemoryLimitStore {
    counters: HashMap<String, BTreeMap<String, u64>>,
}

impl LimitStore for MemoryLimitStore {
    fn try_reserve(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>) -> bool {
        let current = self.counters.get(grant_id);
        for (name, maximum) in limits {
            let used = current
                .and_then(|entry| entry.get(name))
                .copied()
                .unwrap_or(0);
            if used.saturating_add(1) > *maximum {
                return false;
            }
        }
        let entry = self.counters.entry(grant_id.to_string()).or_default();
        for name in limits.keys() {
            *entry.entry(name.clone()).or_insert(0) += 1;
        }
        true
    }

    fn release(&mut self, grant_id: &str, limits: &BTreeMap<String, u64>) {
        let entry = self.counters.entry(grant_id.to_string()).or_default();
        for name in limits.keys() {
            let counter = entry.entry(name.clone()).or_insert(0);
            *counter = counter.saturating_sub(1);
        }
    }

    fn counters(&self, grant_id: &str) -> BTreeMap<String, u64> {
        self.counters.get(grant_id).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
pub struct MemoryPendingStore {
    pending: HashMap<String, PendingRequest>,
}

impl PendingStore for MemoryPendingStore {
    fn put(&mut self, request: PendingRequest) {
        self.pending.insert(request.id.clone(), request);
    }

    fn get(&self, id: &str) -> Option<PendingRequest> {
        self.pending.get(id).cloned()
    }

    fn take(&mut self, id: &str) -> Option<PendingRequest> {
        self.pending.remove(id)
    }
}

/// An append-only in-memory audit log.
#[derive(Default)]
pub struct MemoryAuditLog {
    events: Vec<Value>,
}

impl MemoryAuditLog {
    pub fn events(&self) -> Vec<Value> {
        self.events.clone()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl AuditStore for MemoryAuditLog {
    fn append(&mut self, event: Value) {
        self.events.push(event);
    }
}

/// A convenient bundle of the in-memory defaults.
pub struct MemoryStores {
    pub grants: MemoryGrantStore,
    pub manifests: MemoryManifestStore,
    pub replay: MemoryReplayStore,
    pub limits: MemoryLimitStore,
    pub pending: MemoryPendingStore,
    pub audit: MemoryAuditLog,
}

impl Default for MemoryStores {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStores {
    pub fn new() -> Self {
        Self {
            grants: MemoryGrantStore::default(),
            manifests: MemoryManifestStore::default(),
            replay: MemoryReplayStore::default(),
            limits: MemoryLimitStore::default(),
            pending: MemoryPendingStore::default(),
            audit: MemoryAuditLog::default(),
        }
    }

    pub fn with_records(grants: Vec<Grant>, manifests: Vec<VerifiedManifest>) -> Self {
        Self {
            grants: MemoryGrantStore::new(grants),
            manifests: MemoryManifestStore::new(manifests),
            replay: MemoryReplayStore::default(),
            limits: MemoryLimitStore::default(),
            pending: MemoryPendingStore::default(),
            audit: MemoryAuditLog::default(),
        }
    }
}
