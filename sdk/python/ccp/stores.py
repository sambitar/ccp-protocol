"""Thread-safe stores: grants, manifests, schemas, replay, limits."""

import threading


class GrantStore:
    """In-memory local grant store (§9.1)."""

    def __init__(self, grants=None):
        self._grants = {}
        self._lock = threading.RLock()
        for grant in grants or []:
            self.add(grant)

    def add(self, grant):
        with self._lock:
            self._grants[grant.id] = grant
        return grant

    def get(self, grant_id):
        with self._lock:
            return self._grants.get(grant_id)

    def find(self, requester_key, manifest_digest):
        with self._lock:
            for grant in self._grants.values():
                if (grant.requester_key == requester_key
                        and grant.manifest_digest == manifest_digest):
                    return grant
        return None

    def remove(self, grant_id):
        with self._lock:
            return self._grants.pop(grant_id, None)

    def all(self):
        with self._lock:
            return list(self._grants.values())


class ManifestStore:
    """Approved manifests, keyed by digest."""

    def __init__(self, manifests=None):
        self._by_digest = {}
        self._lock = threading.RLock()
        for manifest in manifests or []:
            self.add(manifest)

    def add(self, manifest):
        with self._lock:
            self._by_digest[manifest.digest] = manifest
        return manifest

    def get(self, digest):
        with self._lock:
            return self._by_digest.get(digest)


class SchemaRegistry:
    """Maps `schema:<...>` identifiers to their schemas (§25.3)."""

    def __init__(self, schemas=None):
        self._schemas = dict(schemas or {})
        self._lock = threading.RLock()

    def register(self, schema_id, schema):
        with self._lock:
            self._schemas[schema_id] = schema

    def get(self, schema_id):
        with self._lock:
            return self._schemas.get(schema_id)


class ReplayStore:
    """Durable replay protection keyed on `request_id` (§10.3 step 8)."""

    def __init__(self):
        self._seen = set()
        self._lock = threading.Lock()

    def seen(self, request_id):
        with self._lock:
            return request_id in self._seen

    def mark(self, request_id):
        with self._lock:
            self._seen.add(request_id)

    def mark_if_new(self, request_id):
        """Atomically check-and-mark; returns False if already seen."""
        with self._lock:
            if request_id in self._seen:
                return False
            self._seen.add(request_id)
            return True

    def snapshot(self):
        with self._lock:
            return set(self._seen)


class LimitTracker:
    """Per-grant cumulative counters with atomic reservation (§9.2)."""

    def __init__(self):
        self._counters = {}
        self._lock = threading.RLock()

    def try_reserve(self, grant_id, limits):
        """Atomically reserve one unit against every limit, or none."""
        with self._lock:
            counters = self._counters.setdefault(grant_id, {})
            for name, maximum in limits.items():
                if counters.get(name, 0) + 1 > maximum:
                    return False
            for name in limits:
                counters[name] = counters.get(name, 0) + 1
            return True

    def release(self, grant_id, limits):
        with self._lock:
            counters = self._counters.setdefault(grant_id, {})
            for name in limits:
                counters[name] = max(0, counters.get(name, 0) - 1)

    def commit(self, grant_id, limits):
        """A reservation becomes permanent; no counter change is needed."""
        return None

    def counters(self, grant_id):
        with self._lock:
            return dict(self._counters.get(grant_id, {}))


class Pending:
    """A confirmation awaiting a trusted decision (§9.5)."""

    def __init__(self, pending_id, signal, grant, intent_spec,
                 state="awaiting_confirmation"):
        self.pending_id = pending_id
        self.signal = signal
        self.grant = grant
        self.intent_spec = intent_spec
        self.state = state


class PendingStore:
    """In-memory pending confirmations; ``take`` resolves at most once."""

    def __init__(self):
        self._pending = {}
        self._lock = threading.RLock()

    def put(self, pending):
        with self._lock:
            self._pending[pending.pending_id] = pending

    def get(self, pending_id):
        with self._lock:
            return self._pending.get(pending_id)

    def take(self, pending_id):
        with self._lock:
            return self._pending.pop(pending_id, None)
