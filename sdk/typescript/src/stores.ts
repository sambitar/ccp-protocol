import type { VerifiedManifest } from "./consumer.js";
import type { JsonValue } from "./json.js";
import { utcnow } from "./time.js";

/**
 * Persistence contract for the runtime.
 *
 * The runtime awaits every operation, so an implementation may be synchronous
 * (the in-memory defaults, or a synchronous SQLite driver) or asynchronous
 * (Postgres, a remote store, or a file-backed store). Methods that mutate
 * authorization state must be atomic: see `LimitStore.tryReserve`,
 * `ReplayStore.markIfNew`, and `PendingStore.take`.
 */
export type Awaitable<T> = T | Promise<T>;

export type GrantState =
  | "active"
  | "paused"
  | "suspended"
  | "revoked"
  | "expired";

export interface Grant {
  id: string;
  requester_key: string;
  contact_id: string;
  manifest_digest: string;
  manifest_version: number;
  intents: string[];
  limits: Record<string, number>;
  created_at: string;
  expires_at: string;
  confirmation: Record<string, string>;
  capabilities: string[];
  placement: string[];
  egress: { [key: string]: JsonValue };
  state: string;
  state_reason?: string | null;
}

export interface PendingRequest {
  id: string;
  signal: any;
  grant: Grant;
  intentSpec: any;
  state: string;
}

/**
 * Authorization records. Revocation must be visible to the next `find`, so a
 * durable implementation must not cache across requests without invalidation.
 */
export interface GrantStore {
  add(grant: Grant): Awaitable<Grant>;
  get(id: string): Awaitable<Grant | undefined>;
  find(
    requesterKey: string,
    manifestDigest: string
  ): Awaitable<Grant | undefined>;
  remove(id: string): Awaitable<Grant | undefined>;
  all(): Awaitable<Grant[]>;
}

/**
 * Verified manifests, keyed by digest. Manifests are immutable, so this
 * contract is synchronous: durable implementations may load and cache them at
 * startup.
 */
export interface ManifestStore {
  add(manifest: VerifiedManifest): VerifiedManifest;
  get(digest: string): VerifiedManifest | undefined;
}

/**
 * Replay protection. `markIfNew` MUST insert atomically and return false if
 * the id already exists. Implementations SHOULD expire entries after the
 * maximum signal lifetime.
 */
export interface ReplayStore {
  has(id: string): Awaitable<boolean>;
  markIfNew(id: string): Awaitable<boolean>;
}

/**
 * Cumulative limit counters. `tryReserve` MUST reserve one unit against every
 * limit or none, inside one transaction; returning true means the reservation
 * is durable. `counters` MUST include in-flight reservations.
 */
export interface LimitStore {
  tryReserve(grantId: string, limits: Record<string, number>): Awaitable<boolean>;
  release(grantId: string, limits: Record<string, number>): Awaitable<void>;
  counters(grantId: string): Awaitable<Record<string, number>>;
}

/**
 * Pending confirmations. `take` MUST remove and return atomically so a
 * confirmation can be resolved at most once, including across processes.
 */
export interface PendingStore {
  put(request: PendingRequest): Awaitable<void>;
  get(id: string): Awaitable<PendingRequest | undefined>;
  take(id: string): Awaitable<PendingRequest | undefined>;
}

/** Append-only audit records. Implementations MUST NOT update past entries. */
export interface AuditStore {
  append(event: Record<string, unknown>): Awaitable<unknown>;
}

export interface RuntimeStores {
  grants: GrantStore;
  manifests: ManifestStore;
  replay: ReplayStore;
  limits: LimitStore;
  pending: PendingStore;
  audit: AuditStore;
}

/** Default in-process stores. State is lost on restart; use durable ones in production. */
export class MemoryGrantStore implements GrantStore {
  private _grants = new Map<string, Grant>();

  constructor(grants: Grant[] = []) {
    for (const grant of grants) this.add(grant);
  }

  add(grant: Grant): Grant {
    this._grants.set(grant.id, grant);
    return grant;
  }

  get(id: string): Grant | undefined {
    return this._grants.get(id);
  }

  find(requesterKey: string, manifestDigest: string): Grant | undefined {
    for (const grant of this._grants.values()) {
      if (
        grant.requester_key === requesterKey &&
        grant.manifest_digest === manifestDigest
      ) {
        return grant;
      }
    }
    return undefined;
  }

  remove(id: string): Grant | undefined {
    const grant = this._grants.get(id);
    this._grants.delete(id);
    return grant;
  }

  all(): Grant[] {
    return [...this._grants.values()];
  }
}

export class MemoryManifestStore implements ManifestStore {
  private _byDigest = new Map<string, VerifiedManifest>();

  constructor(manifests: VerifiedManifest[] = []) {
    for (const manifest of manifests) this.add(manifest);
  }

  add(manifest: VerifiedManifest): VerifiedManifest {
    this._byDigest.set(manifest.digest, manifest);
    return manifest;
  }

  get(digest: string): VerifiedManifest | undefined {
    return this._byDigest.get(digest);
  }
}

export class MemoryReplayStore implements ReplayStore {
  private _seen = new Set<string>();

  has(id: string): boolean {
    return this._seen.has(id);
  }

  mark(id: string): void {
    this._seen.add(id);
  }

  markIfNew(id: string): boolean {
    if (this._seen.has(id)) return false;
    this._seen.add(id);
    return true;
  }

  snapshot(): Set<string> {
    return new Set(this._seen);
  }
}

export class MemoryLimitStore implements LimitStore {
  private _counters = new Map<string, Record<string, number>>();

  /** Atomically reserve one unit against every limit, or none. */
  tryReserve(grantId: string, limits: Record<string, number>): boolean {
    const current = this._counters.get(grantId) ?? {};
    for (const [name, maximum] of Object.entries(limits)) {
      if ((current[name] ?? 0) + 1 > maximum) return false;
    }
    for (const name of Object.keys(limits)) {
      current[name] = (current[name] ?? 0) + 1;
    }
    this._counters.set(grantId, current);
    return true;
  }

  release(grantId: string, limits: Record<string, number>): void {
    const current = this._counters.get(grantId) ?? {};
    for (const name of Object.keys(limits)) {
      current[name] = Math.max(0, (current[name] ?? 0) - 1);
    }
    this._counters.set(grantId, current);
  }

  counters(grantId: string): Record<string, number> {
    return { ...(this._counters.get(grantId) ?? {}) };
  }
}

export class MemoryPendingStore implements PendingStore {
  private _pending = new Map<string, PendingRequest>();

  put(request: PendingRequest): void {
    this._pending.set(request.id, request);
  }

  get(id: string): PendingRequest | undefined {
    return this._pending.get(id);
  }

  take(id: string): PendingRequest | undefined {
    const request = this._pending.get(id);
    this._pending.delete(id);
    return request;
  }
}

export class MemoryAuditLog implements AuditStore {
  private _events: any[] = [];

  append(event: Record<string, unknown>): any {
    const record = { at: utcnow(), ...event };
    this._events.push(record);
    return record;
  }

  events(): any[] {
    return [...this._events];
  }

  get length(): number {
    return this._events.length;
  }
}

export class MemoryStores implements RuntimeStores {
  readonly grants: MemoryGrantStore;
  readonly manifests: MemoryManifestStore;
  readonly replay: MemoryReplayStore;
  readonly limits: MemoryLimitStore;
  readonly pending: MemoryPendingStore;
  readonly audit: MemoryAuditLog;

  constructor(options: {
    grants?: Grant[];
    manifests?: VerifiedManifest[];
  } = {}) {
    this.grants = new MemoryGrantStore(options.grants);
    this.manifests = new MemoryManifestStore(options.manifests);
    this.replay = new MemoryReplayStore();
    this.limits = new MemoryLimitStore();
    this.pending = new MemoryPendingStore();
    this.audit = new MemoryAuditLog();
  }
}
