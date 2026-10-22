import { randomId } from "./ids.js";
import { parseStrict } from "./parse.js";
import { signingBytes } from "./signing.js";
import { keyIdFromPublic, verify } from "./crypto.js";
import { decide } from "./decision.js";
import { validate as validateSchema } from "./schema.js";
import { AUTHORIZED, CONFIRMATION_REQUIRED } from "./errors.js";
import {
  AuditStore,
  Grant,
  GrantStore,
  LimitStore,
  ManifestStore,
  MemoryAuditLog,
  MemoryGrantStore,
  MemoryLimitStore,
  MemoryManifestStore,
  MemoryPendingStore,
  MemoryReplayStore,
  PendingRequest,
  PendingStore,
  ReplayStore,
} from "./stores.js";
import { utcnow } from "./time.js";

export { utcnow };

export interface Decision {
  outcome: string;
  request_id?: string;
  pending_id?: string;
  result?: any;
  error?: string;
  detail?: string;
  state?: string;
}

export class SchemaRegistry {
  private _schemas: Map<string, any>;

  constructor(schemas: Record<string, any> = {}) {
    this._schemas = new Map(Object.entries(schemas));
  }

  register(id: string, schema: any): void {
    this._schemas.set(id, schema);
  }

  get(id: string | undefined): any | undefined {
    return id === undefined ? undefined : this._schemas.get(id);
  }
}

export type IntentExecutor = (params: any, access: HostAccess) => any;
export type HostFunction = (...args: any[]) => any;

export class HostAccess {
  private _granted: Set<string>;

  constructor(
    private readonly registry: HostRegistry,
    granted: string[]
  ) {
    this._granted = new Set(granted);
  }

  call(name: string, ...args: any[]): any {
    if (!this._granted.has(name)) {
      throw new Error(`host function not granted: ${name}`);
    }
    const fn = this.registry.host(name);
    if (!fn) throw new Error(`host function not installed: ${name}`);
    return fn(...args);
  }

  has(name: string): boolean {
    return this._granted.has(name) && this.registry.hasHost(name);
  }
}

export class HostRegistry {
  private _hosts = new Map<string, HostFunction>();
  private _intents = new Map<string, IntentExecutor>();

  registerHost(name: string, fn: HostFunction): void {
    this._hosts.set(name, fn);
  }

  registerIntent(name: string, fn: IntentExecutor): void {
    this._intents.set(name, fn);
  }

  host(name: string): HostFunction | undefined {
    return this._hosts.get(name);
  }

  hasHost(name: string): boolean {
    return this._hosts.has(name);
  }

  intent(name: string): IntentExecutor | undefined {
    return this._intents.get(name);
  }

  hasIntent(name: string): boolean {
    return this._intents.has(name);
  }

  access(granted: string[]): HostAccess {
    return new HostAccess(this, granted);
  }
}

export interface RuntimeOptions {
  grants?: GrantStore;
  manifests?: ManifestStore;
  replay?: ReplayStore;
  limits?: LimitStore;
  pending?: PendingStore;
  schemas?: SchemaRegistry;
  hosts?: HostRegistry;
  audit?: AuditStore;
  clock?: () => string;
  supportedCcp?: string | readonly string[];
}

export class Runtime {
  readonly grants: GrantStore;
  readonly manifests: ManifestStore;
  readonly schemas: SchemaRegistry;
  readonly hosts: HostRegistry;
  readonly audit: AuditStore;
  readonly clock: () => string;
  readonly supportedCcp: string | readonly string[];
  readonly replay: ReplayStore;
  readonly limits: LimitStore;
  readonly pendingStore: PendingStore;

  constructor(options: RuntimeOptions = {}) {
    this.grants = options.grants ?? new MemoryGrantStore();
    this.manifests = options.manifests ?? new MemoryManifestStore();
    this.schemas = options.schemas ?? new SchemaRegistry();
    this.hosts = options.hosts ?? new HostRegistry();
    this.audit = options.audit ?? new MemoryAuditLog();
    this.clock = options.clock ?? utcnow;
    this.supportedCcp = options.supportedCcp ?? ["0.5-draft", "0.4-draft"];
    this.replay = options.replay ?? new MemoryReplayStore();
    this.limits = options.limits ?? new MemoryLimitStore();
    this.pendingStore = options.pending ?? new MemoryPendingStore();
  }

  async submit(document: string, publicKey: Uint8Array): Promise<Decision> {
    const now = this.clock();
    let signal: any;
    try {
      signal = parseStrict(document);
    } catch (error) {
      return this.reject("invalid_request", undefined, undefined, String(error));
    }
    if (signal === null || typeof signal !== "object" || Array.isArray(signal)) {
      return this.reject("invalid_request", undefined, undefined, "signal must be an object");
    }
    for (const field of [
      "ccp",
      "request_id",
      "grant_digest",
      "intent",
      "params",
      "issued_at",
      "expires_at",
      "signature",
    ]) {
      if (!(field in signal)) {
        return this.reject(
          "invalid_request",
          signal.request_id,
          undefined,
          `missing ${field}`
        );
      }
    }
    try {
      if (!verify(signingBytes(signal), signal.signature, publicKey)) {
        return this.reject(
          "unauthenticated",
          signal.request_id,
          undefined,
          "signature mismatch"
        );
      }
    } catch (error) {
      return this.reject(
        "unauthenticated",
        signal.request_id,
        undefined,
        String(error)
      );
    }

    const signer = keyIdFromPublic(publicKey);
    const grant = await this.grants.find(signer, signal.grant_digest);
    let intentSpec: any = null;
    let paramsSchema: any = null;
    if (grant) {
      const manifest = this.manifests.get(grant.manifest_digest);
      if (manifest) {
        intentSpec = manifest.manifest.intents?.[signal.intent] ?? null;
        paramsSchema = intentSpec
          ? this.schemas.get(intentSpec.params_schema)
          : null;
      }
    }

    const replayed = grant ? await this.replay.has(signal.request_id) : false;
    const outcome = decide({
      grant: grant ?? null,
      signal,
      signer,
      now,
      seen: replayed ? new Set([signal.request_id]) : new Set(),
      counters: grant ? await this.limits.counters(grant.id) : {},
      intentSpec,
      paramsSchema,
      supportedCcp: this.supportedCcp,
    });

    if (outcome !== AUTHORIZED && outcome !== CONFIRMATION_REQUIRED) {
      return this.reject(outcome, signal.request_id, grant);
    }

    if (!(await this.replay.markIfNew(signal.request_id))) {
      return this.reject("replay_detected", signal.request_id, grant);
    }
    if (!(await this.limits.tryReserve(grant!.id, grant!.limits))) {
      return this.reject("limit_exceeded", signal.request_id, grant);
    }

    const required: string[] = intentSpec.required_capabilities ?? [];
    const unavailable = required.filter(
      (capability) => !this.hosts.hasHost(capability)
    );
    if (unavailable.length > 0 || !this.hosts.hasIntent(signal.intent)) {
      await this.limits.release(grant!.id, grant!.limits);
      return this.reject(
        "capability_unavailable",
        signal.request_id,
        grant,
        `unavailable: ${unavailable.length > 0 ? unavailable.join(",") : signal.intent}`
      );
    }

    if (outcome === CONFIRMATION_REQUIRED) {
      const pendingId = randomId();
      await this.pendingStore.put({
        id: pendingId,
        signal,
        grant: grant!,
        intentSpec,
        state: "awaiting_confirmation",
      });
      await this.audit.append({
        event: "awaiting_confirmation",
        request_id: signal.request_id,
        intent: signal.intent,
        grant_id: grant!.id,
      });
      return {
        outcome: CONFIRMATION_REQUIRED,
        request_id: signal.request_id,
        pending_id: pendingId,
        state: "awaiting_confirmation",
      };
    }

    return this.execute(signal, grant!, intentSpec);
  }

  async confirm(pendingId: string, approved: boolean): Promise<Decision> {
    const pending = await this.pendingStore.take(pendingId);
    if (!pending) {
      return this.reject(
        "invalid_request",
        undefined,
        undefined,
        "unknown pending request"
      );
    }
    if (!approved) {
      await this.limits.release(pending.grant.id, pending.grant.limits);
      await this.audit.append({
        event: "cancelled",
        request_id: pending.signal.request_id,
        grant_id: pending.grant.id,
      });
      return {
        outcome: "cancelled",
        request_id: pending.signal.request_id,
        state: "cancelled",
      };
    }
    const stateError = this.grantStateError(pending.grant, this.clock());
    if (stateError) {
      await this.limits.release(pending.grant.id, pending.grant.limits);
      return this.reject(stateError, pending.signal.request_id, pending.grant);
    }
    return this.execute(pending.signal, pending.grant, pending.intentSpec);
  }

  pending(pendingId: string): Promise<PendingRequest | undefined> {
    return Promise.resolve(this.pendingStore.get(pendingId));
  }

  private async execute(
    signal: any,
    grant: Grant,
    intentSpec: any
  ): Promise<Decision> {
    await this.audit.append({
      event: "executing",
      request_id: signal.request_id,
      intent: signal.intent,
      grant_id: grant.id,
    });
    const executor = this.hosts.intent(signal.intent);
    if (!executor) {
      await this.limits.release(grant.id, grant.limits);
      return {
        outcome: "execution_failed",
        request_id: signal.request_id,
        error: "execution_failed",
        detail: "intent not installed",
        state: "failed",
      };
    }
    let result: any;
    try {
      result = await executor(signal.params, this.hosts.access(grant.capabilities));
    } catch (error) {
      await this.limits.release(grant.id, grant.limits);
      await this.audit.append({
        event: "failed",
        request_id: signal.request_id,
        grant_id: grant.id,
        detail: String(error),
      });
      return {
        outcome: "execution_failed",
        request_id: signal.request_id,
        error: "execution_failed",
        detail: String(error),
        state: "failed",
      };
    }

    const resultSchema = this.schemas.get(intentSpec.result_schema);
    if (resultSchema !== undefined) {
      const problems = validateSchema(result, resultSchema);
      if (problems.length > 0) {
        await this.limits.release(grant.id, grant.limits);
        await this.audit.append({
          event: "failed",
          request_id: signal.request_id,
          grant_id: grant.id,
          detail: "invalid result",
        });
        return {
          outcome: "execution_failed",
          request_id: signal.request_id,
          error: "execution_failed",
          detail: "invalid result: " + problems.join("; "),
          state: "failed",
        };
      }
    }

    await this.audit.append({
      event: "completed",
      request_id: signal.request_id,
      grant_id: grant.id,
    });
    return {
      outcome: AUTHORIZED,
      request_id: signal.request_id,
      result,
      state: "completed",
    };
  }

  private grantStateError(grant: Grant, now: string): string | undefined {
    if (grant.state === "revoked") return "grant_revoked";
    if (grant.state === "paused") return "grant_paused";
    if (grant.state === "suspended") return "grant_suspended";
    if (grant.state === "expired" || now >= grant.expires_at) {
      return "grant_expired";
    }
    return undefined;
  }

  private async reject(
    code: string,
    requestId?: string,
    grant?: Grant,
    detail?: string
  ): Promise<Decision> {
    await this.audit.append({
      event: "rejected",
      request_id: requestId,
      grant_id: grant?.id,
      code,
      detail,
    });
    return { outcome: code, request_id: requestId, error: code, detail };
  }
}
