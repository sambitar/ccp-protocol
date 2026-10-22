import { randomId } from "./ids.js";
import { parseStrict } from "./parse.js";
import { signingBytes } from "./signing.js";
import { keyIdFromPublic, verify } from "./crypto.js";
import { decide } from "./decision.js";
import { validate as validateSchema } from "./schema.js";
import { AUTHORIZED, CONFIRMATION_REQUIRED, CcpError } from "./errors.js";
import { createGrant } from "./grants.js";
import { verifyManifest, type VerifiedManifest } from "./consumer.js";
import {
  IdentityError,
  admit,
  admittedGrant,
  verifyIdentityDocument,
  type AdmissionRequest,
  type AdmissionResult,
  type VerifiedIdentity,
  type VerifiedPolicy,
  type VerifyIdentityOptions,
} from "./identity.js";
import {
  AuditStore,
  Grant,
  GrantState,
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

export type HostClass = "read" | "write" | "disclose" | "control" | "compute";
export type HostRisk = "read" | "write" | "disclose" | "irreversible";
export type HostPlacement = "local" | "remote" | "delegated";
export type ConfirmationFloor = "none" | "per_action";
export type Idempotency =
  | "pure"
  | "caller_key"
  | "atomic"
  | "none";

/**
 * A host contract (§26.4). Core hosts may omit it; every extension host must
 * declare at least `class`, which fixes the risk and confirmation floor.
 */
export interface HostProfile {
  class?: HostClass;
  risk?: HostRisk;
  minConfirmation?: ConfirmationFloor;
  idempotency?: Idempotency;
  /** May this host send data off the device? Defaults to false. */
  network?: boolean;
  /** Placements this host can serve. Defaults to `["local"]`. */
  placement?: HostPlacement[];
  /** Data categories this host may transmit. Defaults to none. */
  fields?: string[];
}

export interface NormalizedHostProfile {
  class: HostClass;
  risk: HostRisk;
  minConfirmation: ConfirmationFloor;
  idempotency: Idempotency;
  network: boolean;
  placement: HostPlacement[];
  fields: string[];
}

interface HostEntry {
  fn: HostFunction;
  profile: NormalizedHostProfile;
}

/** The only hosts that may be registered without an explicit profile. */
export const CORE_HOSTS: ReadonlySet<string> = new Set([
  "store.read",
  "files.read",
  "files.search",
  "notify",
  "confirm",
  "audit.append",
]);

const HOST_CLASSES: ReadonlySet<string> = new Set([
  "read",
  "write",
  "disclose",
  "control",
  "compute",
]);
const HOST_RISKS: ReadonlySet<string> = new Set([
  "read",
  "write",
  "disclose",
  "irreversible",
]);
const HOST_PLACEMENTS: ReadonlySet<string> = new Set([
  "local",
  "remote",
  "delegated",
]);
const IDEMPOTENCY: ReadonlySet<string> = new Set([
  "pure",
  "caller_key",
  "atomic",
  "none",
]);

const CLASS_DEFAULTS: Record<
  HostClass,
  { risk: HostRisk; minConfirmation: ConfirmationFloor; idempotency: Idempotency }
> = {
  read: { risk: "read", minConfirmation: "none", idempotency: "pure" },
  disclose: { risk: "disclose", minConfirmation: "per_action", idempotency: "pure" },
  write: { risk: "write", minConfirmation: "per_action", idempotency: "caller_key" },
  control: { risk: "write", minConfirmation: "per_action", idempotency: "none" },
  compute: { risk: "read", minConfirmation: "per_action", idempotency: "pure" },
};

export class HostProfileError extends Error {
  readonly code = "invalid_request";

  constructor(message: string) {
    super(`invalid_request: ${message}`);
    this.name = "HostProfileError";
  }
}

/**
 * Validate and normalize a host profile (§26.4).
 *
 * Extension hosts (anything outside the core six) must declare a class; the
 * rest of the contract follows from it unless explicitly overridden. A
 * `write`, `control`, or `compute` host can never suppress confirmation, and
 * an `irreversible` risk cannot either.
 */
export function validateHostProfile(
  name: string,
  profile: HostProfile = {}
): NormalizedHostProfile {
  if (typeof name !== "string" || name === "") {
    throw new HostProfileError("host name is required");
  }

  const declared = profile.class;
  if (declared === undefined && !CORE_HOSTS.has(name)) {
    throw new HostProfileError(`extension host ${name} requires a class`);
  }
  if (declared !== undefined && !HOST_CLASSES.has(declared)) {
    throw new HostProfileError(`unknown host class: ${declared}`);
  }
  const hostClass = (declared ?? "read") as HostClass;
  const defaults = CLASS_DEFAULTS[hostClass];

  const risk = (profile.risk ?? defaults.risk) as HostRisk;
  if (!HOST_RISKS.has(risk)) {
    throw new HostProfileError(`unknown host risk: ${risk}`);
  }

  const minConfirmation = (profile.minConfirmation ??
    defaults.minConfirmation) as ConfirmationFloor;
  if (minConfirmation !== "none" && minConfirmation !== "per_action") {
    throw new HostProfileError(
      `unknown confirmation floor: ${minConfirmation}`
    );
  }
  if (minConfirmation === "none") {
    if (hostClass !== "read" && hostClass !== "disclose") {
      throw new HostProfileError(
        `a ${hostClass} host cannot suppress confirmation`
      );
    }
    if (risk === "irreversible") {
      throw new HostProfileError(
        "an irreversible host cannot suppress confirmation"
      );
    }
  }

  const idempotency = (profile.idempotency ?? defaults.idempotency) as Idempotency;
  if (!IDEMPOTENCY.has(idempotency)) {
    throw new HostProfileError(`unknown idempotency: ${idempotency}`);
  }

  const network = profile.network === true;
  if (profile.network !== undefined && typeof profile.network !== "boolean") {
    throw new HostProfileError("network must be a boolean");
  }

  const placement = profile.placement ?? ["local"];
  if (!Array.isArray(placement) || placement.length === 0) {
    throw new HostProfileError("placement must be a non-empty array");
  }
  const seenPlacement = new Set<string>();
  for (const entry of placement) {
    if (typeof entry !== "string" || !HOST_PLACEMENTS.has(entry)) {
      throw new HostProfileError(`unknown placement: ${entry}`);
    }
    if (seenPlacement.has(entry)) {
      throw new HostProfileError(`duplicate placement: ${entry}`);
    }
    seenPlacement.add(entry);
  }

  const fields = profile.fields ?? [];
  if (!Array.isArray(fields)) {
    throw new HostProfileError("fields must be an array");
  }
  const seenFields = new Set<string>();
  for (const field of fields) {
    if (typeof field !== "string" || field === "") {
      throw new HostProfileError("fields must be non-empty strings");
    }
    if (seenFields.has(field)) {
      throw new HostProfileError(`duplicate field: ${field}`);
    }
    seenFields.add(field);
  }
  if (network && fields.length === 0 && hostClass === "disclose") {
    throw new HostProfileError(
      "a network disclose host must declare the fields it sends"
    );
  }

  return {
    class: hostClass,
    risk,
    minConfirmation,
    idempotency,
    network,
    placement: placement as HostPlacement[],
    fields: [...fields],
  };
}

/** The grant's data-egress ceiling, enforced on every host call. */
export interface EgressPolicy {
  network: boolean;
  fields: ReadonlySet<string>;
}

export class HostAccess {
  private _granted: Set<string>;

  constructor(
    private readonly registry: HostRegistry,
    granted: string[],
    private readonly policy: EgressPolicy = {
      network: false,
      fields: new Set(),
    }
  ) {
    this._granted = new Set(granted);
  }

  call(name: string, ...args: any[]): any {
    if (!this._granted.has(name)) {
      throw new Error(`host function not granted: ${name}`);
    }
    const entry = this.registry.hostMeta(name);
    if (entry === undefined) {
      throw new Error(`host function not installed: ${name}`);
    }
    if (entry.profile.network && !this.policy.network) {
      throw new Error(`host requires network egress not granted: ${name}`);
    }
    for (const field of entry.profile.fields) {
      if (!this.policy.fields.has(field)) {
        throw new Error(`host may send an undeclared field: ${name}/${field}`);
      }
    }
    return entry.fn(...args);
  }

  has(name: string): boolean {
    return this._granted.has(name) && this.registry.hasHost(name);
  }
}

export class HostRegistry {
  private _hosts = new Map<string, HostEntry>();
  private _intents = new Map<string, IntentExecutor>();

  registerHost(
    name: string,
    fn: HostFunction,
    profile: HostProfile = {}
  ): void {
    this._hosts.set(name, {
      fn,
      profile: validateHostProfile(name, profile),
    });
  }

  registerIntent(name: string, fn: IntentExecutor): void {
    this._intents.set(name, fn);
  }

  host(name: string): HostFunction | undefined {
    return this._hosts.get(name)?.fn;
  }

  /** Metadata used to enforce placement, egress, and confirmation (§12). */
  hostMeta(name: string): HostEntry | undefined {
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

  access(granted: string[], policy?: EgressPolicy): HostAccess {
    return new HostAccess(this, granted, policy);
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

export interface AdmitRequestOptions {
  policy: VerifiedPolicy;
  request: AdmissionRequest;
  /** Verified provider manifest that defines the admitted intent. */
  manifest: VerifiedManifest | string;
  confirmation?: Record<string, "none" | "per_action">;
}

export interface AdmitRequestResult {
  result: AdmissionResult;
  grant?: Grant;
}

/**
 * Reserved suspension reason for a requester key change (§7.4). A grant
 * suspended this way cannot be resumed; the consumer re-introduces the
 * contact and creates a new grant.
 */
export const IDENTITY_CHANGED_REASON = "identity_changed";

export interface VerifyContactOptions extends VerifyIdentityOptions {
  /** Local contact the document is being verified for. */
  contactId: string;
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
    const grant = await this.resolveGrant(
      signer,
      signal.grant_digest,
      signal.intent
    );
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
      return this.reject(
        outcome,
        signal.request_id,
        grant,
        this.stateDetail(outcome, grant)
      );
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

    const deployment = this.deploymentError(grant!, intentSpec, required);
    if (deployment !== undefined) {
      await this.limits.release(grant!.id, grant!.limits);
      return this.reject(
        "capability_unavailable",
        signal.request_id,
        grant,
        deployment
      );
    }

    const requiresConfirmation =
      outcome === CONFIRMATION_REQUIRED || this.hostFloor(intentSpec);
    if (requiresConfirmation) {
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
    // The grant may have been revoked or paused while the prompt was open
    // (§9.4.3); re-read it rather than trusting the snapshot.
    const current = (await this.grants.get(pending.grant.id)) ?? pending.grant;
    const stateError = this.grantStateError(current, this.clock());
    if (stateError) {
      await this.limits.release(current.id, current.limits);
      return this.reject(
        stateError,
        pending.signal.request_id,
        current,
        this.stateDetail(stateError, current)
      );
    }
    return this.execute(pending.signal, current, pending.intentSpec);
  }

  pending(pendingId: string): Promise<PendingRequest | undefined> {
    return Promise.resolve(this.pendingStore.get(pendingId));
  }

  /**
   * Pause one grant (§9.4.1). Configuration, limits, and history are kept.
   */
  async pauseGrant(id: string, reason?: string): Promise<Grant> {
    return this.transition(id, "paused", reason);
  }

  /**
   * Suspend one grant (§9.4.2). Used for security events such as a requester
   * key change; resumption requires an explicit `resumeGrant`.
   */
  async suspendGrant(id: string, reason?: string): Promise<Grant> {
    return this.transition(id, "suspended", reason);
  }

  /**
   * Resume a paused or suspended grant (§9.4.3).
   *
   * Re-checks revocation, expiry, and the approved manifest before restoring
   * authority. A revoked or expired grant cannot be resumed.
   */
  async resumeGrant(id: string): Promise<Grant> {
    const grant = await this.grants.get(id);
    if (grant === undefined) {
      throw new CcpError("no_matching_grant", `unknown grant: ${id}`);
    }
    if (grant.state === "revoked") {
      throw new CcpError("grant_revoked", "a revoked grant cannot be resumed");
    }
    if (
      grant.state === "suspended" &&
      grant.state_reason === IDENTITY_CHANGED_REASON
    ) {
      throw new CcpError(
        "grant_suspended",
        "identity changed; re-introduce the contact and create a new grant"
      );
    }
    if (grant.state === "expired" || this.clock() >= grant.expires_at) {
      throw new CcpError("grant_expired", "an expired grant cannot be resumed");
    }
    if (this.manifests.get(grant.manifest_digest) === undefined) {
      throw new CcpError(
        "capability_unavailable",
        "the approved manifest is no longer stored"
      );
    }
    if (grant.state === "active") return grant;
    return this.transition(id, "active", undefined);
  }

  /**
   * Revoke one grant by id (§9.4.4). Permanent: the grant is not resumable and
   * a new approval is required.
   *
   * Policy-created grants reuse their deterministic id, so revoking here also
   * stops an admission rule from re-creating the same access (§25.8.3).
   */
  async revokeGrant(id: string, reason?: string): Promise<Grant> {
    return this.transition(id, "revoked", reason);
  }

  /**
   * Suspend every active grant bound to a contact (§7.4, §9.4.2).
   * Returns the number of grants affected.
   */
  async suspendContact(contactId: string, reason?: string): Promise<number> {
    const affected = (await this.grants.all()).filter(
      (grant) => grant.contact_id === contactId && grant.state !== "revoked"
    );
    for (const grant of affected) {
      await this.setGrantState(grant, "suspended", reason ?? "contact suspended");
    }
    return affected.length;
  }

  /**
   * Verify an identity document for a known contact (§7.4, §25.8.4).
   *
   * On `identity_changed` — a valid signature from a different key — the
   * contact's grants are suspended before the error is rethrown. A bad
   * signature never suspends anything, so an attacker cannot force a
   * suspension by sending garbage.
   */
  async verifyContactIdentity(
    document: string,
    options: VerifyContactOptions
  ): Promise<VerifiedIdentity> {
    try {
      return verifyIdentityDocument(document, options);
    } catch (error) {
      if (error instanceof IdentityError && error.code === "identity_changed") {
        const suspended = await this.suspendContact(
          options.contactId,
          IDENTITY_CHANGED_REASON
        );
        await this.audit.append({
          event: "identity_changed",
          contact_id: options.contactId,
          detail: `${suspended} grant(s) suspended`,
        });
      }
      throw error;
    }
  }

  /**
   * Admit a request under a reviewed policy (§25.8.3).
   *
   * `allow` creates or reuses the grant with the policy's deterministic id,
   * records the admitting rule in the audit log, and leaves the request to
   * proceed through `submit` normally. Revoked ids are consulted from the
   * grant store, so a revocation is never undone here.
   */
  async admitRequest(options: AdmitRequestOptions): Promise<AdmitRequestResult> {
    const { policy, request } = options;
    const manifest =
      typeof options.manifest === "string"
        ? verifyManifest(options.manifest)
        : options.manifest;

    const revoked = new Set(
      (await this.grants.all())
        .filter((grant) => grant.state === "revoked")
        .map((grant) => grant.id)
    );
    const result = admit(policy, request, { revoked });
    if (result.decision !== "allow") return { result };

    const granted = admittedGrant(policy, request, result);
    if (granted === undefined) return { result };

    // A policy may never admit an intent whose hosts require a human.
    const intentSpec = manifest.manifest.intents?.[granted.intent];
    for (const capability of intentSpec?.required_capabilities ?? []) {
      const meta = this.hosts.hostMeta(capability);
      if (meta === undefined) {
        return { result: { decision: "deny", reason: "capability_unavailable" } };
      }
      if (meta.profile.minConfirmation !== "none") {
        return { result: { decision: "deny", reason: "risk_not_admittable" } };
      }
    }

    const existing = await this.grants.get(granted.id);
    if (existing !== undefined) return { result, grant: existing };

    const grant = createGrant({
      id: granted.id,
      contactId: request.contactId,
      requesterKey: request.requesterKey,
      manifest,
      intents: [granted.intent],
      limits: granted.limits,
      confirmation:
        options.confirmation ?? { [granted.intent]: "none" },
      createdAt: this.clock(),
      expiresAt: granted.expiresAt,
      admittedBy: result.ruleId,
    });
    await this.grants.add(grant);
    this.manifests.add(manifest);
    await this.audit.append({
      event: "admitted",
      grant_id: grant.id,
      intent: granted.intent,
      rule_id: result.ruleId,
    });
    return { result, grant };
  }

  /**
   * Resolve the grant for this request.
   *
   * A requester may hold several grants over one manifest digest (for
   * example, a manual grant and a policy-created one). The store lookup is
   * the fast path; when it lands on a grant that does not enable the intent,
   * prefer a grant that does. Revocation remains per grant (§25.8.3).
   */
  private async resolveGrant(
    requesterKey: string,
    manifestDigest: string,
    intent: string
  ): Promise<Grant | undefined> {
    const found = await this.grants.find(requesterKey, manifestDigest);
    if (found !== undefined && found.intents.includes(intent)) return found;

    const candidates = (await this.grants.all()).filter(
      (grant) =>
        grant.requester_key === requesterKey &&
        grant.manifest_digest === manifestDigest &&
        grant.intents.includes(intent)
    );
    if (candidates.length === 0) return found;
    return candidates.find((grant) => grant.state === "active") ?? candidates[0];
  }

  private async transition(
    id: string,
    state: GrantState,
    reason?: string
  ): Promise<Grant> {
    const grant = await this.grants.get(id);
    if (grant === undefined) {
      throw new CcpError("no_matching_grant", `unknown grant: ${id}`);
    }
    if (grant.state === "revoked" && state !== "revoked") {
      throw new CcpError("grant_revoked", "a revoked grant is final");
    }
    return this.setGrantState(grant, state, reason);
  }

  private async setGrantState(
    grant: Grant,
    state: GrantState,
    reason?: string
  ): Promise<Grant> {
    const updated: Grant = {
      ...grant,
      state,
      state_reason:
        state === "active" ? null : reason ?? grant.state_reason ?? null,
    };
    await this.grants.add(updated);
    await this.audit.append({
      event: state === "active" ? "resumed" : state,
      grant_id: grant.id,
      detail: reason,
    });
    return updated;
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
      result = await executor(
        signal.params,
        this.hosts.access(grant.capabilities, this.egressPolicy(grant))
      );
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

  /**
   * Enforce the grant's placement and egress ceilings before execution (§12).
   * A host that needs network access cannot run under a grant that denies it.
   */
  private deploymentError(
    grant: Grant,
    intentSpec: any,
    required: string[]
  ): string | undefined {
    const placement =
      typeof intentSpec.placement === "string" ? intentSpec.placement : "local";
    if (!(grant.placement ?? []).includes(placement)) {
      return `placement ${placement} is not granted`;
    }

    const policy = this.egressPolicy(grant);
    for (const capability of required) {
      const meta = this.hosts.hostMeta(capability);
      if (meta === undefined) return `host ${capability} is not installed`;
      if (!meta.profile.placement.includes(placement)) {
        return `host ${capability} cannot run with ${placement} placement`;
      }
      if (meta.profile.network && !policy.network) {
        return `host ${capability} requires network egress not granted`;
      }
      for (const field of meta.profile.fields) {
        if (!policy.fields.has(field)) {
          return `host ${capability} may send undeclared field ${field}`;
        }
      }
    }
    return undefined;
  }

  /** True when a required host declares a per-action confirmation floor. */
  private hostFloor(intentSpec: any): boolean {
    for (const capability of intentSpec.required_capabilities ?? []) {
      const meta = this.hosts.hostMeta(capability);
      if (meta?.profile.minConfirmation === "per_action") return true;
    }
    return false;
  }

  private egressPolicy(grant: Grant): EgressPolicy {
    const egress = grant.egress ?? {};
    const fields = Array.isArray(egress.fields) ? egress.fields : [];
    return {
      network: egress.network === true,
      fields: new Set(fields.filter((field): field is string => typeof field === "string")),
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

  /**
   * Surface a recorded pause/suspend/revoke reason (§9.4.2). The reason is
   * local and must not contain secrets; hosts choose what to record.
   */
  private stateDetail(outcome: string, grant?: Grant): string | undefined {
    if (grant === undefined) return undefined;
    if (
      outcome === "grant_revoked" ||
      outcome === "grant_paused" ||
      outcome === "grant_suspended"
    ) {
      return grant.state_reason ?? undefined;
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
