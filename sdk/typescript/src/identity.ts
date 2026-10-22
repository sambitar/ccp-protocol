import {
  digestBytes,
  keyIdFromPublic,
  publicBytesFromKeyId,
  publicFromSeed,
  sha256Hex,
  verify,
} from "./crypto.js";
import type { JsonValue } from "./json.js";
import { serialize } from "./json.js";
import { parseStrict } from "./parse.js";
import { signDocument, signingBytes } from "./signing.js";
import { utcnow } from "./time.js";

/** Wire type of an identity document (§25.8.1). */
export const IDENTITY_TYPE = "ccp.identity.v1";
/** Wire type of an admission policy (§25.8.3). */
export const POLICY_TYPE = "ccp.admission-policy.v1";
/** Tolerated clock skew for validity windows (§25.8.1). */
export const IDENTITY_CLOCK_SKEW_SECONDS = 120;

const SUPPORTED_LABELS: ReadonlySet<string> = new Set([
  "0.5-draft",
  "0.4-draft",
]);
const ROLES: ReadonlySet<string> = new Set([
  "provider",
  "requester",
  "consumer",
]);
const ADMITTABLE_RISK: ReadonlySet<string> = new Set(["read", "disclose"]);
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export type RiskClass = "read" | "disclose" | "write" | "irreversible";

/**
 * Identity-layer results (§25.8). These are intentionally separate from the
 * §10.4 decision codes: they occur while establishing a contact, before any
 * signal exists, and must never be returned as a signal outcome.
 */
export type IdentityErrorCode =
  | "invalid_request"
  | "unauthenticated"
  | "identity_expired"
  | "identity_changed"
  | "manifest_mismatch"
  | "policy_mismatch"
  | "policy_expired";

export class IdentityError extends Error {
  readonly code: IdentityErrorCode;

  constructor(code: IdentityErrorCode, message = "") {
    super(message ? `${code}: ${message}` : code);
    this.name = "IdentityError";
    this.code = code;
  }
}

export interface Endpoint {
  transport: string;
  manifest?: string;
  signal?: string;
}

export interface IdentityInput {
  name?: string;
  roles?: string[];
  endpoints?: Endpoint[];
  manifestDigest?: string;
  policyDigest?: string;
  issuedAt: string;
  expiresAt: string;
  ccp?: string;
}

export interface VerifiedIdentity {
  document: string;
  identity: string;
  name?: string;
  roles: string[];
  endpoints: Endpoint[];
  manifestDigest?: string;
  policyDigest?: string;
  issuedAt: string;
  expiresAt: string;
}

export interface VerifyIdentityOptions {
  now?: string;
  expectedIdentity?: string;
  manifestDigest?: string;
  policyDigest?: string;
}

/* ------------------------------------------------------------------ */
/* structural helpers                                                  */
/* ------------------------------------------------------------------ */

type Obj = { [key: string]: JsonValue };

function asObject(value: JsonValue, what: string): Obj {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new IdentityError("invalid_request", `${what} must be an object`);
  }
  return value as Obj;
}

function readString(obj: Obj, key: string, what: string): string {
  const value = obj[key];
  if (typeof value !== "string" || value === "") {
    throw new IdentityError("invalid_request", `${what}.${key} is required`);
  }
  return value;
}

function optionalString(
  obj: Obj,
  key: string,
  what: string
): string | undefined {
  if (!(key in obj)) return undefined;
  return readString(obj, key, what);
}

function readStringArray(obj: Obj, key: string, what: string): string[] {
  const value = obj[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new IdentityError("invalid_request", `${what}.${key} is required`);
  }
  return value.map((item) => {
    if (typeof item !== "string" || item === "") {
      throw new IdentityError(
        "invalid_request",
        `${what}.${key} must contain non-empty strings`
      );
    }
    return item;
  });
}

function optionalStringArray(
  obj: Obj,
  key: string,
  what: string
): string[] | undefined {
  if (!(key in obj)) return undefined;
  return readStringArray(obj, key, what);
}

function readTimestamp(obj: Obj, key: string, what: string): string {
  const value = readString(obj, key, what);
  if (!TIMESTAMP.test(value)) {
    throw new IdentityError(
      "invalid_request",
      `${what}.${key} must be RFC 3339 UTC with second precision`
    );
  }
  return value;
}

function assertDigest(value: string | undefined, field: string): void {
  if (value !== undefined && !DIGEST.test(value)) {
    throw new IdentityError("invalid_request", `${field} is not a digest`);
  }
}

function assertKeyId(identity: string): void {
  let raw: Uint8Array;
  try {
    raw = publicBytesFromKeyId(identity);
  } catch {
    throw new IdentityError("invalid_request", "identity is not a key id");
  }
  if (raw.length !== 32) {
    throw new IdentityError("invalid_request", "identity key is not 32 bytes");
  }
}

function addSeconds(timestamp: string, seconds: number): string {
  const ms = Date.parse(timestamp);
  if (Number.isNaN(ms)) {
    throw new IdentityError("invalid_request", "invalid timestamp");
  }
  return new Date(ms + seconds * 1000)
    .toISOString()
    .replace(/\.\d+Z$/, "Z");
}

function assertLabel(obj: Obj): void {
  const label = readString(obj, "ccp", "document");
  if (!SUPPORTED_LABELS.has(label)) {
    throw new IdentityError("invalid_request", "unsupported ccp label");
  }
}

/** Verify `signature` over the signing bytes using the document's own key. */
function assertSignature(obj: Obj, identity: string): void {
  const signature = obj.signature;
  if (typeof signature !== "string" || !signature.startsWith("ed25519:")) {
    throw new IdentityError("invalid_request", "signature is required");
  }
  if (!verify(signingBytes(obj), signature, publicBytesFromKeyId(identity))) {
    throw new IdentityError("unauthenticated", "signature is invalid");
  }
}

/* ------------------------------------------------------------------ */
/* identity documents                                                  */
/* ------------------------------------------------------------------ */

/** `sha256:<hex>` over the signing bytes of an identity document. */
export function identityDigest(document: string): string {
  return digestBytes(signingBytes(parseStrict(document)));
}

/** Build and sign an identity document; the identity is derived from `seed`. */
export function buildIdentityDocument(
  input: IdentityInput,
  seed: Uint8Array
): string {
  const value: Obj = {
    ccp: input.ccp ?? "0.5-draft",
    type: IDENTITY_TYPE,
    identity: keyIdFromPublic(publicFromSeed(seed)),
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
  };
  if (input.name !== undefined) value.name = input.name;
  if (input.roles !== undefined) value.roles = [...input.roles];
  if (input.endpoints !== undefined) {
    value.endpoints = input.endpoints.map((endpoint) => {
      const entry: Obj = { transport: endpoint.transport };
      if (endpoint.manifest !== undefined) entry.manifest = endpoint.manifest;
      if (endpoint.signal !== undefined) entry.signal = endpoint.signal;
      return entry;
    });
  }
  if (input.manifestDigest !== undefined) {
    value.manifest_digest = input.manifestDigest;
  }
  if (input.policyDigest !== undefined) {
    value.policy_digest = input.policyDigest;
  }
  return signDocument(value, seed);
}

/**
 * Parse and verify an identity document (§25.8.1).
 *
 * `expectedIdentity` is the key the caller already knows for this contact.
 * A different key is `identity_changed`, not `unauthenticated`, because the
 * consequence differs: affected grants must be suspended (§7.4).
 */
export function verifyIdentityDocument(
  document: string,
  options: VerifyIdentityOptions = {}
): VerifiedIdentity {
  const obj = asObject(parseStrict(document), "identity document");
  assertLabel(obj);

  const type = readString(obj, "type", "identity");
  if (type !== IDENTITY_TYPE) {
    throw new IdentityError("invalid_request", "type is not an identity");
  }

  const identity = readString(obj, "identity", "identity");
  assertKeyId(identity);
  assertSignature(obj, identity);

  if (
    options.expectedIdentity !== undefined &&
    options.expectedIdentity !== identity
  ) {
    throw new IdentityError(
      "identity_changed",
      "identity key differs from the known contact"
    );
  }

  const issuedAt = readTimestamp(obj, "issued_at", "identity");
  const expiresAt = readTimestamp(obj, "expires_at", "identity");
  if (expiresAt <= issuedAt) {
    throw new IdentityError(
      "invalid_request",
      "expires_at must sort after issued_at"
    );
  }

  const now = options.now ?? utcnow();
  if (issuedAt > addSeconds(now, IDENTITY_CLOCK_SKEW_SECONDS)) {
    throw new IdentityError(
      "identity_expired",
      "identity document is not yet valid"
    );
  }
  if (now > expiresAt) {
    throw new IdentityError("identity_expired", "identity document expired");
  }

  let roles: string[] = [];
  if ("roles" in obj) {
    roles = readStringArray(obj, "roles", "identity");
    for (const role of roles) {
      if (!ROLES.has(role)) {
        throw new IdentityError("invalid_request", `unknown role: ${role}`);
      }
    }
    if (new Set(roles).size !== roles.length) {
      throw new IdentityError("invalid_request", "roles must be unique");
    }
  }

  const endpoints: Endpoint[] = [];
  if ("endpoints" in obj) {
    const raw = obj.endpoints;
    if (!Array.isArray(raw) || raw.length === 0) {
      throw new IdentityError(
        "invalid_request",
        "endpoints must be a non-empty array"
      );
    }
    for (const item of raw) {
      const entry = asObject(item, "endpoint");
      const transport = readString(entry, "transport", "endpoint");
      const endpoint: Endpoint = { transport };
      const manifest = optionalString(entry, "manifest", "endpoint");
      const signal = optionalString(entry, "signal", "endpoint");
      if (manifest === undefined && signal === undefined) {
        throw new IdentityError(
          "invalid_request",
          "endpoint must carry manifest or signal"
        );
      }
      if (manifest !== undefined) endpoint.manifest = manifest;
      if (signal !== undefined) endpoint.signal = signal;
      endpoints.push(endpoint);
    }
  }

  const manifestDigest = optionalString(obj, "manifest_digest", "identity");
  assertDigest(manifestDigest, "manifest_digest");
  if (
    options.manifestDigest !== undefined &&
    manifestDigest !== undefined &&
    options.manifestDigest !== manifestDigest
  ) {
    throw new IdentityError(
      "manifest_mismatch",
      "manifest digest does not match the document"
    );
  }

  const policyDigest = optionalString(obj, "policy_digest", "identity");
  assertDigest(policyDigest, "policy_digest");
  if (
    options.policyDigest !== undefined &&
    policyDigest !== undefined &&
    options.policyDigest !== policyDigest
  ) {
    throw new IdentityError(
      "policy_mismatch",
      "policy digest does not match the document"
    );
  }

  const verified: VerifiedIdentity = {
    document,
    identity,
    roles,
    endpoints,
    issuedAt,
    expiresAt,
  };
  const name = optionalString(obj, "name", "identity");
  if (name !== undefined) verified.name = name;
  if (manifestDigest !== undefined) verified.manifestDigest = manifestDigest;
  if (policyDigest !== undefined) verified.policyDigest = policyDigest;
  return verified;
}

/* ------------------------------------------------------------------ */
/* admission policies                                                  */
/* ------------------------------------------------------------------ */

export interface PolicyRule {
  id: string;
  intents: string[];
  risk: "read" | "disclose";
  contacts?: string[];
  requesters?: string[];
  destinations?: string[];
  limits?: Record<string, number>;
  confirmation: "none";
  expires_at: string;
}

export interface AdmissionPolicyInput {
  version: number;
  default: "confirm" | "deny";
  rules: PolicyRule[];
  issuedAt: string;
  expiresAt: string;
  ccp?: string;
}

export interface VerifiedPolicy {
  document: string;
  host: string;
  version: number;
  default: "confirm" | "deny";
  rules: PolicyRule[];
  issuedAt: string;
  expiresAt: string;
  digest: string;
}

export interface VerifyPolicyOptions {
  now?: string;
  expectedHost?: string;
}

export interface AdmissionRequest {
  requesterKey: string;
  contactId: string;
  intent: string;
  risk: RiskClass;
  destination?: string;
  now: string;
}

export interface AdmissionResult {
  decision: "allow" | "confirm" | "deny";
  reason: string;
  ruleId?: string;
}

export interface AdmissionOptions {
  /**
   * Ids of grants the consumer has revoked. A match whose deterministic id is
   * in this set is refused with `grant_revoked`; the policy cannot resurrect
   * it (§25.8.3).
   */
  revoked?: ReadonlySet<string>;
}

/** The grant a matched rule may create. `allow` still needs its own record. */
export interface AdmittedGrant {
  /** Deterministic id; reused on every admission of this rule. */
  id: string;
  intent: string;
  limits: Record<string, number>;
  expiresAt: string;
}

/**
 * Deterministic grant id for a policy rule and requester (§25.8.3).
 *
 * Reusing the id is what makes revocation durable: the host stores one
 * record, the consumer revokes it, and every later admission of the same
 * rule resolves to that revoked record.
 */
export function admittedGrantId(
  policy: VerifiedPolicy,
  ruleId: string,
  request: AdmissionRequest
): string {
  const material = serialize({
    intent: request.intent,
    policy: policy.digest,
    requester: request.requesterKey,
    rule: ruleId,
  });
  return "pg-" + sha256Hex(new TextEncoder().encode(material)).slice(0, 32);
}

/** `sha256:<hex>` over the signing bytes of an admission policy. */
export function policyDigest(document: string): string {
  return digestBytes(signingBytes(parseStrict(document)));
}

/** Build and sign an admission policy; `host` is derived from `seed`. */
export function buildAdmissionPolicy(
  input: AdmissionPolicyInput,
  seed: Uint8Array
): string {
  const rules = input.rules.map((rule) => {
    const entry: Obj = {
      id: rule.id,
      intents: [...rule.intents],
      risk: rule.risk,
      confirmation: rule.confirmation,
      expires_at: rule.expires_at,
    };
    if (rule.contacts !== undefined) entry.contacts = [...rule.contacts];
    if (rule.requesters !== undefined) {
      entry.requesters = [...rule.requesters];
    }
    if (rule.destinations !== undefined) {
      entry.destinations = [...rule.destinations];
    }
    if (rule.limits !== undefined) entry.limits = { ...rule.limits };
    return entry;
  });

  const value: Obj = {
    ccp: input.ccp ?? "0.5-draft",
    type: POLICY_TYPE,
    host: keyIdFromPublic(publicFromSeed(seed)),
    version: BigInt(input.version),
    default: input.default,
    rules,
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
  };
  return signDocument(value, seed);
}

function readLimits(obj: Obj): Record<string, number> | undefined {
  if (!("limits" in obj)) return undefined;
  const raw = asObject(obj.limits, "rule.limits");
  const limits: Record<string, number> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof value !== "bigint") {
      throw new IdentityError(
        "invalid_request",
        "rule.limits values must be integers"
      );
    }
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new IdentityError("invalid_request", "rule.limits out of range");
    }
    limits[key] = Number(value);
  }
  return limits;
}

function readRule(value: JsonValue, policyExpiresAt: string): PolicyRule {
  const obj = asObject(value, "rule");
  const id = readString(obj, "id", "rule");
  const intents = readStringArray(obj, "intents", "rule");
  const risk = readString(obj, "risk", "rule");
  if (!ADMITTABLE_RISK.has(risk)) {
    throw new IdentityError(
      "invalid_request",
      "a policy may only admit read or disclose intents"
    );
  }

  const contacts = optionalStringArray(obj, "contacts", "rule");
  const requesters = optionalStringArray(obj, "requesters", "rule");
  if (contacts === undefined && requesters === undefined) {
    throw new IdentityError(
      "invalid_request",
      "a rule must name contacts or requesters"
    );
  }

  const destinations = optionalStringArray(obj, "destinations", "rule");
  if (risk === "disclose" && destinations === undefined) {
    throw new IdentityError(
      "invalid_request",
      "a disclose rule must pin destinations"
    );
  }
  if (risk === "read" && destinations !== undefined) {
    throw new IdentityError(
      "invalid_request",
      "only a disclose rule may pin destinations"
    );
  }

  const confirmation = readString(obj, "confirmation", "rule");
  if (confirmation !== "none") {
    throw new IdentityError("invalid_request", "rule.confirmation must be none");
  }

  const expiresAt = readTimestamp(obj, "expires_at", "rule");
  if (expiresAt > policyExpiresAt) {
    throw new IdentityError("invalid_request", "rule expires after the policy");
  }

  const rule: PolicyRule = {
    id,
    intents,
    risk: risk as "read" | "disclose",
    confirmation: "none",
    expires_at: expiresAt,
  };
  if (contacts !== undefined) rule.contacts = contacts;
  if (requesters !== undefined) rule.requesters = requesters;
  if (destinations !== undefined) rule.destinations = destinations;
  const limits = readLimits(obj);
  if (limits !== undefined) rule.limits = limits;
  return rule;
}

/** Parse and verify an admission policy (§25.8.3). */
export function verifyAdmissionPolicy(
  document: string,
  options: VerifyPolicyOptions = {}
): VerifiedPolicy {
  const obj = asObject(parseStrict(document), "policy");
  assertLabel(obj);

  const type = readString(obj, "type", "policy");
  if (type !== POLICY_TYPE) {
    throw new IdentityError("invalid_request", "type is not a policy");
  }

  const host = readString(obj, "host", "policy");
  assertKeyId(host);
  assertSignature(obj, host);

  if (options.expectedHost !== undefined && options.expectedHost !== host) {
    throw new IdentityError(
      "identity_changed",
      "policy host differs from the known identity"
    );
  }

  const rawVersion = obj.version;
  if (typeof rawVersion !== "bigint") {
    throw new IdentityError("invalid_request", "version must be an integer");
  }
  if (rawVersion < 1n || rawVersion > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new IdentityError("invalid_request", "version is out of range");
  }

  const fallback = readString(obj, "default", "policy");
  if (fallback !== "confirm" && fallback !== "deny") {
    throw new IdentityError(
      "invalid_request",
      "default must be confirm or deny"
    );
  }

  const issuedAt = readTimestamp(obj, "issued_at", "policy");
  const expiresAt = readTimestamp(obj, "expires_at", "policy");
  if (expiresAt <= issuedAt) {
    throw new IdentityError(
      "invalid_request",
      "expires_at must sort after issued_at"
    );
  }

  const rawRules = obj.rules;
  if (!Array.isArray(rawRules) || rawRules.length === 0) {
    throw new IdentityError(
      "invalid_request",
      "rules must be a non-empty array"
    );
  }

  const rules: PolicyRule[] = [];
  const seen = new Set<string>();
  for (const value of rawRules) {
    const rule = readRule(value, expiresAt);
    if (seen.has(rule.id)) {
      throw new IdentityError("invalid_request", "rule ids must be unique");
    }
    seen.add(rule.id);
    rules.push(rule);
  }

  const now = options.now ?? utcnow();
  if (now > expiresAt) {
    throw new IdentityError("policy_expired", "admission policy expired");
  }

  return {
    document,
    host,
    version: Number(rawVersion),
    default: fallback,
    rules,
    issuedAt,
    expiresAt,
    digest: digestBytes(signingBytes(obj)),
  };
}

/**
 * Evaluate a verified policy against one request (§25.8.3).
 *
 * `allow` is not an execution: use `admittedGrant` to create the record and
 * then proceed through §10.3.
 */
export function admit(
  policy: VerifiedPolicy,
  request: AdmissionRequest,
  options: AdmissionOptions = {}
): AdmissionResult {
  if (request.now > policy.expiresAt) {
    return { decision: "deny", reason: "policy_expired" };
  }
  if (!ADMITTABLE_RISK.has(request.risk)) {
    return { decision: "deny", reason: "risk_not_admittable" };
  }

  for (const rule of policy.rules) {
    if (request.now > rule.expires_at) continue;
    if (!rule.intents.includes(request.intent)) continue;
    if (rule.risk !== request.risk) continue;
    if (
      rule.contacts !== undefined &&
      !rule.contacts.includes(request.contactId)
    ) {
      continue;
    }
    if (
      rule.requesters !== undefined &&
      !rule.requesters.includes(request.requesterKey)
    ) {
      continue;
    }
    if (rule.risk === "disclose") {
      if (
        request.destination === undefined ||
        rule.destinations === undefined ||
        !rule.destinations.includes(request.destination)
      ) {
        continue;
      }
    }
    if (options.revoked?.has(admittedGrantId(policy, rule.id, request))) {
      return {
        decision: "deny",
        reason: "grant_revoked",
        ruleId: rule.id,
      };
    }
    return { decision: "allow", reason: "rule_matched", ruleId: rule.id };
  }

  if (policy.default === "deny") {
    return { decision: "deny", reason: "default_deny" };
  }
  return { decision: "confirm", reason: "default_confirm" };
}

/**
 * The grant record a match may create: exactly the requested intent, the
 * rule's limits, and the earlier of the rule and policy expiries.
 * Returns `undefined` unless the decision was `allow`.
 */
export function admittedGrant(
  policy: VerifiedPolicy,
  request: AdmissionRequest,
  result: AdmissionResult
): AdmittedGrant | undefined {
  if (result.decision !== "allow" || result.ruleId === undefined) {
    return undefined;
  }
  const rule = policy.rules.find((entry) => entry.id === result.ruleId);
  if (rule === undefined) return undefined;
  const expiresAt =
    rule.expires_at < policy.expiresAt ? rule.expires_at : policy.expiresAt;
  return {
    id: admittedGrantId(policy, rule.id, request),
    intent: request.intent,
    limits: rule.limits ?? {},
    expiresAt,
  };
}
