import { publicBytesFromKeyId } from "./crypto.js";
import { verifyManifest, type VerifiedManifest } from "./consumer.js";
import { CcpError } from "./errors.js";
import { randomId } from "./ids.js";
import type { JsonValue } from "./json.js";
import type { Grant, GrantState } from "./stores.js";
import { utcnow } from "./time.js";

export type ConfirmationPolicy = "none" | "per_action";

export interface CreateGrantOptions {
  /** Opaque local id. Defaults to a random 128-bit hex id. */
  id?: string;
  /** Local contact reference; never sent to the provider. */
  contactId: string;
  /** `key:ed25519:<base64url>` of the approved requester. */
  requesterKey: string;
  /** Signed manifest wire or an already-verified manifest. */
  manifest: VerifiedManifest | string;
  /** Intents the user approved. Each must exist in the manifest. */
  intents: string[];
  /**
   * Consumer-selected ceilings. Defaults to the manifest's suggested limits.
   * A value above the suggestion is rejected (§9.2).
   */
  limits?: Record<string, number>;
  /**
   * Per-intent confirmation policy. Defaults to the manifest policy, or
   * `per_action` when unspecified. A grant may tighten but never relax it.
   */
  confirmation?: Record<string, ConfirmationPolicy>;
  /**
   * Host capabilities. Defaults to the union required by the approved
   * intents; additional capabilities are rejected as unnecessary authority.
   */
  capabilities?: string[];
  /** Allowed placement. Defaults to the union declared by the intents. */
  placement?: string[];
  /** Data-egress policy. Defaults to the union declared by the intents. */
  egress?: { [key: string]: JsonValue };
  /** RFC 3339 UTC, second precision. Defaults to now. */
  createdAt?: string;
  /** RFC 3339 UTC, second precision. Must be after `createdAt`. */
  expiresAt: string;
  state?: GrantState;
  stateReason?: string | null;
  /**
   * Rule id that admitted this grant under an admission policy (§25.8.3).
   * Suppressing per-action confirmation requires this, because the policy is
   * the consumer's explicit automation decision (§9.5, §26.2).
   */
  admittedBy?: string;
}

const CONFIRMATION_POLICIES = new Set<string>(["none", "per_action"]);
const GRANT_STATES = new Set<string>([
  "active",
  "paused",
  "suspended",
  "revoked",
  "expired",
]);
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * Build a least-authority grant from an approved manifest and intent list.
 *
 * The helper only ever narrows what the manifest declares: limits cannot
 * exceed `suggested_limits`, confirmation cannot relax to `none`, and
 * capabilities/placement/egress are derived from the approved intents.
 */
export function createGrant(options: CreateGrantOptions): Grant {
  const verified =
    typeof options.manifest === "string"
      ? verifyManifest(options.manifest)
      : options.manifest;

  if (options.intents.length === 0) {
    throw new CcpError("invalid_request", "grant must enable at least one intent");
  }
  const intents = [...new Set(options.intents)];
  const definitions = intents.map((intent) => {
    const definition = verified.manifest.intents?.[intent];
    if (definition === undefined) {
      throw new CcpError("intent_not_allowed", `intent ${intent} is not in the manifest`);
    }
    return definition;
  });

  assertRequesterKey(options.requesterKey);
  if (typeof options.contactId !== "string" || options.contactId === "") {
    throw new CcpError("invalid_request", "contactId is required");
  }

  const version = toSafeInteger(
    verified.manifest.version,
    "manifest version must be an integer"
  );
  if (version < 0) {
    throw new CcpError("invalid_request", "manifest version must be an integer");
  }

  const createdAt = options.createdAt ?? utcnow();
  assertTimestamp(createdAt, "createdAt");
  assertTimestamp(options.expiresAt, "expiresAt");
  if (options.expiresAt <= createdAt) {
    throw new CcpError("invalid_request", "expiresAt must be after createdAt");
  }

  const limits = resolveLimits(definitions, options.limits);
  const confirmation = resolveConfirmation(
    intents,
    definitions,
    options.confirmation,
    options.admittedBy
  );
  const capabilities = resolveCapabilities(definitions, options.capabilities);
  const placement = resolvePlacement(definitions, options.placement);
  const egress = resolveEgress(definitions, options.egress ?? {});

  const state = options.state ?? "active";
  if (!GRANT_STATES.has(state)) {
    throw new CcpError("invalid_request", `unknown grant state: ${state}`);
  }
  if (state !== "active" && (options.stateReason ?? "") === "") {
    throw new CcpError(
      "invalid_request",
      "stateReason is required when the grant is not active"
    );
  }

  return {
    id: options.id ?? randomId(),
    requester_key: options.requesterKey,
    contact_id: options.contactId,
    manifest_digest: verified.digest,
    manifest_version: version,
    intents,
    limits,
    created_at: createdAt,
    expires_at: options.expiresAt,
    confirmation,
    capabilities,
    placement,
    egress,
    state,
    state_reason: options.stateReason ?? null,
  };
}

function resolveLimits(
  definitions: any[],
  requested: Record<string, number> | undefined
): Record<string, number> {
  const suggested: Record<string, number> = {};
  for (const definition of definitions) {
    for (const [name, raw] of Object.entries(
      (definition.suggested_limits ?? {}) as Record<string, unknown>
    )) {
      const value = toLimit(name, raw);
      suggested[name] =
        suggested[name] === undefined ? value : Math.min(suggested[name], value);
    }
  }

  const limits = { ...suggested };
  for (const [name, raw] of Object.entries(requested ?? {})) {
    const value = toLimit(name, raw);
    const ceiling = suggested[name];
    if (ceiling !== undefined && value > ceiling) {
      throw new CcpError(
        "invalid_request",
        `limit ${name} (${value}) exceeds the manifest suggestion (${ceiling})`
      );
    }
    limits[name] = value;
  }
  return limits;
}

function resolveConfirmation(
  intents: string[],
  definitions: any[],
  requested: Record<string, ConfirmationPolicy> | undefined,
  admittedBy: string | undefined
): Record<string, string> {
  const overrides = requested ?? {};
  for (const intent of Object.keys(overrides)) {
    if (!intents.includes(intent)) {
      throw new CcpError(
        "invalid_request",
        `confirmation override for an intent that is not enabled: ${intent}`
      );
    }
  }

  const confirmation: Record<string, string> = {};
  intents.forEach((intent, index) => {
    const manifestPolicy = definitions[index].confirmation;
    const base =
      manifestPolicy === "none" || manifestPolicy === "per_action"
        ? manifestPolicy
        : "per_action";
    const override = overrides[intent];
    if (override === undefined) {
      confirmation[intent] = base;
      return;
    }
    if (!CONFIRMATION_POLICIES.has(override)) {
      throw new CcpError(
        "invalid_request",
        `unknown confirmation policy: ${override}`
      );
    }
    if (base === "per_action" && override === "none" && admittedBy === undefined) {
      throw new CcpError(
        "invalid_request",
        `confirmation for ${intent} cannot be relaxed to none`
      );
    }
    confirmation[intent] = override;
  });
  return confirmation;
}

function resolveCapabilities(
  definitions: any[],
  requested: string[] | undefined
): string[] {
  const required = new Set<string>();
  for (const definition of definitions) {
    for (const capability of definition.required_capabilities ?? []) {
      required.add(capability);
    }
  }

  if (requested === undefined) return [...required];

  const supplied = new Set(requested);
  for (const capability of required) {
    if (!supplied.has(capability)) {
      throw new CcpError(
        "capability_unavailable",
        `grant is missing required capability: ${capability}`
      );
    }
  }
  for (const capability of supplied) {
    if (!required.has(capability)) {
      throw new CcpError(
        "invalid_request",
        `capability is not required by the enabled intents: ${capability}`
      );
    }
  }
  return [...supplied];
}

function resolvePlacement(
  definitions: any[],
  requested: string[] | undefined
): string[] {
  const declared = new Set<string>(
    definitions.map((definition) => definition.placement ?? "local")
  );
  if (requested === undefined) return [...declared];
  if (requested.length === 0) {
    throw new CcpError("invalid_request", "placement must not be empty");
  }
  for (const placement of requested) {
    if (!declared.has(placement)) {
      throw new CcpError(
        "invalid_request",
        `placement is not declared by the enabled intents: ${placement}`
      );
    }
  }
  return [...new Set(requested)];
}

function resolveEgress(
  definitions: any[],
  requested: { [key: string]: JsonValue }
): { [key: string]: JsonValue } {
  const network = definitions.some(
    (definition) => definition.data_egress?.network === true
  );
  const fields = new Set<string>();
  for (const definition of definitions) {
    for (const field of definition.data_egress?.fields ?? []) {
      fields.add(field);
    }
  }

  if (requested.network !== undefined && typeof requested.network !== "boolean") {
    throw new CcpError("invalid_request", "egress.network must be a boolean");
  }
  if (requested.network === true && !network) {
    throw new CcpError(
      "invalid_request",
      "egress network is not declared by the enabled intents"
    );
  }
  const suppliedFields = requested.fields;
  if (suppliedFields !== undefined) {
    if (
      !Array.isArray(suppliedFields) ||
      suppliedFields.some((field) => typeof field !== "string")
    ) {
      throw new CcpError("invalid_request", "egress.fields must be strings");
    }
    for (const field of suppliedFields as string[]) {
      if (!fields.has(field)) {
        throw new CcpError(
          "invalid_request",
          `egress field is not declared by the enabled intents: ${field}`
        );
      }
    }
  }

  return {
    ...requested,
    network: requested.network ?? network,
    fields: (suppliedFields as string[] | undefined) ?? [...fields],
  };
}

function assertRequesterKey(keyId: string): void {
  let bytes: Uint8Array;
  try {
    bytes = publicBytesFromKeyId(keyId);
  } catch {
    throw new CcpError("invalid_request", "requesterKey is not an Ed25519 key id");
  }
  if (bytes.length !== 32) {
    throw new CcpError("invalid_request", "requesterKey must be a 32-byte key");
  }
}

function assertTimestamp(value: string, name: string): void {
  const parsed = TIMESTAMP.test(value) ? Date.parse(value) : Number.NaN;
  const normalized = Number.isNaN(parsed)
    ? undefined
    : new Date(parsed).toISOString().replace(/\.\d+Z$/, "Z");
  if (normalized !== value) {
    throw new CcpError(
      "invalid_request",
      `${name} must be an RFC 3339 UTC timestamp with second precision`
    );
  }
}

function toLimit(name: string, value: unknown): number {
  const parsed =
    typeof value === "bigint" ? Number(value) : value;
  if (
    typeof parsed !== "number" ||
    !Number.isSafeInteger(parsed) ||
    parsed < 0
  ) {
    throw new CcpError(
      "invalid_request",
      `limit ${name} must be a non-negative integer`
    );
  }
  return parsed;
}

function toSafeInteger(value: unknown, message: string): number {
  const parsed = typeof value === "bigint" ? Number(value) : value;
  if (typeof parsed !== "number" || !Number.isSafeInteger(parsed)) {
    throw new CcpError("invalid_request", message);
  }
  return parsed;
}
