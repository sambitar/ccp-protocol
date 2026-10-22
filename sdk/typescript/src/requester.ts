import type { JsonValue } from "./json.js";
import { signDocument } from "./signing.js";
import { keyIdFromPublic, publicFromSeed } from "./crypto.js";

export interface IntentDefinition {
  description?: string;
  params_schema: string;
  result_schema: string;
  required_capabilities: string[];
  placement?: string;
  data_egress?: { network: boolean; fields: string[] };
  suggested_limits?: Record<string, number>;
  confirmation?: string;
}

export interface ManifestInput {
  ccp?: string;
  provider: { id: string; name?: string };
  version: number;
  intents: Record<string, IntentDefinition>;
}

export interface SignalInput {
  ccp?: string;
  requestId: string;
  grantDigest: string;
  intent: string;
  params: Record<string, JsonValue>;
  issuedAt: string;
  expiresAt: string;
}

const DEFAULT_CCP = "0.5-draft";

export function buildManifest(input: ManifestInput): { [key: string]: JsonValue } {
  const provider: { [key: string]: JsonValue } = { id: input.provider.id };
  if (input.provider.name !== undefined) provider.name = input.provider.name;
  return {
    ccp: input.ccp ?? DEFAULT_CCP,
    provider,
    version: input.version,
    intents: input.intents as unknown as { [key: string]: JsonValue },
  };
}

export function signManifest(input: ManifestInput, seed: Uint8Array): string {
  return signDocument(buildManifest(input), seed);
}

export function buildSignal(input: SignalInput): { [key: string]: JsonValue } {
  return {
    ccp: input.ccp ?? DEFAULT_CCP,
    request_id: input.requestId,
    grant_digest: input.grantDigest,
    intent: input.intent,
    params: input.params,
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
  };
}

export function signSignal(input: SignalInput, seed: Uint8Array): string {
  return signDocument(buildSignal(input), seed);
}

/** Convenience wrapper around a signing key. */
export class Requester {
  readonly keyId: string;

  constructor(private readonly seed: Uint8Array) {
    this.keyId = keyIdFromPublic(publicFromSeed(seed));
  }

  manifest(input: ManifestInput): string {
    return signManifest(input, this.seed);
  }

  signal(input: SignalInput): string {
    return signSignal(input, this.seed);
  }
}
