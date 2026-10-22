import { parseStrict } from "./parse.js";
import { signingBytes } from "./signing.js";
import { digestBytes, publicBytesFromKeyId, verify } from "./crypto.js";
import { CcpError } from "./errors.js";

export interface VerifiedManifest {
  document: string;
  manifest: any;
  digest: string;
  providerId: string;
}

/** Parse and verify a signed manifest; return its digest. */
export function verifyManifest(
  document: string,
  expectedProviderId?: string
): VerifiedManifest {
  const manifest = parseStrict(document) as any;
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new CcpError("invalid_request", "manifest must be an object");
  }
  const providerId = manifest.provider?.id;
  if (typeof providerId !== "string") {
    throw new CcpError("invalid_request", "manifest provider.id is required");
  }
  if (expectedProviderId !== undefined && providerId !== expectedProviderId) {
    throw new CcpError("unauthenticated", "provider id does not match");
  }
  if (typeof manifest.signature !== "string") {
    throw new CcpError("invalid_request", "manifest signature is required");
  }
  const bytes = signingBytes(manifest);
  if (!verify(bytes, manifest.signature, publicBytesFromKeyId(providerId))) {
    throw new CcpError("unauthenticated", "manifest signature is invalid");
  }
  return { document, manifest, digest: digestBytes(bytes), providerId };
}

export interface VerifiedSignal {
  document: string;
  signal: any;
}

const SIGNAL_FIELDS = [
  "ccp",
  "request_id",
  "grant_digest",
  "intent",
  "params",
  "issued_at",
  "expires_at",
  "signature",
];

/** Parse and verify a signed signal against the sender's public key. */
export function verifySignal(
  document: string,
  publicKey: Uint8Array
): VerifiedSignal {
  const signal = parseStrict(document) as any;
  if (signal === null || typeof signal !== "object" || Array.isArray(signal)) {
    throw new CcpError("invalid_request", "signal must be an object");
  }
  for (const field of SIGNAL_FIELDS) {
    if (!(field in signal)) {
      throw new CcpError("invalid_request", `signal missing ${field}`);
    }
  }
  if (!verify(signingBytes(signal), signal.signature, publicKey)) {
    throw new CcpError("unauthenticated", "signal signature is invalid");
  }
  return { document, signal };
}

export interface PermissionCard {
  who: string;
  what: string;
  dataRead: string[];
  where: string;
  egress: string;
  effects: string;
  recurrence: string;
  revoke: string;
}

export interface PermissionCardOptions {
  providerName?: string;
  dataRead?: string[];
  where?: string;
  effects?: string;
  recurrence?: "once" | "future";
  revoke?: string;
}

/** Build the plain-language permission card for an intent (§11.4). */
export function permissionCard(
  manifest: any,
  intent: string,
  options: PermissionCardOptions = {}
): PermissionCard {
  const definition = manifest.intents?.[intent];
  if (!definition) {
    throw new CcpError("intent_not_allowed", `unknown intent ${intent}`);
  }
  const who =
    options.providerName ??
    manifest.provider?.name ??
    manifest.provider?.id ??
    "unknown";
  const placement = definition.placement ?? "local";
  const network = definition.data_egress?.network === true;
  const fields: string[] = definition.data_egress?.fields ?? [];
  return {
    who,
    what: definition.description ?? intent,
    dataRead: options.dataRead ?? [...(definition.required_capabilities ?? [])],
    where: options.where ?? (placement === "local" ? "on this device" : `via ${placement}`),
    egress: network
      ? `sends ${fields.join(", ") || "declared fields"} to a remote endpoint`
      : "does not send data off the device",
    effects: options.effects ?? "no external side effect declared",
    recurrence:
      options.recurrence === "future" ? "applies to future requests" : "applies once",
    revoke: options.revoke ?? "you can revoke this grant at any time",
  };
}
