import type { JsonValue } from "./json.js";
import type { Grant } from "./stores.js";
import { signSignal } from "./requester.js";
import { keyIdFromPublic, publicFromSeed } from "./crypto.js";

export interface ToolCall {
  intent: string;
  params: Record<string, JsonValue>;
}

export interface SignalIds {
  requestId: string;
  issuedAt: string;
  expiresAt: string;
  ccp?: string;
}

/** Wraps agent tool calls into signed, grant-bound signals. */
export class Agent {
  readonly publicKey: Uint8Array;
  readonly keyId: string;

  constructor(private readonly seed: Uint8Array) {
    this.publicKey = publicFromSeed(seed);
    this.keyId = keyIdFromPublic(this.publicKey);
  }

  signalFor(tool: ToolCall, grant: Grant, ids: SignalIds): string {
    return signSignal(
      {
        requestId: ids.requestId,
        grantDigest: grant.manifest_digest,
        intent: tool.intent,
        params: tool.params,
        issuedAt: ids.issuedAt,
        expiresAt: ids.expiresAt,
        ccp: ids.ccp,
      },
      this.seed
    );
  }
}

function isSubset(child: string[], parent: string[]): boolean {
  const allowed = new Set(parent);
  return child.every((item) => allowed.has(item));
}

function policyRank(policy: string | undefined): number {
  return policy === "per_action" ? 1 : 0;
}

/** True when `child` is no broader than `parent` (§15.1 attenuation). */
export function attenuates(parent: Grant, child: Grant): boolean {
  if (!isSubset(child.intents, parent.intents)) return false;
  if (!isSubset(child.capabilities, parent.capabilities)) return false;
  if (!isSubset(child.placement, parent.placement)) return false;
  if (child.expires_at > parent.expires_at) return false;

  for (const [name, maximum] of Object.entries(child.limits)) {
    if (maximum > (parent.limits[name] ?? 0)) return false;
  }

  const parentEgress = parent.egress ?? {};
  const childEgress = child.egress ?? {};
  if (childEgress.network === true && parentEgress.network !== true) return false;
  const parentFields = new Set(
    Array.isArray(parentEgress.fields) ? parentEgress.fields : []
  );
  const childFields = Array.isArray(childEgress.fields) ? childEgress.fields : [];
  if (!childFields.every((field) => parentFields.has(field))) return false;

  for (const intent of child.intents) {
    if (
      policyRank(child.confirmation?.[intent]) <
      policyRank(parent.confirmation?.[intent])
    ) {
      return false;
    }
  }

  return true;
}
