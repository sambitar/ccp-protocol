import type { JsonValue } from "./json.js";
import { isValid } from "./schema.js";

export interface DecisionContext {
  grant: any | null;
  signal: any;
  signer: string;
  now: string;
  seen: Set<string>;
  counters: Record<string, number>;
  intentSpec: any | null;
  paramsSchema: any | null;
  supportedCcp?: string | readonly string[];
}

export const DEFAULT_SUPPORTED_CCP = ["0.5-draft", "0.4-draft"] as const;

function isSupported(
  value: unknown,
  supported: string | readonly string[]
): boolean {
  const labels = typeof supported === "string" ? [supported] : supported;
  return typeof value === "string" && labels.includes(value);
}

/**
 * The pure §10.3 decision. Returns `authorized`,
 * `confirmation_required`, or a rejection code.
 */
export function decide(ctx: DecisionContext): string {
  const { grant, signal, signer, now, seen, counters } = ctx;
  const supported = ctx.supportedCcp ?? DEFAULT_SUPPORTED_CCP;

  if (!isSupported(signal.ccp, supported)) return "invalid_request";
  if (grant === null || grant === undefined) return "no_matching_grant";
  if (signer !== grant.requester_key) return "unauthenticated";
  if (signal.grant_digest !== grant.manifest_digest) return "no_matching_grant";

  if (grant.state === "revoked") return "grant_revoked";
  if (grant.state === "paused") return "grant_paused";
  if (grant.state === "suspended") return "grant_suspended";
  if (grant.state === "expired" || now >= grant.expires_at) {
    return "grant_expired";
  }

  const intent = signal.intent;
  if (!(grant.intents ?? []).includes(intent)) return "intent_not_allowed";

  if (
    ctx.intentSpec === null ||
    ctx.intentSpec === undefined ||
    ctx.paramsSchema === null ||
    ctx.paramsSchema === undefined
  ) {
    return "capability_unavailable";
  }
  if (!isValid(signal.params as JsonValue, ctx.paramsSchema)) {
    return "invalid_request";
  }

  if (now >= signal.expires_at) return "request_expired";
  if (seen.has(signal.request_id)) return "replay_detected";

  for (const [name, maximum] of Object.entries(grant.limits ?? {})) {
    if ((counters[name] ?? 0) + 1 > (maximum as number)) {
      return "limit_exceeded";
    }
  }

  const required: string[] = ctx.intentSpec.required_capabilities ?? [];
  const granted = new Set<string>(grant.capabilities ?? []);
  if (!required.every((capability) => granted.has(capability))) {
    return "capability_unavailable";
  }

  if (confirmationPolicy(grant, ctx.intentSpec, intent) === "per_action") {
    return "confirmation_required";
  }
  return "authorized";
}

export function confirmationPolicy(
  grant: any,
  intentSpec: any,
  intent: string
): string {
  const grantPolicy = (grant.confirmation ?? {})[intent];
  if (grantPolicy === "none" || grantPolicy === "per_action") {
    return grantPolicy;
  }
  const manifestPolicy = intentSpec.confirmation;
  if (manifestPolicy === "none" || manifestPolicy === "per_action") {
    return manifestPolicy;
  }
  return "per_action";
}
