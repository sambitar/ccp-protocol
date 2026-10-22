import type { Decision } from "../runtime.js";

/**
 * HTTP status for a runtime decision. Shared by the HTTP adapters so a
 * provider gets the same semantics from Express and Next.
 */
export function httpStatusFor(decision: Decision): number {
  switch (decision.outcome) {
    case "authorized":
    case "confirmation_required":
      return 200;
    case "invalid_request":
      return 400;
    case "unauthenticated":
    case "no_matching_grant":
      return 403;
    default:
      return 409;
  }
}
