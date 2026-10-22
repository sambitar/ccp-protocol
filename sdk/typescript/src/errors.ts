export const AUTHORIZED = "authorized";
export const CONFIRMATION_REQUIRED = "confirmation_required";

/** Rejection codes from §10.4 (success outcomes are separate). */
export const ERROR_CODES: ReadonlySet<string> = new Set([
  "invalid_request",
  "unauthenticated",
  "no_matching_grant",
  "intent_not_allowed",
  "grant_expired",
  "grant_revoked",
  "grant_paused",
  "grant_suspended",
  "limit_exceeded",
  "request_expired",
  "replay_detected",
  "capability_unavailable",
  "execution_failed",
  "outcome_unknown",
]);

export class CcpError extends Error {
  readonly code: string;

  constructor(code: string, message = "") {
    if (!ERROR_CODES.has(code)) {
      throw new Error(`unknown CCP error code: ${code}`);
    }
    super(message ? `${code}: ${message}` : code);
    this.name = "CcpError";
    this.code = code;
  }
}
