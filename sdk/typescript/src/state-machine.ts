const TRANSITIONS: Record<string, string> = {
  "null:arrive": "received",
  "received:validate_ok": "authorized",
  "authorized:confirmation_required": "awaiting_confirmation",
  "authorized:no_confirmation": "executing",
  "awaiting_confirmation:approved": "executing",
  "awaiting_confirmation:denied": "cancelled",
  "executing:succeeded": "completed",
  "executing:failed": "failed",
  "executing:cancelled": "cancelled",
  "executing:outcome_lost": "outcome_unknown",
};

/** Return the state after `event`; throw if the transition is undefined. */
export function nextState(state: string | null, event: string): string {
  const from = state === "start" ? null : state;
  const next = TRANSITIONS[`${from}:${event}`];
  if (next === undefined) {
    throw new Error(`no transition from ${from} on ${event}`);
  }
  return next;
}
