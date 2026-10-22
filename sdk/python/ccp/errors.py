"""Typed error codes and exceptions for CCP (§10.4)."""

AUTHORIZED = "authorized"
CONFIRMATION_REQUIRED = "confirmation_required"

#: Rejection codes from §10.4. ``confirmation_required`` is a transient
#: success, not a rejection, and is handled separately.
ERROR_CODES = frozenset({
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
})


class CCPError(Exception):
    """An error carrying one of the §10.4 codes."""

    def __init__(self, code, message=""):
        if code not in ERROR_CODES:
            raise ValueError("unknown CCP error code: %r" % (code,))
        self.code = code
        self.message = message
        detail = "%s: %s" % (code, message) if message else code
        super().__init__(detail)
