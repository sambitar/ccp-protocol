"""Side-effect state machine per CCP Working Draft v0.3 §26.3.

The prose renders the machine as a mermaid state diagram:

    [*] --> received
    received --> authorized
    authorized --> awaiting_confirmation : confirmation required
    authorized --> executing             : no confirmation
    awaiting_confirmation --> executing  : approved
    awaiting_confirmation --> cancelled  : denied
    executing --> completed
    executing --> failed
    executing --> cancelled
    executing --> outcome_unknown

The vector file names the events for the unlabeled edges and the initial
entry, so we map those names onto the diagram edges here. ``start`` is the
mermaid ``[*]`` initial pseudo-state.
"""

from __future__ import annotations

TRANSITIONS = {
    ("start", "arrive"): "received",
    ("received", "validate_ok"): "authorized",
    ("authorized", "confirmation_required"): "awaiting_confirmation",
    ("authorized", "no_confirmation"): "executing",
    ("awaiting_confirmation", "approved"): "executing",
    ("awaiting_confirmation", "denied"): "cancelled",
    ("executing", "succeeded"): "completed",
    ("executing", "failed"): "failed",
    ("executing", "cancelled"): "cancelled",
    ("executing", "outcome_lost"): "outcome_unknown",
}


def transition(from_state: str, event: str) -> str | None:
    """Return the destination state, or ``None`` if the edge is undefined."""
    return TRANSITIONS.get((from_state, event))
