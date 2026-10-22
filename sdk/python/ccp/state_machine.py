"""The side-effect state machine (§26.3)."""

#: (from, event) -> to. ``None`` is the start pseudo-state.
TRANSITIONS = {
    (None, "arrive"): "received",
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

TERMINAL = frozenset({"completed", "failed", "cancelled", "outcome_unknown"})


def next_state(state, event):
    """Return the state after ``event``; raise ValueError if undefined."""
    if state == "start":
        state = None
    try:
        return TRANSITIONS[(state, event)]
    except KeyError:
        raise ValueError("no transition from %r on %r" % (state, event))


def reachable_states():
    states = set(TRANSITIONS.values())
    states.update(state for (state, _event) in TRANSITIONS if state is not None)
    return states
