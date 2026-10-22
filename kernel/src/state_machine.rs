//! The §26.3 side-effect state machine.

/// Return the state after `event`; `None` is the start pseudo-state.
pub fn next_state(state: Option<&str>, event: &str) -> Result<&'static str, String> {
    let from = match state {
        Some("start") | None => None,
        Some(other) => Some(other),
    };
    let to = match (from, event) {
        (None, "arrive") => "received",
        (Some("received"), "validate_ok") => "authorized",
        (Some("authorized"), "confirmation_required") => "awaiting_confirmation",
        (Some("authorized"), "no_confirmation") => "executing",
        (Some("awaiting_confirmation"), "approved") => "executing",
        (Some("awaiting_confirmation"), "denied") => "cancelled",
        (Some("executing"), "succeeded") => "completed",
        (Some("executing"), "failed") => "failed",
        (Some("executing"), "cancelled") => "cancelled",
        (Some("executing"), "outcome_lost") => "outcome_unknown",
        _ => return Err(format!("no transition from {:?} on {}", from, event)),
    };
    Ok(to)
}
