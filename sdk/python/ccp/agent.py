"""Agent role: signed tool calls and attenuation-only delegation."""

from .requester import DEFAULT_CCP, sign_signal


class Agent:
    """A requester identity used by an AI agent for tool calls."""

    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.key_id = signing_key.key_id

    @property
    def verifying_key(self):
        return self.signing_key.verifying_key()

    def signal_for(self, *, intent, params, grant, request_id, issued_at,
                   expires_at, ccp=DEFAULT_CCP):
        """Sign one tool call against the grant's manifest digest."""
        return sign_signal(
            request_id, grant.manifest_digest, intent, params,
            issued_at, expires_at, self.signing_key, ccp=ccp,
        )


def _is_subset(child, parent):
    allowed = set(parent)
    return all(item in allowed for item in child)


def _policy_rank(policy):
    return 1 if policy == "per_action" else 0


def attenuates(parent, child):
    """True when ``child`` is no broader than ``parent`` (§15.1)."""
    if not _is_subset(child.intents, parent.intents):
        return False
    if not _is_subset(child.capabilities, parent.capabilities):
        return False
    if not _is_subset(child.placement, parent.placement):
        return False
    if child.expires_at > parent.expires_at:
        return False

    for name, maximum in (child.limits or {}).items():
        if maximum > (parent.limits or {}).get(name, 0):
            return False

    parent_egress = parent.egress or {}
    child_egress = child.egress or {}
    if child_egress.get("network") is True and parent_egress.get("network") is not True:
        return False
    parent_fields = set(parent_egress.get("fields") or [])
    child_fields = child_egress.get("fields") or []
    if not set(child_fields).issubset(parent_fields):
        return False

    parent_confirmation = parent.confirmation or {}
    child_confirmation = child.confirmation or {}
    for intent in child.intents:
        if _policy_rank(child_confirmation.get(intent)) < _policy_rank(
                parent_confirmation.get(intent)):
            return False

    return True
