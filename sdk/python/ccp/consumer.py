"""Consumer role: verify inbound documents and build permission cards."""

from dataclasses import asdict, dataclass

from .errors import CCPError
from .model import Manifest, Signal


def verify_manifest(document, expected_provider_id=None):
    """Parse and verify a signed manifest (§8), returning the `Manifest`."""
    manifest = Manifest.parse(document)
    manifest.verify(expected_provider_id)
    return manifest


def verify_signal(document, verifying_key):
    """Parse and verify a signed signal (§10.1), returning the `Signal`."""
    signal = Signal.parse(document)
    signal.verify(verifying_key)
    return signal


@dataclass
class PermissionCard:
    """Plain-language permission card for a trusted UI (§11.4)."""

    who: str
    what: str
    data_read: list
    where: str
    egress: str
    effects: str
    recurrence: str
    revoke: str

    def to_dict(self):
        return asdict(self)


def permission_card(manifest, intent, *, provider_name=None, data_read=None,
                    where=None, effects=None, recurrence="once", revoke=None):
    """Build the §11.4 card for one intent of a verified manifest."""
    definition = (manifest.intents or {}).get(intent)
    if definition is None:
        raise CCPError("intent_not_allowed", "unknown intent %r" % (intent,))

    who = provider_name or manifest.provider_name or manifest.provider_id
    placement = definition.get("placement", "local")
    egress_spec = definition.get("data_egress") or {}
    network = egress_spec.get("network") is True
    fields = egress_spec.get("fields") or []

    if where is None:
        where = ("on this device" if placement == "local"
                 else "via %s" % placement)
    if network:
        egress = "sends %s to a remote endpoint" % (
            ", ".join(fields) or "declared fields")
    else:
        egress = "does not send data off the device"

    return PermissionCard(
        who=who,
        what=definition.get("description", intent),
        data_read=list(
            data_read if data_read is not None
            else definition.get("required_capabilities") or []
        ),
        where=where,
        egress=egress,
        effects=effects or "no external side effect declared",
        recurrence=("applies to future requests" if recurrence == "future"
                    else "applies once"),
        revoke=revoke or "you can revoke this grant at any time",
    )
