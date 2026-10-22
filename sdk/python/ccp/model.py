"""Protocol data models: Manifest, Grant, Signal, Decision."""

from dataclasses import asdict, dataclass, field

from . import canonical, crypto
from .errors import AUTHORIZED, CONFIRMATION_REQUIRED, CCPError


@dataclass
class Decision:
    """The outcome of submitting or confirming a signal."""

    outcome: str
    request_id: str | None = None
    pending_id: str | None = None
    result: object = None
    error: str | None = None
    detail: str | None = None
    state: str | None = None

    @property
    def authorized(self):
        return self.outcome == AUTHORIZED

    @property
    def needs_confirmation(self):
        return self.outcome == CONFIRMATION_REQUIRED

    @property
    def rejected(self):
        return self.outcome not in (AUTHORIZED, CONFIRMATION_REQUIRED)


class Manifest:
    """A signed provider manifest (§8)."""

    def __init__(self, document, data):
        self.document = document
        self.data = data
        self._signing_input = canonical.signing_bytes(document)

    @classmethod
    def parse(cls, document):
        data = canonical.parse_strict(document)
        if not isinstance(data, dict):
            raise CCPError("invalid_request", "manifest must be a JSON object")
        for name in ("ccp", "provider", "version", "intents", "signature"):
            if name not in data:
                raise CCPError("invalid_request", "manifest missing %r" % (name,))
        if not isinstance(data["provider"], dict) or "id" not in data["provider"]:
            raise CCPError("invalid_request", "manifest provider.id is required")
        if not isinstance(data["intents"], dict):
            raise CCPError("invalid_request", "manifest intents must be an object")
        return cls(document, data)

    @property
    def provider_id(self):
        return self.data["provider"]["id"]

    @property
    def provider_name(self):
        return self.data["provider"].get("name")

    @property
    def version(self):
        return self.data["version"]

    @property
    def intents(self):
        return self.data["intents"]

    @property
    def signature(self):
        return self.data["signature"]

    @property
    def signing_input(self):
        return self._signing_input

    @property
    def digest(self):
        """`sha256:<hex>` over the canonical signing bytes (§26.1)."""
        return canonical.digest_bytes(self._signing_input)

    def intent_spec(self, name):
        return self.intents.get(name)

    def verify(self, expected_provider_id=None):
        """Verify the manifest signature; raise CCPError on failure."""
        if expected_provider_id is not None and self.provider_id != expected_provider_id:
            raise CCPError("unauthenticated", "provider id does not match")
        key = crypto.VerifyingKey.from_key_id(self.provider_id)
        if not key.verify(self._signing_input, self.signature):
            raise CCPError("unauthenticated", "manifest signature is invalid")
        return True


@dataclass
class Grant:
    """The consumer's local authorization record (§26.1)."""

    id: str
    requester_key: str
    contact_id: str
    manifest_digest: str
    manifest_version: int
    intents: list = field(default_factory=list)
    limits: dict = field(default_factory=dict)
    created_at: str = ""
    expires_at: str = ""
    confirmation: dict = field(default_factory=dict)
    capabilities: list = field(default_factory=list)
    placement: list = field(default_factory=list)
    egress: dict = field(default_factory=dict)
    state: str = "active"
    state_reason: str | None = None

    def is_active(self, now):
        return self.state == "active" and now < self.expires_at

    def pause(self, reason=None):
        if self.state in ("revoked", "expired"):
            raise CCPError("invalid_request", "cannot pause a %s grant" % self.state)
        self.state = "paused"
        self.state_reason = reason

    def suspend(self, reason=None):
        if self.state in ("revoked", "expired"):
            raise CCPError("invalid_request", "cannot suspend a %s grant" % self.state)
        self.state = "suspended"
        self.state_reason = reason

    def resume(self):
        if self.state not in ("paused", "suspended"):
            raise CCPError("invalid_request", "cannot resume a %s grant" % self.state)
        self.state = "active"
        self.state_reason = None

    def revoke(self, reason=None):
        self.state = "revoked"
        self.state_reason = reason

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


class Signal:
    """A signed request to invoke one intent (§10.1)."""

    FIELDS = ("ccp", "request_id", "grant_digest", "intent", "params",
              "issued_at", "expires_at", "signature")

    def __init__(self, document, data):
        self.document = document
        self.data = data
        self._signing_input = canonical.signing_bytes(document)

    @classmethod
    def parse(cls, document):
        data = canonical.parse_strict(document)
        if not isinstance(data, dict):
            raise CCPError("invalid_request", "signal must be a JSON object")
        for name in cls.FIELDS:
            if name not in data:
                raise CCPError("invalid_request", "signal missing %r" % (name,))
        return cls(document, data)

    @property
    def request_id(self):
        return self.data["request_id"]

    @property
    def intent(self):
        return self.data["intent"]

    @property
    def params(self):
        return self.data["params"]

    def verify(self, verifying_key):
        if not verifying_key.verify(self._signing_input, self.data["signature"]):
            raise CCPError("unauthenticated", "signal signature is invalid")
        return True
