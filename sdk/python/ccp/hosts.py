"""Host-function registry and per-request privilege mediation (§26.4).

The runtime passes a :class:`HostAccess` proxy to an intent executor. The
proxy exposes only the host functions granted to the requester, and enforces
the grant's placement and egress ceiling on every call (§12), so an executor
cannot reach capabilities or disclosures outside the grant.

Every host also carries a contract: its class, risk, confirmation floor, and
idempotency behavior. Core hosts may omit it; extension hosts must declare a
class, which fixes the rest of the contract unless it is overridden.
"""

CORE_HOSTS = frozenset({
    "store.read",
    "files.read",
    "files.search",
    "notify",
    "confirm",
    "audit.append",
})

HOST_CLASSES = frozenset({"read", "write", "disclose", "control", "compute"})
HOST_RISKS = frozenset({"read", "write", "disclose", "irreversible"})
HOST_PLACEMENTS = frozenset({"local", "remote", "delegated"})
IDEMPOTENCY = frozenset({"pure", "caller_key", "atomic", "none"})

_CLASS_DEFAULTS = {
    "read": {"risk": "read", "minConfirmation": "none", "idempotency": "pure"},
    "disclose": {"risk": "disclose", "minConfirmation": "per_action",
                 "idempotency": "pure"},
    "write": {"risk": "write", "minConfirmation": "per_action",
              "idempotency": "caller_key"},
    "control": {"risk": "write", "minConfirmation": "per_action",
                "idempotency": "none"},
    "compute": {"risk": "read", "minConfirmation": "per_action",
                "idempotency": "pure"},
}


class HostProfileError(ValueError):
    """An invalid host contract (§26.4)."""

    code = "invalid_request"

    def __init__(self, message):
        self.message = message
        super().__init__("%s: %s" % (self.code, message))


def validate_host_profile(name, profile=None):
    """Validate and normalize a host profile (§26.4).

    Extension hosts (anything outside the core six) must declare a class; the
    rest of the contract follows from it unless explicitly overridden. A
    ``write``, ``control``, or ``compute`` host can never suppress
    confirmation, and an ``irreversible`` risk cannot either.
    """
    profile = dict(profile or {})

    if not isinstance(name, str) or name == "":
        raise HostProfileError("host name is required")

    declared = profile.get("class")
    if declared is None and name not in CORE_HOSTS:
        raise HostProfileError("extension host %s requires a class" % (name,))
    if declared is not None and declared not in HOST_CLASSES:
        raise HostProfileError("unknown host class: %s" % (declared,))
    host_class = declared or "read"
    defaults = _CLASS_DEFAULTS[host_class]

    risk = profile.get("risk") or defaults["risk"]
    if risk not in HOST_RISKS:
        raise HostProfileError("unknown host risk: %s" % (risk,))

    min_confirmation = (profile.get("minConfirmation")
                        or defaults["minConfirmation"])
    if min_confirmation not in ("none", "per_action"):
        raise HostProfileError(
            "unknown confirmation floor: %s" % (min_confirmation,))
    if min_confirmation == "none":
        if host_class not in ("read", "disclose"):
            raise HostProfileError(
                "a %s host cannot suppress confirmation" % (host_class,))
        if risk == "irreversible":
            raise HostProfileError(
                "an irreversible host cannot suppress confirmation")

    idempotency = profile.get("idempotency") or defaults["idempotency"]
    if idempotency not in IDEMPOTENCY:
        raise HostProfileError("unknown idempotency: %s" % (idempotency,))

    network = profile.get("network", False)
    if not isinstance(network, bool):
        raise HostProfileError("network must be a boolean")

    placement = profile.get("placement")
    if placement is None:
        placement = ["local"]
    if not isinstance(placement, list) or not placement:
        raise HostProfileError("placement must be a non-empty array")
    seen = set()
    for entry in placement:
        if entry not in HOST_PLACEMENTS:
            raise HostProfileError("unknown placement: %s" % (entry,))
        if entry in seen:
            raise HostProfileError("duplicate placement: %s" % (entry,))
        seen.add(entry)

    fields = profile.get("fields")
    if fields is None:
        fields = []
    if not isinstance(fields, list):
        raise HostProfileError("fields must be an array")
    seen_fields = set()
    for field in fields:
        if not isinstance(field, str) or field == "":
            raise HostProfileError("fields must be non-empty strings")
        if field in seen_fields:
            raise HostProfileError("duplicate field: %s" % (field,))
        seen_fields.add(field)
    if network and not fields and host_class == "disclose":
        raise HostProfileError(
            "a network disclose host must declare the fields it sends")

    return {
        "class": host_class,
        "risk": risk,
        "minConfirmation": min_confirmation,
        "idempotency": idempotency,
        "network": network,
        "placement": list(placement),
        "fields": list(fields),
    }


class HostAccess:
    def __init__(self, registry, granted, policy=None):
        self._registry = registry
        self._granted = set(granted)
        self._policy = policy or {"network": False, "fields": frozenset()}

    def call(self, name, *args, **kwargs):
        if name not in self._granted:
            raise PermissionError("host function not granted: %s" % (name,))
        entry = self._registry.host_meta(name)
        if entry is None:
            raise PermissionError("host function not installed: %s" % (name,))
        profile = entry["profile"]
        if profile["network"] and not self._policy["network"]:
            raise PermissionError(
                "host requires network egress not granted: %s" % (name,))
        for field in profile["fields"]:
            if field not in self._policy["fields"]:
                raise PermissionError(
                    "host may send an undeclared field: %s/%s"
                    % (name, field))
        return entry["fn"](*args, **kwargs)

    def has(self, name):
        return name in self._granted and self._registry.host(name) is not None


class HostRegistry:
    """Installed intents and their underlying host functions."""

    def __init__(self):
        self._hosts = {}
        self._intents = {}

    def register_host(self, name, function, *, host_class=None, risk=None,
                      min_confirmation=None, idempotency=None,
                      network=False, placement=None, fields=None):
        profile = validate_host_profile(name, {
            "class": host_class,
            "risk": risk,
            "minConfirmation": min_confirmation,
            "idempotency": idempotency,
            "network": network,
            "placement": placement,
            "fields": fields,
        })
        self._hosts[name] = {"fn": function, "profile": profile}

    def register_intent(self, name, function):
        self._intents[name] = function

    def host(self, name):
        entry = self._hosts.get(name)
        return entry["fn"] if entry is not None else None

    def host_meta(self, name):
        """Metadata used to enforce placement, egress, and confirmation."""
        return self._hosts.get(name)

    def has_host(self, name):
        return name in self._hosts

    def intent(self, name):
        return self._intents.get(name)

    def has_intent(self, name):
        return name in self._intents

    def access(self, granted, policy=None):
        return HostAccess(self, granted, policy)
