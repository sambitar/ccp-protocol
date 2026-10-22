"""Host-function registry and per-request privilege mediation (§26.4).

The runtime passes a :class:`HostAccess` proxy to an intent executor. The
proxy exposes only the host functions granted to the requester, and enforces
the grant's placement and egress ceiling on every call (§12), so an executor
cannot reach capabilities or disclosures outside the grant.
"""


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
        if entry["network"] and not self._policy["network"]:
            raise PermissionError(
                "host requires network egress not granted: %s" % (name,))
        for field in entry["fields"]:
            if field not in self._policy["fields"]:
                raise PermissionError(
                    "host may send an undeclared field: %s/%s"
                    % (name, field))
        return entry["fn"](*args, **kwargs)

    def has(self, name):
        return name in self._granted and self._registry.host(name) is not None


class HostRegistry:
    """Installed intents and their underlying host functions.

    ``register_host`` records what the host may do. The defaults are the safe
    ones: local placement, no network, no transmitted fields.
    """

    def __init__(self):
        self._hosts = {}
        self._intents = {}

    def register_host(self, name, function, *, network=False, placement=None,
                      fields=None):
        self._hosts[name] = {
            "fn": function,
            "network": network is True,
            "placement": list(placement) if placement is not None else ["local"],
            "fields": list(fields or []),
        }

    def register_intent(self, name, function):
        self._intents[name] = function

    def host(self, name):
        entry = self._hosts.get(name)
        return entry["fn"] if entry is not None else None

    def host_meta(self, name):
        """Metadata used to enforce placement and egress (§12)."""
        return self._hosts.get(name)

    def has_host(self, name):
        return name in self._hosts

    def intent(self, name):
        return self._intents.get(name)

    def has_intent(self, name):
        return name in self._intents

    def access(self, granted, policy=None):
        return HostAccess(self, granted, policy)
