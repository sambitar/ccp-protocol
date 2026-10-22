"""Host-function registry and per-request privilege mediation (§26.4).

The runtime passes an :class:`HostAccess` proxy to an intent executor. The
proxy exposes only the host functions granted to the requester, so an
executor cannot reach capabilities outside the grant.
"""


class HostAccess:
    def __init__(self, registry, granted):
        self._registry = registry
        self._granted = set(granted)

    def call(self, name, *args, **kwargs):
        if name not in self._granted:
            raise PermissionError("host function not granted: %s" % (name,))
        function = self._registry.host(name)
        if function is None:
            raise PermissionError("host function not installed: %s" % (name,))
        return function(*args, **kwargs)

    def has(self, name):
        return name in self._granted and self._registry.host(name) is not None


class HostRegistry:
    """Installed intents and their underlying host functions."""

    def __init__(self):
        self._hosts = {}
        self._intents = {}

    def register_host(self, name, function):
        self._hosts[name] = function

    def register_intent(self, name, function):
        self._intents[name] = function

    def host(self, name):
        return self._hosts.get(name)

    def has_host(self, name):
        return name in self._hosts

    def intent(self, name):
        return self._intents.get(name)

    def has_intent(self, name):
        return name in self._intents

    def access(self, granted):
        return HostAccess(self, granted)
