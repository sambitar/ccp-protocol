"""Requester role: build and sign manifests and signals."""

from .errors import CCPError
from .signing import sign_document

DEFAULT_CCP = "0.5-draft"


def build_manifest(provider, version, intents, *, ccp=DEFAULT_CCP):
    """Build the unsigned manifest mapping (§8)."""
    if not isinstance(provider, dict) or not provider.get("id"):
        raise CCPError("invalid_request", "provider.id is required")
    return {
        "ccp": ccp,
        "provider": dict(provider),
        "version": version,
        "intents": intents,
    }


def sign_manifest(provider, version, intents, signing_key, *,
                  ccp=DEFAULT_CCP):
    """Return a signed manifest in canonical wire form."""
    return sign_document(
        build_manifest(provider, version, intents, ccp=ccp), signing_key)


def build_signal(request_id, grant_digest, intent, params, issued_at,
                 expires_at, *, ccp=DEFAULT_CCP):
    """Build the unsigned signal mapping (§10.1)."""
    return {
        "ccp": ccp,
        "request_id": request_id,
        "grant_digest": grant_digest,
        "intent": intent,
        "params": params,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def sign_signal(request_id, grant_digest, intent, params, issued_at,
                expires_at, signing_key, *, ccp=DEFAULT_CCP):
    """Return a signed signal in canonical wire form."""
    return sign_document(
        build_signal(request_id, grant_digest, intent, params, issued_at,
                     expires_at, ccp=ccp),
        signing_key,
    )


class Requester:
    """A signing identity that produces manifests and signals."""

    def __init__(self, signing_key):
        self.signing_key = signing_key
        self.key_id = signing_key.key_id

    def manifest(self, provider, version, intents, *, ccp=DEFAULT_CCP):
        return sign_manifest(provider, version, intents, self.signing_key,
                             ccp=ccp)

    def signal(self, request_id, grant_digest, intent, params, issued_at,
               expires_at, *, ccp=DEFAULT_CCP):
        return sign_signal(request_id, grant_digest, intent, params,
                           issued_at, expires_at, self.signing_key, ccp=ccp)
