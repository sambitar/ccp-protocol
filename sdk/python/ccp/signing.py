"""Helpers for signing CCP documents."""

from . import canonical


def sign_document(value, signing_key):
    """Return the canonical wire form of ``value`` signed by ``signing_key``.

    The value is a mapping; any existing ``signature`` key is replaced.
    """
    value = dict(value)
    value.pop("signature", None)
    value["signature"] = signing_key.sign(canonical.signing_bytes_of(value))
    return canonical.serialize(value)
