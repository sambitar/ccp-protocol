"""Ed25519 (RFC 8032) + CCP key/signature encoding per §25.2.

* key identifier: ``key:ed25519:<base64url>`` of the 32-byte public key;
* signature field value: ``ed25519:<base64url>`` of the 64-byte signature;
* ``<base64url>`` is unpadded base64url (``+``/``/`` -> ``-``/``_``, no
  ``=`` padding).

The private input is the 32-byte RFC 8032 *seed*. Public-key derivation and
signing are delegated to the ``cryptography`` package (Ed25519 is
deterministic per RFC 8032, so no nonce is introduced).
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def derive_public_key(seed_hex: str) -> bytes:
    """Return the 32-byte public key for an RFC 8032 seed (hex)."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id(public_key: bytes) -> str:
    """``key:ed25519:<base64url>`` for a raw 32-byte public key."""
    return "key:ed25519:" + _b64url(public_key)


def sign(seed_hex: str, message: bytes) -> bytes:
    """Return the 64-byte Ed25519 signature of *message*."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return priv.sign(message)


def signature_field(signature: bytes) -> str:
    """``ed25519:<base64url>`` for a raw 64-byte signature."""
    return "ed25519:" + _b64url(signature)
