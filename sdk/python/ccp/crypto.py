"""Ed25519 key and signature encoding per CCP §25.2."""

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KEY_PREFIX = "key:ed25519:"
SIG_PREFIX = "ed25519:"


class CryptoError(ValueError):
    pass


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def key_id_from_public_bytes(raw):
    return KEY_PREFIX + b64url_encode(raw)


def public_bytes_from_key_id(key_id):
    if not key_id.startswith(KEY_PREFIX):
        raise CryptoError("unsupported key identifier: %r" % (key_id,))
    return b64url_decode(key_id[len(KEY_PREFIX):])


class SigningKey:
    """A 32-byte RFC 8032 seed and its Ed25519 signer."""

    def __init__(self, private_key):
        self._key = private_key

    @classmethod
    def generate(cls):
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed):
        if len(seed) != 32:
            raise CryptoError("seed must be 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_bytes(self):
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def key_id(self):
        return key_id_from_public_bytes(self.public_bytes)

    def verifying_key(self):
        return VerifyingKey(self._key.public_key())

    def sign(self, message):
        """Return the signature field value `ed25519:<base64url>`."""
        return SIG_PREFIX + b64url_encode(self._key.sign(message))


class VerifyingKey:
    def __init__(self, public_key):
        self._key = public_key

    @classmethod
    def from_key_id(cls, key_id):
        raw = public_bytes_from_key_id(key_id)
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    @property
    def key_id(self):
        return key_id_from_public_bytes(
            self._key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def verify(self, message, signature_field):
        """Verify an `ed25519:<base64url>` signature over ``message``."""
        if not isinstance(signature_field, str) or not signature_field.startswith(SIG_PREFIX):
            raise CryptoError("unsupported signature encoding")
        raw = b64url_decode(signature_field[len(SIG_PREFIX):])
        try:
            self._key.verify(raw, message)
            return True
        except InvalidSignature:
            return False
