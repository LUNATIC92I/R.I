"""Envelope encryption.

Each object gets a random 256-bit data key (DEK). Content is encrypted with
AES-256-GCM under the DEK; the DEK is wrapped by a key-encryption key (KEK)
supplied by a :class:`KeyProvider`. The default provider derives KEKs from the
master key passed through the environment; production deployments should
plug an HSM or KMS (see ``docs/SECURITY.md``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class KeyProvider(Protocol):
    active_key_id: str

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]: ...

    def unwrap(self, key_id: str, wrapped: bytes, aad: bytes) -> bytes: ...


class LocalKeyProvider:
    """KEK derived from the master key with HKDF. Key id allows rotation."""

    def __init__(self, master_key: bytes, key_id: str = "local-v1", retired: dict[str, bytes] | None = None):
        self.active_key_id = key_id
        self._keys = {key_id: self._derive(master_key, key_id)}
        for kid, key in (retired or {}).items():
            self._keys[kid] = self._derive(key, kid)

    @staticmethod
    def _derive(master: bytes, key_id: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"aic-kek:{key_id}".encode()).derive(master)

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        nonce = os.urandom(12)
        return self.active_key_id, nonce + AESGCM(self._keys[self.active_key_id]).encrypt(nonce, dek, aad)

    def unwrap(self, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyError(f"Unknown key id {key_id}")
        return AESGCM(key).decrypt(wrapped[:12], wrapped[12:], aad)


@dataclass
class Sealed:
    key_id: str
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes


class Cipher:
    def __init__(self, provider: KeyProvider, master_key: bytes):
        self.provider = provider
        self._field_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"aic-field").derive(master_key)
        self._hmac_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"aic-hmac").derive(master_key)

    def seal(self, plaintext: bytes, aad: bytes) -> Sealed:
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
        key_id, wrapped = self.provider.wrap(dek, aad)
        return Sealed(key_id, wrapped, nonce, ciphertext)

    def open(self, sealed: Sealed, aad: bytes) -> bytes:
        dek = self.provider.unwrap(sealed.key_id, sealed.wrapped_key, aad)
        return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, aad)

    def encrypt_field(self, value: str) -> str:
        """Small secrets stored in columns (TOTP seeds, push tokens)."""
        nonce = os.urandom(12)
        data = AESGCM(self._field_key).encrypt(nonce, value.encode(), b"field")
        return base64.b64encode(nonce + data).decode()

    def decrypt_field(self, value: str) -> str:
        raw = base64.b64decode(value)
        return AESGCM(self._field_key).decrypt(raw[:12], raw[12:], b"field").decode()

    def keyed_hash(self, value: str) -> str:
        """Deterministic HMAC used for lookups on secrets (refresh tokens, IOC values)."""
        return hmac.new(self._hmac_key, value.encode(), hashlib.sha256).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
