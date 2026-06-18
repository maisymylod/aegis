"""Ed25519 key material.

Keys are derived deterministically from seeds so the demo and tests reproduce
without bundling secret files. A real deployment would generate the root key in
an offline HSM and never derive it from a seed; this is called out in the README.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class KeyPair:
    private: Ed25519PrivateKey

    @classmethod
    def from_seed(cls, seed: bytes) -> "KeyPair":
        material = seed if len(seed) == 32 else hashlib.sha256(seed).digest()
        return cls(Ed25519PrivateKey.from_private_bytes(material))

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    def public_hex(self) -> str:
        return public_bytes(self.public).hex()

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


def public_bytes(key: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_from_hex(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def verify(public: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature

    try:
        public.verify(signature, message)
        return True
    except InvalidSignature:
        return False
