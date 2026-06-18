"""Key certificates and the verifying chain.

An offline root key (held only by the CertificateAuthority) signs a certificate
for each ground-station signing key. Verifiers trust only the root *public* key
and validate that a command's signing key chains back to it. Rotation issues a
new versioned certificate; the old key id can be revoked.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .keys import KeyPair, public_from_hex, verify


@dataclass(frozen=True)
class KeyCertificate:
    key_id: str  # "<ground_station_id>:v<version>"
    ground_station_id: str
    public_key_hex: str
    version: int
    root_signature_hex: str = ""

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "key_id": self.key_id,
                "ground_station_id": self.ground_station_id,
                "public_key_hex": self.public_key_hex,
                "version": self.version,
            },
            sort_keys=True,
        ).encode("utf-8")

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "ground_station_id": self.ground_station_id,
            "public_key_hex": self.public_key_hex,
            "version": self.version,
            "root_signature_hex": self.root_signature_hex,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyCertificate":
        return cls(**d)


def make_key_id(ground_station_id: str, version: int) -> str:
    return f"{ground_station_id}:v{version}"


class CertificateAuthority:
    """Holds the offline root key and issues ground-station certificates."""

    def __init__(self, root: KeyPair) -> None:
        self._root = root

    @property
    def root_public_hex(self) -> str:
        return self._root.public_hex()

    def issue(self, ground_station_id: str, signing_key: KeyPair, version: int) -> KeyCertificate:
        cert = KeyCertificate(
            key_id=make_key_id(ground_station_id, version),
            ground_station_id=ground_station_id,
            public_key_hex=signing_key.public_hex(),
            version=version,
        )
        sig = self._root.sign(cert.signed_bytes())
        return KeyCertificate(
            key_id=cert.key_id,
            ground_station_id=cert.ground_station_id,
            public_key_hex=cert.public_key_hex,
            version=cert.version,
            root_signature_hex=sig.hex(),
        )


class KeyRegistry:
    """Trusts the root public key; tracks valid and revoked certificates."""

    def __init__(self, root_public_hex: str) -> None:
        self._root_public = public_from_hex(root_public_hex)
        self._certs: dict[str, KeyCertificate] = {}
        self._revoked: set[str] = set()

    def add(self, cert: KeyCertificate) -> None:
        if not self._chains_to_root(cert):
            raise ValueError(f"certificate {cert.key_id} does not chain to the trusted root")
        self._certs[cert.key_id] = cert

    def revoke(self, key_id: str) -> None:
        self._revoked.add(key_id)

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked

    def get(self, key_id: str) -> KeyCertificate | None:
        return self._certs.get(key_id)

    def _chains_to_root(self, cert: KeyCertificate) -> bool:
        if not cert.root_signature_hex:
            return False
        return verify(
            self._root_public, bytes.fromhex(cert.root_signature_hex), cert.signed_bytes()
        )

    def trusts(self, cert: KeyCertificate) -> bool:
        return self._chains_to_root(cert) and not self.is_revoked(cert.key_id)
