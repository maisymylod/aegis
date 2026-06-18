"""Cryptographic command authentication for the uplink path."""
from __future__ import annotations

from dataclasses import dataclass

from ..config import GROUND_STATION_SEEDS, ROOT_KEY_SEED
from .chain import CertificateAuthority, KeyCertificate, KeyRegistry, make_key_id
from .envelope import CommandEnvelope, CommandSigner
from .keys import KeyPair
from .verifier import CommandVerifier, VerificationResult


@dataclass
class KeyHierarchy:
    """An offline root CA, a verifier registry, and per-ground-station signers."""

    authority: CertificateAuthority
    registry: KeyRegistry
    signers: dict[str, CommandSigner]
    versions: dict[str, int]

    def rotate(self, ground_station_id: str, **signer_kwargs) -> str:
        """Issue a new key version for a ground station; revoke the old key id."""
        old_version = self.versions[ground_station_id]
        old_key_id = make_key_id(ground_station_id, old_version)
        new_version = old_version + 1
        seed = GROUND_STATION_SEEDS[ground_station_id] + bytes([new_version])
        keypair = KeyPair.from_seed(seed)
        cert = self.authority.issue(ground_station_id, keypair, new_version)
        self.registry.add(cert)
        self.registry.revoke(old_key_id)
        self.versions[ground_station_id] = new_version
        self.signers[ground_station_id] = CommandSigner(
            keypair, cert.key_id, ground_station_id, **signer_kwargs
        )
        return cert.key_id


def build_hierarchy(**signer_kwargs) -> KeyHierarchy:
    """Build the demo key hierarchy from the deterministic config seeds."""
    root = KeyPair.from_seed(ROOT_KEY_SEED)
    authority = CertificateAuthority(root)
    registry = KeyRegistry(authority.root_public_hex)
    signers: dict[str, CommandSigner] = {}
    versions: dict[str, int] = {}
    for gs_id, seed in GROUND_STATION_SEEDS.items():
        keypair = KeyPair.from_seed(seed + bytes([1]))
        cert = authority.issue(gs_id, keypair, 1)
        registry.add(cert)
        signers[gs_id] = CommandSigner(keypair, cert.key_id, gs_id, **signer_kwargs)
        versions[gs_id] = 1
    return KeyHierarchy(authority, registry, signers, versions)


__all__ = [
    "KeyHierarchy",
    "build_hierarchy",
    "CertificateAuthority",
    "KeyRegistry",
    "KeyCertificate",
    "CommandEnvelope",
    "CommandSigner",
    "CommandVerifier",
    "VerificationResult",
    "KeyPair",
]
