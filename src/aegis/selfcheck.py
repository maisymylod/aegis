"""Deterministic crypto and mTLS self-checks shown in the demo.

These run fully offline and prove the command-authentication and network layers
directly (independent of the agent harness).
"""
from __future__ import annotations

from dataclasses import dataclass

from .crypto import CommandVerifier, build_hierarchy
from .crypto.envelope import CommandEnvelope
from .net import MtlsMaterial, mutual_handshake

_T0 = 1_700_000_000.0


@dataclass(frozen=True)
class Check:
    label: str
    expected: str
    actual: str
    ok: bool


def crypto_checks() -> list[Check]:
    clock = lambda: _T0  # noqa: E731
    h = build_hierarchy(clock=clock, nonce_factory=iter([f"c{i}" for i in range(99)]).__next__)
    signer = h.signers["gs-canberra"]
    valid = signer.sign("enter_safe_mode", "HEL-0004")

    def reason(env: CommandEnvelope, verifier: CommandVerifier | None = None) -> str:
        verifier = verifier or CommandVerifier(h.registry, clock=clock)
        return verifier.verify(env).reason

    checks = [
        Check("valid command", "ok", reason(valid), True),
        Check("forged signature", "rejected", "rejected" if reason(valid.with_signature("00" * 64)) == "bad_signature" else "accepted", reason(valid.with_signature("00" * 64)) == "bad_signature"),
        Check("unsigned command", "rejected", "rejected" if reason(valid.with_signature("")) == "unsigned" else "accepted", reason(valid.with_signature("")) == "unsigned"),
        Check("tampered command", "rejected", "rejected" if reason(CommandEnvelope.from_dict({**valid.to_dict(), "command": "self_destruct"})) == "bad_signature" else "accepted", reason(CommandEnvelope.from_dict({**valid.to_dict(), "command": "self_destruct"})) == "bad_signature"),
    ]
    # replay: same verifier sees the nonce twice
    v = CommandVerifier(h.registry, clock=clock)
    first = v.verify(valid).reason
    second = v.verify(valid).reason
    checks.append(Check("replayed command", "rejected", "rejected" if (first == "ok" and second == "replay") else "accepted", first == "ok" and second == "replay"))
    # rotation revokes the old key
    old = signer.sign("monitor", "HEL-1")
    h.rotate("gs-canberra", clock=clock, nonce_factory=iter([f"r{i}" for i in range(9)]).__next__)
    rotated = CommandVerifier(h.registry, clock=clock).verify(old).reason
    checks.append(Check("revoked (rotated) key", "rejected", "rejected" if rotated == "revoked_key" else "accepted", rotated == "revoked_key"))
    return checks


def mtls_checks() -> list[Check]:
    material = MtlsMaterial.generate()
    ok = mutual_handshake(material, present_client_cert=True)
    bad = mutual_handshake(material, present_client_cert=False)
    return [
        Check("certified client", "accepted", "accepted" if ok.ok else "rejected", ok.ok),
        Check("uncertified client", "rejected", "rejected" if not bad.ok else "accepted", not bad.ok),
    ]
