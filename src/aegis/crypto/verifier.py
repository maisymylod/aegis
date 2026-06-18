"""Command verification: the gate on the uplink command path.

A command is accepted only if its signature is valid, its key chains to the
trusted offline root, the key is not revoked, the timestamp is fresh, and the
nonce has not been seen before. Anything else is rejected with a reason code, so
an unsigned, forged, replayed, stale, or revoked-key command never passes.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from ..config import COMMAND_TTL_S
from .chain import KeyRegistry
from .envelope import CommandEnvelope
from .keys import public_from_hex, verify

# Reason codes (also used as security-event signals).
OK = "ok"
UNSIGNED = "unsigned"
BAD_SIGNATURE = "bad_signature"
UNKNOWN_KEY = "unknown_key"
UNTRUSTED_CHAIN = "untrusted_chain"
REVOKED_KEY = "revoked_key"
STALE = "stale"
REPLAY = "replay"


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: str

    @property
    def rejected(self) -> bool:
        return not self.valid


class CommandVerifier:
    def __init__(
        self,
        registry: KeyRegistry,
        *,
        ttl_s: int = COMMAND_TTL_S,
        clock: Callable[[], float] = time.time,
        skew_s: int = 5,
    ) -> None:
        self._registry = registry
        self._ttl = ttl_s
        self._clock = clock
        self._skew = skew_s
        self._seen_nonces: set[str] = set()

    def verify(self, envelope: CommandEnvelope) -> VerificationResult:
        if not envelope.signature_hex:
            return VerificationResult(False, UNSIGNED)

        cert = self._registry.get(envelope.key_id)
        if cert is None:
            return VerificationResult(False, UNKNOWN_KEY)
        if self._registry.is_revoked(envelope.key_id):
            return VerificationResult(False, REVOKED_KEY)
        if not self._registry.trusts(cert):
            return VerificationResult(False, UNTRUSTED_CHAIN)

        public = public_from_hex(cert.public_key_hex)
        try:
            signature = bytes.fromhex(envelope.signature_hex)
        except ValueError:
            return VerificationResult(False, BAD_SIGNATURE)
        if not verify(public, signature, envelope.signed_bytes()):
            return VerificationResult(False, BAD_SIGNATURE)

        now = self._clock()
        age = now - envelope.issued_at
        if age > self._ttl or age < -self._skew:
            return VerificationResult(False, STALE)

        # Replay check is last so a replayed-but-otherwise-valid command is
        # caught only once the nonce would actually be consumed.
        if envelope.nonce in self._seen_nonces:
            return VerificationResult(False, REPLAY)
        self._seen_nonces.add(envelope.nonce)

        return VerificationResult(True, OK)
