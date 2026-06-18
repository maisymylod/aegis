"""Signed command envelopes.

A command emitted by the mission-ops copilot (after its human approval gate) is
wrapped in an envelope, signed by a ground-station key. The signature covers the
command, target, issuing key, a fresh timestamp, and a unique nonce, so an
attacker cannot forge, alter, or replay it.
"""
from __future__ import annotations

import itertools
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .keys import KeyPair


@dataclass(frozen=True)
class CommandEnvelope:
    command: str
    target: str
    ground_station_id: str
    key_id: str
    issued_at: float
    nonce: str
    params: dict[str, Any] = field(default_factory=dict)
    signature_hex: str = ""

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "command": self.command,
                "target": self.target,
                "ground_station_id": self.ground_station_id,
                "key_id": self.key_id,
                "issued_at": self.issued_at,
                "nonce": self.nonce,
                "params": self.params,
            },
            sort_keys=True,
        ).encode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        d = {
            "command": self.command,
            "target": self.target,
            "ground_station_id": self.ground_station_id,
            "key_id": self.key_id,
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "params": self.params,
            "signature_hex": self.signature_hex,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CommandEnvelope":
        return cls(
            command=d["command"],
            target=d["target"],
            ground_station_id=d["ground_station_id"],
            key_id=d["key_id"],
            issued_at=d["issued_at"],
            nonce=d["nonce"],
            params=d.get("params", {}),
            signature_hex=d.get("signature_hex", ""),
        )

    def with_signature(self, signature_hex: str) -> "CommandEnvelope":
        return CommandEnvelope(
            command=self.command,
            target=self.target,
            ground_station_id=self.ground_station_id,
            key_id=self.key_id,
            issued_at=self.issued_at,
            nonce=self.nonce,
            params=dict(self.params),
            signature_hex=signature_hex,
        )


class CommandSigner:
    """Signs commands for one ground-station key.

    ``clock`` and ``nonce_factory`` are injectable so signing is deterministic in
    tests/demo; defaults use the wall clock and a unique token.
    """

    def __init__(
        self,
        signing_key: KeyPair,
        key_id: str,
        ground_station_id: str,
        *,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self._key = signing_key
        self._key_id = key_id
        self._gs = ground_station_id
        self._clock = clock
        self._counter = itertools.count(1)
        self._nonce_factory = nonce_factory or self._default_nonce

    def _default_nonce(self) -> str:
        import secrets

        return secrets.token_hex(12)

    def sign(
        self, command: str, target: str, params: dict[str, Any] | None = None
    ) -> CommandEnvelope:
        envelope = CommandEnvelope(
            command=command,
            target=target,
            ground_station_id=self._gs,
            key_id=self._key_id,
            issued_at=self._clock(),
            nonce=self._nonce_factory(),
            params=params or {},
        )
        return envelope.with_signature(self._key.sign(envelope.signed_bytes()).hex())
