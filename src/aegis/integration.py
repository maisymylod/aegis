"""Integration with live groundstation / constellation (env-gated).

By default aegis runs fully self-contained. When GROUNDSTATION_API is set, the
command authority can wrap a command that groundstation's planner emitted (after
its human approval gate) in a signed envelope, and a verifier downstream rejects
anything unsigned, forged, or replayed. This mirrors groundstation's own
fixture-or-live pattern.
"""
from __future__ import annotations

from typing import Any

from .config import groundstation_api
from .crypto import CommandVerifier, KeyHierarchy, build_hierarchy
from .crypto.envelope import CommandEnvelope


class CommandAuthority:
    """Signs approved commands and verifies them on the uplink path."""

    def __init__(self, hierarchy: KeyHierarchy | None = None, ground_station_id: str = "gs-canberra"):
        self.hierarchy = hierarchy or build_hierarchy()
        self._gs = ground_station_id
        self.verifier = CommandVerifier(self.hierarchy.registry)

    def sign_command(self, command: str, target: str, params: dict[str, Any] | None = None) -> dict:
        envelope = self.hierarchy.signers[self._gs].sign(command, target, params or {})
        return envelope.to_dict()

    def verify_command(self, envelope: dict) -> dict:
        result = self.verifier.verify(CommandEnvelope.from_dict(envelope))
        return {"valid": result.valid, "reason": result.reason}

    def fetch_groundstation_proposal(self, sat_id: str) -> dict | None:
        """If a live groundstation is configured, run an investigation and sign
        the proposed command. Returns None when no endpoint is set."""
        api = groundstation_api()
        if not api:
            return None
        import httpx  # noqa: PLC0415

        proposal = httpx.post(f"{api}/investigate", json={"sat_id": sat_id}, timeout=30).json()
        cmd = proposal.get("proposed_command") or {}
        signed = self.sign_command(cmd.get("command", "monitor"), cmd.get("target", sat_id))
        return {"proposal": proposal, "signed_envelope": signed}
