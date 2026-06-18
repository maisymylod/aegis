"""Optional command-authority service (requires the `service` extra).

Exposes the signing and verification of the uplink command path over HTTP so
groundstation can have its approved commands signed and the core can verify them.
Self-contained; integrates with a live groundstation when GROUNDSTATION_API is set.

    uvicorn aegis.service:app --port 8600
"""
from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from . import __version__
from .integration import CommandAuthority

app = FastAPI(title="aegis-command-authority", version=__version__)
_authority = CommandAuthority()


class SignRequest(BaseModel):
    command: str
    target: str
    params: dict | None = None


class VerifyRequest(BaseModel):
    envelope: dict


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "ground_station": "gs-canberra"}


@app.post("/sign")
def sign(req: SignRequest) -> dict:
    return {"envelope": _authority.sign_command(req.command, req.target, req.params)}


@app.post("/verify")
def verify(req: VerifyRequest) -> dict:
    return _authority.verify_command(req.envelope)
