from pathlib import Path

from fastapi.testclient import TestClient

from aegis.cli import main as cli_main
from aegis.integration import CommandAuthority
from aegis.service import app


def test_cli_demo_writes_artifacts(tmp_path: Path):
    rc = cli_main(["demo", "--out", str(tmp_path), "--run-id", "test"])
    assert rc == 0
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "incident.md").exists()
    assert (tmp_path / "events_on.jsonl").exists()


def test_cli_gate_passes_at_default_threshold():
    assert cli_main(["gate", "--threshold", "0.95"]) == 0


def test_cli_gate_fails_above_achievable():
    assert cli_main(["gate", "--threshold", "1.01"]) == 1


def test_service_sign_verify_roundtrip_and_forgery():
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    env = client.post("/sign", json={"command": "reset_adcs", "target": "HEL-9"}).json()["envelope"]
    assert client.post("/verify", json={"envelope": env}).json()["valid"] is True
    env["signature_hex"] = "00" * 64
    assert client.post("/verify", json={"envelope": env}).json()["valid"] is False


def test_integration_authority_offline_returns_none():
    # No GROUNDSTATION_API set -> fetch returns None (self-contained).
    authority = CommandAuthority()
    assert authority.fetch_groundstation_proposal("HEL-1") is None
