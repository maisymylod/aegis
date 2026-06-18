"""Mutual TLS for the ground-station to core link.

Builds a self-signed CA, issues server and client certificates (Ed25519, deterministic
from seeds), and constructs hardened SSLContexts that require *mutual*
authentication. A real loopback handshake proves a properly-certified client is
accepted and an uncertified one is rejected.
"""
from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from ..crypto.keys import KeyPair

# Fixed validity window keeps issued certs deterministic for the demo/tests.
_NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
_NOT_AFTER = datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc)

# TLS 1.2 ciphers are disabled below; we require TLS 1.3.


@dataclass(frozen=True)
class CertPair:
    cert_pem: bytes
    key_pem: bytes


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key_pem(kp: KeyPair) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return kp.private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def make_ca(seed: bytes = b"aegis-mtls-ca-seed-000000000000a") -> tuple[CertPair, KeyPair]:
    kp = KeyPair.from_seed(seed)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("aegis-ground-core-ca"))
        .issuer_name(_name("aegis-ground-core-ca"))
        .public_key(kp.public)
        .serial_number(1)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(kp.private, algorithm=None)
    )
    return CertPair(cert.public_bytes(serialization_pem()), _key_pem(kp)), kp


def issue(ca: KeyPair, ca_cert_pem: bytes, common_name: str, seed: bytes, serial: int) -> CertPair:
    kp = KeyPair.from_seed(seed)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(kp.public)
        .serial_number(serial)
        .not_valid_before(_NOT_BEFORE)
        .not_valid_after(_NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(ca.private, algorithm=None)
    )
    return CertPair(cert.public_bytes(serialization_pem()), _key_pem(kp))


def serialization_pem():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.PEM


@dataclass
class MtlsMaterial:
    ca: CertPair
    server: CertPair
    client: CertPair

    @classmethod
    def generate(cls) -> "MtlsMaterial":
        ca_pair, ca_key = make_ca()
        server = issue(ca_key, ca_pair.cert_pem, "core.heliosnet", b"aegis-mtls-server-seed-0000001s", 2)
        client = issue(ca_key, ca_pair.cert_pem, "gs-canberra", b"aegis-mtls-client-seed-0000001c", 3)
        return cls(ca=ca_pair, server=server, client=client)


def _write(tmp: Path, name: str, data: bytes) -> str:
    path = tmp / name
    path.write_bytes(data)
    return str(path)


def _context(purpose: ssl.Purpose, certs: CertPair, ca_pem: bytes, tmp: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if purpose == ssl.Purpose.CLIENT_AUTH else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # protocol hardening: TLS 1.3 only
    ctx.load_verify_locations(cadata=ca_pem.decode())
    ctx.verify_mode = ssl.CERT_REQUIRED  # both sides demand a valid peer cert
    ctx.load_cert_chain(
        _write(tmp, f"{purpose}.crt", certs.cert_pem),
        _write(tmp, f"{purpose}.key", certs.key_pem),
    )
    if purpose == ssl.Purpose.SERVER_AUTH:
        ctx.check_hostname = True
    return ctx


@dataclass(frozen=True)
class HandshakeResult:
    ok: bool
    peer_common_name: str | None
    error: str | None = None


def mutual_handshake(material: MtlsMaterial, present_client_cert: bool = True) -> HandshakeResult:
    """Run a real loopback mTLS handshake; return whether it succeeded.

    With ``present_client_cert=False`` the client offers no certificate, which a
    mutually-authenticated server must reject.
    """
    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        server_ctx = _context(ssl.Purpose.CLIENT_AUTH, material.server, material.ca.cert_pem, tmp)
        if present_client_cert:
            client_ctx = _context(ssl.Purpose.SERVER_AUTH, material.client, material.ca.cert_pem, tmp)
        else:
            client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            client_ctx.load_verify_locations(cadata=material.ca.cert_pem.decode())
            client_ctx.check_hostname = True

        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        port = lsock.getsockname()[1]
        result: dict[str, object] = {}

        def serve() -> None:
            try:
                conn, _ = lsock.accept()
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    peer = tls.getpeercert()
                    cn = _common_name(peer)
                    result["peer_cn"] = cn
                    tls.recv(16)
            except Exception as exc:  # noqa: BLE001  (negative path is expected)
                result["server_error"] = repr(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.send(b"hello")
            ok = True
            error = None
        except Exception as exc:  # noqa: BLE001
            ok = False
            error = repr(exc)
        finally:
            thread.join(timeout=5)
            lsock.close()

        if "server_error" in result:
            ok = False
            error = error or str(result["server_error"])
        return HandshakeResult(ok=ok, peer_common_name=result.get("peer_cn"), error=error)  # type: ignore[arg-type]


def _common_name(peer_cert: dict | None) -> str | None:
    if not peer_cert:
        return None
    for rdn in peer_cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None
