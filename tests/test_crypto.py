from aegis.crypto import CommandVerifier, KeyRegistry, build_hierarchy
from aegis.crypto.chain import CertificateAuthority, KeyCertificate
from aegis.crypto.envelope import CommandEnvelope
from aegis.crypto.keys import KeyPair

T0 = 1000.0


def _hierarchy():
    nonces = iter(f"n{i}" for i in range(999))
    return build_hierarchy(clock=lambda: T0, nonce_factory=lambda: next(nonces))


def _verifier(h):
    return CommandVerifier(h.registry, clock=lambda: T0)


def test_valid_command_accepted():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("enter_safe_mode", "HEL-1")
    assert _verifier(h).verify(env).reason == "ok"


def test_forged_signature_rejected():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("enter_safe_mode", "HEL-1")
    assert _verifier(h).verify(env.with_signature("00" * 64)).reason == "bad_signature"


def test_unsigned_rejected():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    assert _verifier(h).verify(env.with_signature("")).reason == "unsigned"


def test_tampered_command_rejected():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    tampered = CommandEnvelope.from_dict({**env.to_dict(), "command": "self_destruct"})
    assert _verifier(h).verify(tampered).reason == "bad_signature"


def test_replay_rejected_on_second_use():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    v = _verifier(h)
    assert v.verify(env).reason == "ok"
    assert v.verify(env).reason == "replay"


def test_stale_command_rejected():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    late = CommandVerifier(h.registry, clock=lambda: T0 + 10_000)
    assert late.verify(env).reason == "stale"


def test_rotation_revokes_old_key():
    h = _hierarchy()
    old = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    nonces = iter(f"r{i}" for i in range(99))
    h.rotate("gs-canberra", clock=lambda: T0, nonce_factory=lambda: next(nonces))
    assert _verifier(h).verify(old).reason == "revoked_key"
    new = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    assert _verifier(h).verify(new).reason == "ok"


def test_untrusted_cert_rejected_by_registry():
    # A cert signed by a different "root" must not be accepted into the registry.
    real = build_hierarchy()
    rogue_root = KeyPair.from_seed(b"rogue-root-key-seed-000000000001")
    rogue_ca = CertificateAuthority(rogue_root)
    rogue_cert = rogue_ca.issue("gs-evil", KeyPair.from_seed(b"evil" * 8), 1)
    registry = KeyRegistry(real.authority.root_public_hex)
    try:
        registry.add(rogue_cert)
        assert False, "rogue cert should not chain to the trusted root"
    except ValueError:
        pass


def test_unknown_key_rejected():
    h = _hierarchy()
    env = h.signers["gs-canberra"].sign("monitor", "HEL-1")
    bad = CommandEnvelope.from_dict({**env.to_dict(), "key_id": "gs-nope:v9"})
    assert _verifier(h).verify(bad).reason in ("unknown_key", "bad_signature")
