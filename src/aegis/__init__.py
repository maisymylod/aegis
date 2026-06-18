"""aegis — the security layer for the Heliosnet ground system.

Cryptographic command authentication (Ed25519 signed envelopes, replay
protection, key rotation, a verifying chain to an offline root), mTLS for the
ground-to-core link, and an adversarial harness that attacks the mission-ops
agents and measures a toggleable defense stack.
"""

__version__ = "0.1.0"
