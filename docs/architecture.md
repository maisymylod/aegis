# Architecture

`aegis` is the **security layer** of the Heliosnet ground system. It authenticates
the uplink command path, secures the ground-to-core link with mutual TLS, and
runs an adversarial harness that attacks the mission-ops agents and measures a
toggleable defense stack.

```
  groundstation                aegis command authority              spacecraft
  (approval gate) ── command ─▶  sign envelope (Ed25519) ─┐
                                                          │ mTLS (TLS 1.3)
                                                          ▼
                                              ┌────────────────────────┐
                                              │  CommandVerifier        │
                                              │  signature + chain +    │── reject ──▶ unsigned/
                                              │  freshness + nonce      │              forged/
                                              └───────────┬────────────┘              replayed/
                                                          │ accept                     revoked
                                                          ▼
                                                       uplink

  offline root key (CA)  ──signs──▶  per-ground-station key certs  ──▶  KeyRegistry
        (out of band)                  (rotation issues vN+1, revokes vN)

  Adversarial harness (seeded from gauntlet):
    corpus ──▶ ReferenceAgent ──through──▶ DefenseStack ──▶ oracle ──▶ scoreboard
                  (telemetry,                │  telemetry_sanitizer
                   tool calls,               │  tool_policy
                   output)                   │  output_guard
                                             │  command_auth
                                             ▼
                              security events ─▶ detector ─▶ incident report
```

## Command path (cryptographic authentication)

1. groundstation's planner proposes a command; a human approves it at the gate.
2. The ground station signs a `CommandEnvelope` (command, target, key id, fresh
   timestamp, unique nonce) with its Ed25519 key.
3. The `CommandVerifier` accepts it only if: the signature is valid, the signing
   key's certificate chains to the trusted **offline root**, the key is not
   revoked, the timestamp is fresh, and the nonce is unseen. Anything else is
   rejected with a reason code.
4. Key rotation issues a new versioned certificate and revokes the old key id.

## Network layer (mTLS)

A self-signed CA issues server and client certificates. Both ends require a valid
peer certificate (`CERT_REQUIRED`, TLS 1.3 only). A real loopback handshake proves
a certified client is accepted and an uncertified one is rejected.

## Adversarial harness

The harness (seeded from `gauntlet`) drives a reference mission-ops agent through
four attack classes, each with a deterministic success oracle:

| Class | Attack | Defended by |
|---|---|---|
| indirect_injection | instructions hidden in telemetry | telemetry_sanitizer |
| command_spoofing | forged / unsigned / tampered / replayed uplink | command_auth |
| exfiltration | agent coaxed to emit the system secret | output_guard |
| tool_abuse | agent calls a disallowed tool | tool_policy |

Each defense is independently toggleable, so the scoreboard reports its block
rate alone and the whole stack together. Every action emits a structured security
event; a detection pass and incident report sit on top.

## Determinism and backends

Keys derive from fixed seeds; the harness uses a fixed clock and deterministic
nonces; the crypto, replay, forgery, and mTLS results are fully deterministic.
The model-dependent classes (injection, exfiltration, tool abuse) run against the
recorded stub offline and against the real model when `ANTHROPIC_API_KEY` is set.
