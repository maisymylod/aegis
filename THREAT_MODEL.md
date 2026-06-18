# Threat Model — Heliosnet uplink / downlink and command path

Scope: the path from the mission-ops copilot (`groundstation`) through a ground
station to the spacecraft, and the telemetry path back. aegis defends the
**command path** and the **agent's trust in telemetry**. Spacecraft flight
software is out of scope.

## Assets

- **Command authority.** The ability to cause a satellite to act
  (`reset_adcs`, `failover_downlink`, `enter_safe_mode`). Highest-value asset.
- **Agent integrity.** The mission-ops agents' reasoning must reflect real
  telemetry and approved policy, not attacker-injected instructions.
- **Operational data.** Telemetry, fleet state, and any secrets in the agent's
  context.

## Trust boundaries

```
 spacecraft ──downlink──▶ ground station ──mTLS──▶ core / groundstation agents
      ▲                                                     │
      └──────────── uplink (signed commands) ◀──────────────┘
```

1. **Downlink / telemetry → agent context.** Telemetry is *attacker-influençable*
   data (a spoofed or tampered downlink). It must never be treated as trusted
   instructions. → indirect prompt injection.
2. **Ground station ↔ core.** Network link; must be mutually authenticated and
   confidential. → mTLS.
3. **Agent → uplink command.** A command leaving the approval gate must be
   authenticated end to end so a forged or replayed command cannot reach a
   spacecraft. → Ed25519 signed envelopes + replay protection.

## Adversaries and mitigations

| Threat | Vector | Mitigation (aegis) |
|---|---|---|
| Forged command | Attacker crafts a command envelope | Ed25519 signature over the envelope; verified against a key that chains to the offline root |
| Altered command | Tamper a valid command in flight | Signature covers all command fields; any change invalidates it |
| Replayed command | Re-send a previously valid command | Per-command nonce + freshness window; a seen nonce or stale timestamp is rejected |
| Compromised ground-station key | Stolen signing key | Key rotation issues a new versioned cert and revokes the old key id |
| Unauthenticated peer on the link | Rogue client/server | mutual TLS (TLS 1.3, `CERT_REQUIRED` both sides) |
| Indirect prompt injection | Instructions hidden in telemetry the agent reads | Telemetry sanitizer strips imperative/instruction content before it enters agent context |
| Data exfiltration | Agent coaxed into emitting secrets | Output guard redacts known secret/credential patterns |
| Tool abuse | Agent driven to call disallowed tools or out-of-policy args | Tool-call policy denies tools and argument patterns outside the allowlist |

## Assumptions and non-goals

- The **offline root key** is generated and stored out of band (an HSM in a real
  deployment). In this repo it is derived from a fixed seed for reproducibility;
  that derivation is for the demo only and is stated in the README.
- aegis does not defend spacecraft flight software, RF-layer jamming, or supply
  chain. It defends the ground-segment command path and the agent's trust
  boundary.
- The defense stack is *measured*, not assumed: every defense is independently
  toggleable and its block rate is reported (see the scoreboard).
