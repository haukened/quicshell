[![GitHub License](https://img.shields.io/github/license/haukened/quicshell?color=blue)](LICENSE)
[![Static Badge](https://img.shields.io/badge/TRL-3-red)](https://en.wikipedia.org/wiki/Technology_readiness_level)
[![Build](https://github.com/haukened/quicshell/actions/workflows/build.yaml/badge.svg)](https://github.com/haukened/quicshell/actions/workflows/build.yaml)
[![Codacy Quality Badge](https://app.codacy.com/project/badge/Grade/3115454a626a4b7c80cc524a91b964f1)](https://app.codacy.com/gh/haukened/quicshell/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)
[![Codacy Coverage Badge](https://app.codacy.com/project/badge/Coverage/3115454a626a4b7c80cc524a91b964f1)](https://app.codacy.com/gh/haukened/quicshell/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_coverage)

# QuicShell (qsh)

qsh is a modern secure remote shell, designed as a clean successor to SSHv2. The project is in the design & early implementation phase; this README is intentionally minimal and aimed at future users (not contributors).

## Why rethink SSH?

SSHv2 has served for decades, but several structural issues are hard to fix in-place:

1. Algorithm negotiation complexity creates downgrade / configuration risk.
2. One set of session keys stretches across all channels with infrequent rekeys.
3. TCP-only transport suffers head‑of‑line blocking and brittle network migration.
4. Ad‑hoc binary framing and sprawling extensions raise parsing & audit complexity.
5. Host key rotation is awkward; users either click through or get locked out.
6. Privacy signals (capability ordering, message sizing) are inconsistent.
7. Post‑quantum readiness requires bolt‑on patches instead of a coherent design.

## How qsh addresses this

qsh keeps the familiar user model (keys, TOFU, `qsh user@host`) while changing foundations:

* Fixed, modern hybrid cryptography (post‑quantum + classical) — no cipher negotiation.
* QUIC‑first transport with seamless TCP fallback for blocked UDP environments.
* Independent, frequently refreshed per‑channel (per direction) keys to narrow exposure windows.
* Deterministic, compact CBOR control messages for easier auditing and fuzzing.
* Explicit, signed host key rotation (“TOFU‑plus”) instead of silent trust shifts.
* Built‑in privacy measures (adaptive padding, canonical capability ordering).
* Versioned evolution (new ALPN for future modes) instead of in‑band option sprawl.

## Comparison

| Aspect | SSHv2 (today) | qsh v1 |
|--------|---------------|--------|
| **Crypto** | RSA / Ed25519 / Curve25519 (classical only) | **Hybrid post-quantum by default** (X25519 + ML-KEM-768, Ed25519 + ML-DSA-44) |
| **Key lifecycle** | One session key for all channels, rekey ~1GB/hour | **Per-channel, per-direction keys**; automatic rekey ≤1 MiB or 30 s (whichever first) |
| **Handshake** | Multi-roundtrip `KEXINIT`, cipher negotiation, downgrade risks | **Single 1-RTT handshake**, fixed suite (no negotiation) |
| **Transport** | TCP only → head-of-line blocking, fragile across NAT/Wi-Fi hops | **QUIC/UDP preferred** (multiplexing, migration, congestion control), **TCP fallback** |
| **Wire format** | Custom ad-hoc binary blobs, extension hell | **Deterministic CBOR maps**, simple, fuzzable, extensible |
| **Host trust** | TOFU `known_hosts`, awkward rotation | **TOFU-plus** (pinned hybrid keys, explicit signed rotations) |
| **Audit posture** | Optional session logging, weak tamper evidence | Planned option: **per-channel MAC chaining** (tamper-evident logs) |
| **Legacy behavior** | SSH to non-SSH service = confusing hangs | **Preface “QSH1” → fast fail** (“protocol mismatch”), predictable |

**Bottom line:**  
- For the user: looks and feels like SSH.  
- For the implementer/admin: a simpler spec, smaller attack surface, future-proof crypto, and better transport resilience.

## Current status

Planning & specification work are active. The reference implementation is **not yet ready for production use**. Interfaces and on‑disk formats may still change.

If you need a stable tool today: keep using SSH. Monitor this project if you care about a QUIC‑native, post‑quantum‑ready successor with a smaller, stricter spec.

## When might you switch later?

* You want lower latency interactive shells over variable networks.
* You need forward secrecy windows measured in seconds/megabytes, not hours/gigabytes.
* You operate in environments planning for post‑quantum migration.
* You prefer fixed suites (no negotiation spreadsheets) and simpler compliance narratives.

## Where are the details?

Deep technical definitions (message formats, key schedule, limits, staging) live in [`spec.md`](./docs/spec.md) and [`roadmap.md`](./docs/roadmap.md). This README intentionally defers those so it stays approachable.

## License

MIT — see `LICENSE`.

## Author

Created by @haukened (David Haukeness).

Project home: https://github.com/haukened/quicshell
