# QuicShell (qsh)

**QuicShell (`qsh`)** is a next-generation secure remote shell protocol and reference implementation in Rust.  
It aims to be the spiritual successor to SSH, built on modern cryptography and transport:

- **QUIC-first** with multiplexed, low-latency streams.  
- **TCP/TLS fallback** with SNI routing for environments that block UDP.  
- **Post-quantum hybrid cryptography** by default (X25519 + ML-KEM, Ed25519 + ML-DSA).  
- **Per-channel rekey** for tighter forward secrecy and smaller compromise windows.  
- **Simple trust model**: host enforces privilege, users authenticate with hybrid keys or short-lived certs.  
- **Tiny, deterministic wire format** using CBOR for clarity and auditability.  
- **Memory-safe implementation**: Rust throughout.  

## Why qsh and not SSH?

qsh keeps the usability of SSH — keys in `authorized_keys`, TOFU for hosts, `qsh user@host` — but fixes structural problems that SSHv2 has carried for 25 years.

| Aspect | SSHv2 (today) | qsh v1 |
|--------|---------------|--------|
| **Crypto** | RSA / Ed25519 / Curve25519 (classical only) | **Hybrid post-quantum by default** (X25519 + ML-KEM, Ed25519 + Dilithium) |
| **Key lifecycle** | One session key for all channels, rekey ~1GB/hour | **Per-channel keys** with enforced rekey every 1 MiB / 30 s |
| **Handshake** | Multi-roundtrip `KEXINIT`, cipher negotiation, downgrade risks | **Single 1-RTT handshake**, no cipher negotiation, fixed safe suites |
| **Transport** | TCP only → head-of-line blocking, fragile across NAT/Wi-Fi hops | **QUIC/UDP preferred** (multiplexing, migration, congestion control), **TCP fallback** |
| **Wire format** | Custom ad-hoc binary blobs, extension hell | **Deterministic CBOR maps**, simple, fuzzable, extensible |
| **Host trust** | TOFU `known_hosts`, awkward rotation | **TOFU-plus** (pinned hybrid keys, explicit signed rotations) |
| **Audit posture** | Optional session logging, weak tamper evidence | Built-in option for **per-channel MAC chaining** (tamper-evident logs) |
| **Legacy behavior** | SSH to non-SSH service = confusing hangs | **Preface “QSH1” → fast fail** (“protocol mismatch”), predictable |

**Bottom line:**  
- For the user: looks and feels like SSH.  
- For the implementer/admin: a simpler spec, smaller attack surface, future-proof crypto, and better transport resilience.

---

## Features (planned / in progress)

- **Modern crypto stack**  
  - Hybrid KEM: X25519 + ML-KEM-768  
  - Hybrid signatures: Ed25519 + ML-DSA-44  
  - AEAD: XChaCha20-Poly1305  
  - HKDF-SHA-384 with strict domain labels  

- **Flexible transport**  
  - QUIC v1 (`ALPN=qshq/1`) preferred  
  - TLS 1.3/TCP fallback (`ALPN=qsht/1`)  
  - SNI routing compatible with load balancers  
  - Optional ECH to hide SNI  

- **Channel multiplexing**  
  - TTY (interactive shell)  
  - EXEC (single command)  
  - SFTP (file transfer)  
  - PFWD (port forwarding)  
  - Each channel rekeys independently (1 MiB / 30 s)  

- **Operational simplicity**  
  - Host keys: pinned on first contact (TOFU-plus), rotation signed by the old key  
  - User keys: authorized hybrid keys or short-lived certs  
  - No passwords, PAM, or policy engines—hosts enforce privilege  

- **Specification clarity**  
  - Deterministic CBOR maps for all control messages  
  - Single protocol version (`v=1`) with clear upgrade path  
  - Fixed KDF label catalog (`qsh v1 …`)  

---

## Roadmap

- [ ] MVP: QUIC transport, handshake, TTY channel  
- [ ] TCP/TLS fallback with logical stream mux  
- [ ] EXEC and SFTP channels  
- [ ] Port forwarding (PFWD)  
- [ ] Host key rotation & resumption tickets  
- [ ] Audit log with per-channel MAC chaining  
- [ ] Interop vectors and CDDL schema for handshake  

---

## Why MIT?

QuicShell is licensed under the [MIT License](./LICENSE) to maximize adoption across open-source and commercial environments.  
Like SSH before it, `qsh` is intended to become a universal building block for secure remote access.

---

## Author

Created by [@haukened](https://github.com/haukened) (David Haukeness).  

---

## Repository

<https://github.com/haukened/quicshell>
