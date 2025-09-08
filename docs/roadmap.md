# QuicShell Roadmap

This roadmap outlines the anticipated development path for **qsh** (QuicShell).  
It reflects both the **protocol specification** and the **Rust reference implementation**.

---

## Stage 1: Foundation (MVP) — v1 Scope

- [ ] Core handshake (deterministic CBOR)  
  - Hybrid KEM (X25519 + ML-KEM-768)  
  - Hybrid signatures (Ed25519 + ML-DSA-44)  
  - HKDF-SHA-384 labels: hs, app, exp, confirm, ch root, ch rekey  
  - XChaCha20-Poly1305 for data + confirm tags  
- [ ] QUIC transport (ALPN `qshq/1`) even=client / odd=server streams  
- [ ] Channels: TTY + EXEC (EXIT status via CTRL EXIT)  
- [ ] Per-direction rekey (1 MiB / 30 s)  
- [ ] Environment sanitization & limits  
- [ ] Adaptive padding + 30 s encrypted keepalives  
- [ ] Error code registry & escalation rules  
- [ ] Exporter interface  
- [ ] Logging modes (privacy-minimal, standard, enterprise)  

---

## Stage 2: Fallback & Multiplexing

- [ ] TCP/TLS fallback (ALPN `qsht/1`) with QUIC-varint mux  
- [ ] Channel: QFTP (formerly SFTP) minimal file protocol (single channel multiplex)  
- [ ] Enhanced flow control tuning  

---

## Stage 3: Advanced Features

- [ ] Channel: PFWD (port forwarding)  
- [ ] Resumption tickets (single-use, 10 min default, fresh KEM)  
- [ ] Host key rotation (signed rotation object, grace overlap)  
- [ ] Audit logs (per-channel MAC chain)  
- [ ] Optional `revocation_policy` advisory hint ("none"|"soft"|"hard")  

---

## Stage 4: Ecosystem & Spec Work

- [ ] **Formal CDDL schemas** for all handshake/control messages  
- [ ] **Interop test vectors** (Rust <-> other languages)  
- [ ] **State machine diagrams** for handshake and channel lifecycles  
- [ ] **Wire captures** with annotated transcripts  
- [ ] **Draft I-D style spec** for community review  

---

## Stage 5: Usability & Hardening

- [ ] CLI tooling (`qsh`, `qshd`)  
- [ ] Example configs & quickstart image  
- [ ] Fuzzing priority: handshake CBOR, channel frames, rekey logic, TCP mux  
- [ ] Memory / timing audits (constant-time only for KEM + signatures)  
- [ ] Post-quantum only mode (new ALPN)  

---

## Stretch Goals

- [ ] **HTTP/2 CONNECT / WebSocket encapsulation** for ultra-restricted networks  
- [ ] **Minimal embedded server** for IoT environments  
- [ ] **GUI client** with session recording / replay  
- [ ] **Transparency log** for host key discovery and pinning proofs  

---

## Philosophy

QuicShell is designed to be:
- **Post-quantum secure by default**  
- **Minimal and auditable** (small spec, deterministic wire format)  
- **Transport-flexible** (QUIC-first, TCP fallback)  
- **Host-enforced privilege** (no central policy engine)  
- **Friendly to adoption** via MIT licensing and simple trust models  

---

## Author

Maintained by [@haukened](https://github.com/haukened) (David Haukeness).  
