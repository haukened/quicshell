markdown
// filepath: /Users/David.Haukeness/dev/quicshell/docs/roadmap.md
# QuicShell Roadmap

This roadmap outlines the anticipated development path for **qsh** (QuicShell).  
It reflects both the **protocol specification** and the **Rust reference implementation**.

---

## Stage 1: Foundation (MVP) — v1 Scope

- [x] Core handshake (deterministic CBOR: HELLO / ACCEPT / FINISH*, transcript hashing, pad stripping)
  - [x] Hybrid KEM (X25519 + ML-KEM-768) domain types (crypto ops/integration pending)
  - [x] Hybrid signatures (Ed25519 + ML-DSA-44) domain types (verification integration pending)
  - [x] HKDF-SHA-384 label scaffolding (transcript / constant usage present; full key schedule wiring TBD)
  - [ ] XChaCha20-Poly1305 for data + confirm tags
    - [x] AEAD port (`AeadSeal` trait, key/nonce newtypes)
    - [x] XChaCha20-Poly1305 adapter (16B salt + 8B seq -> 24B nonce) + unit tests
    - [x] Key schedule derivation (HKDF: directional AEAD keys + salts from transcript hash)
  - [x] Confirm tag sealing/verification using transcript AAD helpers
    - [ ] Directional nonce/sequence manager with reuse/overflow detection
    - [ ] Channel integration (wrap channel I/O in AEAD seal/open)
    - [ ] Rekey implementation (ADR-0009 chained HKDF; volume/time triggers)
    - [ ] Integration tests: full handshake -> encrypted payload + confirm tags
    - [x] Handshake FSM skeleton (state enum, role checks, transitions)
    - [x] FSM guards (role crossover prevention, no regression, enforced path)
  - [x] FSM transcript integration (absorb canonical CBOR, pad-stripped)
  - [x] FSM confirm-tag verification via AEAD adapter
    - [ ] FSM timeout / cancellation handling
    - [ ] FSM rekey orchestration (propose/ack/cutover states)
- [ ] QUIC transport (ALPN `qshq/1`) even=client / odd=server streams
- [ ] Channels: TTY + EXEC (EXIT status via CTRL EXIT)
- [ ] Per-direction rekey (1 MiB / 30 s)
- [ ] Environment sanitization & limits
- [~] Adaptive padding (handshake message pad field & stripping implemented; keepalive cadence not yet)
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