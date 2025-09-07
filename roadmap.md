# QuicShell Roadmap

This roadmap outlines the anticipated development path for **qsh** (QuicShell).  
It reflects both the **protocol specification** and the **Rust reference implementation**.

---

## Stage 1: Foundation (MVP)

- [ ] **Core handshake**  
  - Hybrid KEM (X25519 + ML-KEM-768)  
  - Hybrid signatures (Ed25519 + ML-DSA-44)  
  - HKDF-SHA-384 with fixed label catalog  
  - Inner AEAD (XChaCha20-Poly1305) for confirms and channel data  

- [ ] **QUIC transport**  
  - ALPN `qshq/1`  
  - Control stream (ID 0) for handshake and channel management  
  - Data streams for channels  

- [ ] **Channel: TTY**  
  - Interactive shell session  
  - Basic control messages (`OPEN`, `ACCEPT`, `DATA`, `CTRL`, `CLOSE`)  
  - Per-channel rekey after 1 MiB or 30 s  

---

## Stage 2: Fallback & Multiplexing

- [ ] **TCP/TLS fallback**  
  - ALPN `qsht/1`  
  - SNI routing compatible with existing load balancers  
  - Logical stream multiplexer over TLS app data  
  - Shared codepath with QUIC for higher layers  

- [ ] **Channel: EXEC**  
  - Single command execution with return code  
  - ENV injection and signal handling  

- [ ] **Channel: SFTP**  
  - File transfer subsystem using independent channel  
  - Streaming transfers with rekey support  

---

## Stage 3: Advanced Features

- [ ] **Channel: PFWD**  
  - Secure port forwarding (local/remote)  
  - Capability-bound and independently keyed  

- [ ] **Resumption tickets**  
  - Single-use, bound to user key  
  - Short lifetime (e.g. 10 minutes)  
  - Always triggers a fresh KEM for forward secrecy  

- [ ] **Host key rotation**  
  - New host key signed by old key  
  - Clients auto-pin swap after successful rotation  

- [ ] **Audit logs (optional)**  
  - Per-channel MAC chaining for tamper-evident local logs  
  - Configurable log sink  

---

## Stage 4: Ecosystem & Spec Work

- [ ] **Formal CDDL schemas** for all handshake/control messages  
- [ ] **Interop test vectors** (Rust <-> other languages)  
- [ ] **State machine diagrams** for handshake and channel lifecycles  
- [ ] **Wire captures** with annotated transcripts  
- [ ] **Draft I-D style spec** for community review  

---

## Stage 5: Usability & Hardening

- [ ] **CLI tooling**  
  - `qsh` (client) with subcommands for connect, exec, copy  
  - `qshd` (daemon) with config for host key management and user auth  

- [ ] **Developer ergonomics**  
  - Example configs (`authorized_keys`, certs)  
  - Quickstart Docker image for testing  

- [ ] **Security hardening**  
  - Fuzzing parsers and channel logic  
  - Memory safety audits  
  - Timing side-channel checks  

- [ ] **Post-quantum only mode**  
  - Optional config to drop classical algorithms entirely once ecosystem matures  

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
