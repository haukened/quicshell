# qsh Protocol Specification (v1)

QuicShell (qsh) is a modern secure remote shell protocol, designed as a successor to SSH.
This document describes version 1 of the wire protocol and expected server behavior.

⸻

## 1. Ports & Transports

	•	Default ports
	•	22/UDP — preferred transport, qsh over QUIC (ALPN=qshq/1)
	•	22/TCP — fallback transport, qsh over TCP (ALPN=qsht/1)
	•	Client connection order
	1.	Attempt QUIC on UDP/22.
	2.	If no ACCEPT within ~300–500 ms, attempt TCP/22 in parallel.
	3.	First successful handshake wins; abort the other.

⸻

## 2. Legacy Compatibility

	•	On TCP connect, the server always sends the ASCII preface:
QSH1\n
	•	This causes legacy SSH clients to fail quickly with “Protocol mismatch.”
	•	After sending the preface, the server expects a qsh HELLO.
If none arrives or data is invalid within 2s, the server closes the connection.
	•	No other reject messages are sent. Constant behavior minimizes fingerprinting.

⸻

## 3. Cryptographic Suite (v1)

qsh v1 fixes the cryptographic suite. There is **no cipher negotiation**.  
All implementations must support the following algorithms:

- **Key Exchange (KEM)**  
  - Hybrid: `X25519` (ECDH) + `ML-KEM-768` (Kyber-768, NIST PQC)  
  - Combined via `HKDF-Extract(SHA-384)` over concatenated shared secrets

- **Signatures (host & user)**  
  - Hybrid: `Ed25519` + `ML-DSA-44` (Dilithium-2, NIST PQC)  
  - Both signatures must verify successfully

- **Key Derivation**  
  - `HKDF-SHA-384` with domain-separated labels:  
    - `"qsh v1 hs"` – handshake secret  
    - `"qsh v1 app"` – application traffic secret  
    - `"qsh v1 exp"` – exporter secret  
    - `"qsh v1 ch root"` – per-channel root key  
    - `"qsh v1 ch rekey"` – per-channel rekey

- **Encryption (symmetric)**  
  - `XChaCha20-Poly1305` (AEAD)  
  - 192-bit nonces avoid reuse across channels/rekeys

- **Rekeying**  
  - Each channel rekeys after **1 MiB** of traffic or **30 seconds**, whichever comes first  
  - Rekey derivation:  
    ```
    k_ch' = HKDF(k_ch, "qsh v1 ch rekey" || counter)
    ```

- **0-RTT**  
  - Not supported in v1  
  - Resumption tickets are single-use, short-lived, and always require a fresh KEM

**Rationale:**  
Fixing the suite eliminates downgrade attacks, simplifies the spec, and guarantees interoperability.  
Future updates (e.g., larger PQ parameters) will be released as new protocol versions (`qsh v2`), not as negotiable options within v1.

⸻

## 4. Identity & Trust

	•	Host identity
	•	Static hybrid signing key pinned on first connect (TOFU-plus).
	•	Rotation: new key must be signed by old key.
	•	User identity
	•	Authorized hybrid keys (authorized_keys equivalent), or
	•	Short-lived user certs (10–60 min) signed by a qsh-CA.
	•	No passwords, PAM, or policy engines. Privilege enforcement is the host’s job.

⸻

## 5. Handshake Flow

All handshake messages are CBOR maps, length-prefixed.

### 5.1 Messages

HELLO (client → server)

{
  v: 1,
  kem_client_ephemeral: { x25519_pub: bstr, mlkem_pub: bstr },
  client_nonce: bstr(32),
  capabilities: ["TTY","EXEC","SFTP","PFWD"]
}

ACCEPT (server → client)

{
  kem_server_ephemeral: { x25519_pub: bstr, mlkem_pub: bstr },
  host_cert_chain: [bstr, ...],
  server_nonce: bstr(32),
  ticket_params: { lifetime_s: uint, max_uses: 1 }
}

FINISH_CLIENT (client → server)

{
  kem_ciphertexts: { mlkem_ct: bstr },
  user_auth: { pubkey: bstr, sig: bstr } | { user_cert_chain: [bstr,...], sig: bstr },
  client_confirm: bstr
}

FINISH_SERVER (server → client)

{
  server_confirm: bstr,
  resumption_ticket?: bstr
}

### 5.2 Key Schedule

hs_secret    = HKDF-Extract(x25519_shared || mlkem_shared, "qsh v1 hs")
app_secret   = HKDF(hs_secret, "qsh v1 app")
export_secret= HKDF(hs_secret, "qsh v1 exp")
ch_root[i]   = HKDF(app_secret, "qsh v1 ch root" || stream_id)

	•	Transcript hash = SHA-384(HELLO || ACCEPT || FINISH_CLIENT)
	•	Both client and server sign the transcript hash with hybrid sigs.
	•	Confirms (client_confirm, server_confirm) are AEAD tags over transcript hash.

⸻

## 6. Channels

qsh multiplexes multiple channels per session.
	•	QUIC transport: each channel = QUIC stream
	•	TCP transport: minimal varint header mux, one TCP connection

### 6.1 Channel Types

	•	TTY — interactive shell
	•	EXEC — single command execution
	•	SFTP — file transfer subsystem
	•	PFWD — port forwarding

### 6.2 Control Frames

	•	OPEN { id, kind, cmd?, target?, env?, winsize? }
	•	ACCEPT { id, features, initial_window }
	•	REJECT { id, code, reason }
	•	DATA { id, seq, ciphertext } (AEAD-sealed)
	•	CTRL { id, signal } (WINCH, SIGINT, EOF, CLOSE, WINDOW_UPDATE)
	•	REKEY_REQ { id, counter } / REKEY_ACK { id, counter }

### 6.3 Rekeying

k_ch' = HKDF(k_ch, "qsh v1 ch rekey" || counter)

Unacked rekey → channel closure.

⸻

## 7. Error Handling

	•	Connection-level: PROTOCOL_ERROR, BAD_IDENTITY, REPLAY, TIMEOUT
	•	Channel-level: PERMISSION_DENIED, NO_SUCH_CMD, RESOURCE_LIMIT, DECRYPT_FAIL
	•	Any decrypt failure closes that channel; ≥3 such closures drop the whole connection.

⸻

## 8. Padding & Privacy

	•	Handshake messages padded to 1–2–4 KB buckets.
	•	Optional fixed-rate encrypted keepalives to blur idle TTY traffic.
	•	Usernames never sent in cleartext.

⸻

## 9. Operational Defaults

	•	Ports: 22/UDP (QUIC) and 22/TCP (fallback).
	•	Handshake timeout: 400 ms before racing TCP.
	•	Rekey: 1 MiB or 30 s.
	•	Resumption tickets: 10 min, single-use.
	•	Server logs one line per connect: {path=quic|tcp, user=..., host=..., rtt_ms=...}

⸻

## 10. Future Extensions

	•	QUIC-only fast path on 22/UDP.
	•	Transparency logs for host key pinning.
	•	Post-quantum-only mode (drop classical curves).
⸻

## 11. Security Considerations

qsh v1 is designed as a security-first replacement for SSH. This section documents the rationale behind key choices and highlights rules implementers must follow.

### No Cipher Negotiation
- qsh v1 defines a **fixed cryptographic suite** (see Section 3).  
- There is no negotiation of ciphers, hashes, or key sizes.  
- This eliminates downgrade attacks and ensures all compliant implementations interoperate.

### No 0-RTT
- Early data before key confirmation is disallowed.  
- Replay protection is simpler and stronger without 0-RTT.  
- Resumption tickets are supported, but they are **single-use, short-lived, and always require a fresh hybrid KEM**.

### Per-Channel Rekey
- Each channel derives its own sub-keys from the application secret.  
- Keys are rederived after **1 MiB** of traffic or **30 seconds**, whichever comes first.  
- This limits compromise impact: if one channel key is exposed, only a small traffic window is at risk.

### Hybrid Cryptography
- **KEM:** X25519 + ML-KEM-768  
- **Signatures:** Ed25519 + ML-DSA-44  
- Both halves must verify/derive successfully.  
- Hybrid mode ensures security even if one algorithm family is broken in the future.

### Transcript Binding
- All signatures and handshake confirms cover the **transcript hash**.  
- This prevents downgrade, replay, and MITM tampering of handshake parameters.

### Host Key Continuity
- First connection uses **TOFU-plus**: clients pin the host’s hybrid key.  
- Host rotation requires the new key to be signed by the old.  
- Clients must warn and refuse if rotation proof is absent.

### Authorized Keys
- Users authenticate with raw hybrid keys listed in `authorized_keys`.  
- Revocation is handled by removing entries from this file.  
- No passwords or interactive prompts are allowed.

### Preface and Legacy Rejects
- On TCP connections, servers send a fixed preface string (`QSH1\n`) and nothing else until a valid HELLO is received.  
- This causes legacy SSH clients to fail fast and avoids silent timeouts.  
- No dynamic error messages are sent, to reduce fingerprinting surface.

### Deterministic Encoding
- All control messages use **deterministic CBOR**.  
- Implementers must not accept non-canonical encodings.  
- This guarantees transcript stability for signatures and reduces parser ambiguity.

### Padding and Privacy
- Handshake messages should be padded to 1–2–4 KB buckets to obscure message lengths.  
- Implementations may add encrypted keepalives at regular intervals to reduce traffic fingerprinting.  
- Usernames and other identifiers must never appear in cleartext outside encrypted payloads.

### Forbidden Changes
- Implementations must not:
  - Offer alternative algorithms or allow cipher negotiation.  
  - Weaken or disable per-channel rekeying.  
  - Allow 0-RTT application data.  
  - Accept non-deterministic CBOR.  
- Such changes risk interoperability and security.

**Note:** This section documents the design intent of qsh v1. Future versions (e.g., qsh v2) may define different suites or transport rules, but v1 implementations must conform exactly to these requirements.

---

12. License

This specification and reference implementation are released under the MIT License.

⸻

13. Author

Maintained by @haukened (David Haukeness).