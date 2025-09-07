# qsh Protocol Specification (v1)

QuicShell (qsh) is a modern secure remote shell protocol, designed as a successor to SSH. This document describes version 1 of the wire protocol and expected server behavior.

Clarifications Incorporated (2025-09): This revision folds in normative decisions from the clarification log. Where prior drafts differed, this text prevails. Features explicitly marked Future / Stage ≥2 are NOT required for baseline v1 interoperability.

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

Fixed suite: no negotiation and no algorithm identifiers on the wire (implicit by ALPN + version).

Key Encapsulation (Hybrid KEM)
* X25519 + ML-KEM-768 (canonical label: ML-KEM-768). Concatenate shared secrets without length prefixes:
	`combined_kem_secret = x25519_shared || mlkem_shared`.
* HKDF-Extract(SHA-384) input = combined_kem_secret. Salt is the label where shown below.

Signatures (Hybrid, host & user)
* Ed25519 + ML-DSA-44 (canonical label: ML-DSA-44). Both signatures MUST verify.

HKDF-SHA-384 Labels (HKDF-Expand with explicit L):
* "qsh v1 hs" (handshake secret)
* "qsh v1 app" (application traffic root)
* "qsh v1 exp" (exporter interface)
* "qsh v1 confirm" (confirm key seed; directional)
* "qsh v1 ch root" (per-channel root)
* "qsh v1 ch rekey" (channel key chaining)

AEAD
* XChaCha20-Poly1305 for channel payloads and confirm tags.
* 192-bit nonce = 128-bit prefix (per channel,direction,rekey-epoch) || 64-bit counter.

Directional Keys
* Derive distinct c2s and s2c keys; do not rely on nonce partitioning alone.

Rekeying (Per Direction)
* Trigger after 1 MiB plaintext sent OR 30 s since last rekey (whichever first).
* Chaining:
	`k_ch' = HKDF-Expand(k_ch, "qsh v1 ch rekey" || uint64(counter), key_len)` where counter starts at 0.
* Forward secrecy window limited to last interval.

Confirm Tags
* `client_confirm` / `server_confirm` are AEAD tags over transcript_hash with empty plaintext, AAD = transcript_hash.
* Keys:
	`confirm_key_client = HKDF-Expand(hs_secret, "qsh v1 confirm client", 32)`
	`confirm_key_server = HKDF-Expand(hs_secret, "qsh v1 confirm server", 32)`
	Nonce = 24 zero bytes.

Exporter
* `export(bytes L, context) = HKDF-Expand(app_secret, "qsh v1 exp" || context, L)` with L ≤ 256.

0-RTT
* Not supported. Resumption tickets (OPTIONAL, Stage 3) still require fresh hybrid KEM.

Forbidden Deviations
* No alternative algorithms, no negotiation extensions under `qshq/1` or `qsht/1`.
* Nonce construction and chaining MUST match this spec.

⸻

## 4. Identity & Trust


	•	Host identity
	•	Static hybrid signing key pinned on first connect (TOFU-plus).
	•	Rotation: new key must be signed by old key.
	•	User identity
	•	Authorized hybrid keys (authorized_keys equivalent), or
	•	Short-lived user certs (10–60 min) signed by a qsh-CA.
	•	No passwords, PAM, or policy engines. Privilege enforcement is the host’s job.

When a CA is configured, the server MAY disable `authorized_keys` and require `user_cert_chain`. This is a deployment choice and does not affect the wire protocol.

⸻

## 5. Handshake Flow

All handshake messages are deterministic (canonical) CBOR maps (RFC 8949 §4.2.1). Keys are text strings (v1); unknown keys are ignored (forward compat). Optional padding is an explicit `pad` field (byte string) and is EXCLUDED from transcript hashing.

### 5.1 Messages

HELLO (client → server)
```
{
	v: 1,
	kem_client_ephemeral: { x25519_pub: bstr, mlkem_pub: bstr },
	client_nonce: bstr(32),
	capabilities: ["EXEC","TTY"],  # v1 mandatory baseline in canonical (lexicographic) order
	pad?: bstr
}
```
Capabilities are advisory; unknown ones are ignored. Ordering MUST be canonical to reduce fingerprinting.

ACCEPT (server → client)
```
{
	kem_server_ephemeral: { x25519_pub: bstr, mlkem_pub: bstr },
	host_cert_chain: [bstr, ...],      # array even if length 1
	server_nonce: bstr(32),
	ticket_params?: { lifetime_s: uint, max_uses: 1 },  # Stage 3 indicator
	revocation_policy?: "none" | "soft" | "hard"  # optional hint, ignored by v1 clients
	pad?: bstr
}
```
Presence of `ticket_params` signals ticket support. Omission = no resumption.

Presence of `revocation_policy` is advisory and optional. Clients that do not understand it ignore it. It allows enterprises to signal CA-driven revocation expectations without breaking v1 interoperability.

FINISH_CLIENT (client → server)
```
{
	kem_ciphertexts: { mlkem_ct: bstr },
	user_auth: { raw_keys: { ed25519_pub: bstr, mldsa44_pub: bstr }, sig: { ed25519: bstr, mldsa44: bstr } }
					 | { user_cert_chain: [bstr,...], sig: { ed25519: bstr, mldsa44: bstr } },
	client_confirm: bstr,  # AEAD tag
	pad?: bstr
}
```
Exactly one user auth method present. Signature covers transcript hash only.

FINISH_SERVER (server → client)
```
{
	server_confirm: bstr,        # AEAD tag
	resumption_ticket?: bstr,    # Stage 3 optional
	pad?: bstr
}
```

### 5.2 Key Schedule & Transcript
```
hs_secret      = HKDF-Extract(SHA-384, combined_kem_secret, "qsh v1 hs")
app_secret     = HKDF-Expand(hs_secret, "qsh v1 app", L_app)
export_secret  = HKDF-Expand(hs_secret, "qsh v1 exp", L_exp)
confirm_keys   = HKDF-Expand(hs_secret, "qsh v1 confirm {client|server}", 32)
ch_root[i]     = HKDF-Expand(app_secret, "qsh v1 ch root" || encode_varint(stream_id), L_root)
```
Channel directional keys derived from `ch_root[i]` (details §6.3).

Transcript hash bytes:
```
transcript_hash = SHA-384( canon_cbor(HELLO_no_pad) ||
							canon_cbor(ACCEPT_no_pad) ||
							canon_cbor(FINISH_CLIENT_no_pad) )
```
Padding excluded. ALPN token and transport (QUIC vs TCP) affect context via distinct outer conditions and are thereby bound. Unknown keys (ignored semantically) still appear in canonical CBOR and are thus bound.

⸻

## 6. Channels

Multiplex multiple logical channels per connection.
* QUIC: each bidirectional stream (even=client init, odd=server) is a channel; stream 0 MAY carry control only.
* TCP fallback (Stage 2): single TLS connection with QUIC varint framed substreams.

### 6.1 Channel Types

v1 required: TTY (interactive shell), EXEC (single command). EXEC exit status reported via CTRL EXIT.
Future: QFTP (minimal file protocol multiplexed within one channel), PFWD (port forwarding, direction field).

### 6.2 Control / Data Frames (deterministic CBOR)

OPEN { id, kind, cmd?, env?, winsize?, pad? }
ACCEPT { id, features, initial_window }
REJECT { id, code, reason? }
DATA { id, seq, ciphertext }         # seq uint64 (wrap modulo 2^64)
CTRL { id, signal, payload? }        # signals: WINCH, SIGINT, EOF, CLOSE, WINDOW_UPDATE, EXIT
REKEY_REQ { id, counter }
REKEY_ACK { id, counter }

WINDOW_UPDATE uses CTRL with payload { delta: uint64 } (delta bytes additional credit). EXIT carries payload { code: int, msg?: text }.
OPEN.cmd max 256 bytes UTF-8 NFC. Environment constraints §8.

### 6.3 Rekeying

Per direction triggers (1 MiB OR 30 s). Either peer may initiate on threshold crossing. Race: if both send REKEY_REQ concurrently, lower channel id wins; other discards.

Procedure:
1. Initiator sends REKEY_REQ { counter = next } under old key.
2. Receiver derives tentative new key via chaining, replies REKEY_ACK.
3. Both switch after ACK; old-key DATA accepted until all seq < cutover_seq consumed.

Chaining:
`k_ch' = HKDF-Expand(k_ch, "qsh v1 ch rekey" || uint64(counter), key_len)`

Nonce counters reset to 0 post rekey. If ACK not received within 500 ms, retransmit; after (RECOMMENDED) 3 attempts, close channel with DECRYPT_FAIL. ≥3 consecutive DECRYPT_FAIL closures escalate to connection drop.

⸻

## 7. Error Handling & Codes

Errors encoded as integers referencing a registry. Suggested symbolic mapping:
Connection: PROTOCOL_ERROR, BAD_IDENTITY (on-wire indistinguishable from generic failure for privacy), REPLAY, TIMEOUT.
Channel: PERMISSION_DENIED, NO_SUCH_CMD, RESOURCE_LIMIT, DECRYPT_FAIL.

After PROTOCOL_ERROR client SHOULD attempt fallback transport once. ≥3 consecutive DECRYPT_FAIL channel closures triggers connection termination. BAD_IDENTITY indistinguishable on-wire from generic failure.

⸻

## 8. Encoding, Padding, Environment & Privacy

Deterministic CBOR: definite-length maps, canonical key ordering, reject non-canonical encodings.
Unknown keys ignored (forward compat) yet bound by transcript hash.

Padding: Optional `pad` field (byte string). Adaptive distribution among {1,2,4} KiB bucket sizes RECOMMENDED (non-uniform if improves cover traffic). Padding excluded from transcript hash.

Environment Variable Sanitization:
* Names MUST match `[A-Z0-9_]{1,64}` (ASCII). Reject control chars / NUL.
* Values ≤ 4096 bytes, UTF-8 NFC.
* Duplicate names or disallowed names → reject entire env set.
* Server MAY whitelist additional patterns (config `AllowClientEnv`).
* Disallowed baseline (MUST strip or reject): `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `SSH_AUTH_SOCK`, `GIT_SSH`, `GIT_SSH_COMMAND` (list may expand in implementation docs).

Capabilities: advisory; ordering fixed (lexicographic). Unknown ignored.

Keepalives: Encrypted keepalive (empty DATA/CTRL) every 30 s RECOMMENDED for TTY smoothing.

Privacy Logging Modes: `privacy-minimal` (no client IP for successful sessions), `standard` (IP:port), `enterprise` (IP:port+CIDR tags). Failed auth/security events SHOULD always log source IP (auditing / fail2ban). Provide hashing/redaction options.

Length Limits:
* Handshake (pre-padding) < 2 KiB target.
* OPEN.cmd ≤ 256 bytes.
* Env var count ≤ 64.
* (Future QFTP) path length ≤ 512 bytes.

⸻

## 9. Operational Defaults & Limits

Ports: 22/UDP (QUIC), 22/TCP (fallback). Attempt QUIC; if no ACCEPT within 300–500 ms, start TCP.
QUIC params (RECOMMENDED defaults): max_idle_timeout=30s, initial_max_data=1 MiB, initial_max_streams_bidi=100.
Rekey thresholds: 1 MiB / 30 s per direction.
Resumption tickets (Stage 3): single-use, default lifetime 600 s, target size ≤512 bytes, bound to (user key hash, host key fingerprint, ALPN, nonces, capabilities, timestamp). Server tracks nonces until expiry (replay prevention).
Memory cap unauthenticated connection ≤256 KiB.
Logging: JSON lines with canonical field order (e.g. time, level, path, user?, host, rtt_ms, addr?).

⸻

## 10. Future Extensions (Non-Normative)

QFTP (minimal file subsystem) – new capability string `QFTP`.
PFWD (port forwarding) – capability `PFWD` with direction/address fields.
Host key rotation object: `{ new_host_key, old_host_key_signature, valid_from? }` (overlap grace window). If old key compromised without signature, out-of-band re-bootstrap required.
Resumption tickets (Stage 3) as in §9.
Transparency logs for host key pinning.
Post-quantum-only mode via new ALPN (e.g. `qshq/1-pq`).
Reserved CBOR keys for v2+ extensions (ignore unknown under v1).
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
Directional sub-keys derived from channel root; forward-secret chaining narrows exposure window.

### Hybrid Cryptography
- **KEM:** X25519 + ML-KEM-768  
- **Signatures:** Ed25519 + ML-DSA-44  
- Both halves must verify/derive successfully.  
- Hybrid mode ensures security even if one algorithm family is broken in the future.

### Transcript Binding
Hybrid signatures + confirm tags bind canonical CBOR of HELLO/ACCEPT/FINISH_CLIENT (excluding padding) plus implicit ALPN & transport context preventing downgrade/cross-protocol confusion.

### Host Key Continuity
TOFU-plus pinning. Rotation (Stage 3) requires signed rotation object; absence => hard fail.

### Authorized Keys
- Users authenticate with raw hybrid keys listed in `authorized_keys`.  
- Revocation is handled by removing entries from this file.  
- No passwords or interactive prompts are allowed.

### Preface and Legacy Rejects
- On TCP connections, servers send a fixed preface string (`QSH1\n`) and nothing else until a valid HELLO is received.  
- This causes legacy SSH clients to fail fast and avoids silent timeouts.  
- No dynamic error messages are sent, to reduce fingerprinting surface.

### Deterministic Encoding
Non-canonical CBOR MUST be rejected. Unknown keys ignored but still bound.

### Padding and Privacy
Adaptive bucket padding and 30 s encrypted keepalives recommended. Capability ordering fixed (lexicographic) to reduce fingerprinting variability.

### Replay & Nonce Handling
FINISH replay detection via stored nonces/tickets (single-use). Nonce counters reset on rekey.

### Environment Security
Strict sanitization prevents injection of dynamic loader / toolchain variables (`LD_PRELOAD`, etc.). Duplicates rejected to eliminate ambiguity.

### Forbidden Changes
Implementations MUST NOT: add negotiable cipher lists, disable rekeying, permit 0-RTT app data, accept non-deterministic CBOR, or modify nonce/key schedule. Doing so breaks interoperability/security.

**Note:** Future versions (e.g., qsh v2) may define different suites; v1 MUST follow this specification exactly.

---

12. License

This specification and reference implementation are released under the MIT License.

⸻

13. Author

Maintained by @haukened (David Haukeness).