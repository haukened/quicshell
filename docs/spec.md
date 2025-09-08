# qsh Protocol Specification (v1)

QuicShell (qsh) is a modern secure remote shell protocol, designed as a successor to SSH. This document describes version 1 of the wire protocol and expected server behavior.

⸻

## 1. Ports & Transports

- Default ports
- 22/UDP — preferred transport, qsh over QUIC (ALPN=qshq/1)
- 22/TCP — fallback transport, qsh over TCP (ALPN=qsht/1)
- Client connection order
  - Attempt QUIC on UDP/22.
  - If no ACCEPT within ~300–500 ms, attempt TCP/22 in parallel.
  - First successful handshake wins; abort the other.

⸻

## 2. Legacy Compatibility

- On TCP connect, the server always sends the ASCII preface:
`QSH1\n`
- This causes legacy SSH clients to fail quickly with “Protocol mismatch.”
- After sending the preface, the server expects a qsh HELLO.
- If none arrives or data is invalid within 2s, the server closes the connection.
- No other reject messages are sent. Constant behavior minimizes fingerprinting.

⸻

## 3. Cryptographic Suite (v1)

Fixed suite: no negotiation and no algorithm identifiers on the wire (implicit by ALPN + version).

Key Encapsulation (Hybrid KEM)

- X25519 + ML-KEM-768 (canonical label: ML-KEM-768). Concatenate shared secrets without length prefixes:
	`combined_kem_secret = x25519_shared || mlkem_shared`.
- HKDF-Extract(SHA-384) input = combined_kem_secret. Salt is the label where shown below.

Signatures (Hybrid, host & user)

- Ed25519 + ML-DSA-44 (canonical label: ML-DSA-44). Both signatures MUST verify.

HKDF-SHA-384 Labels (HKDF-Expand with explicit L):

- "qsh v1 hs" (handshake secret)
- "qsh v1 app" (application traffic root)
- "qsh v1 exp" (exporter interface)
- "qsh v1 confirm" (confirm key seed; directional)
- "qsh v1 ch root" (per-channel root)
- "qsh v1 ch rekey" (channel key chaining)

AEAD

- XChaCha20-Poly1305 for channel payloads and confirm tags.
-  192-bit nonce = 128-bit prefix (per channel,direction,rekey-epoch) || 64-bit counter.
	- Nonce prefix derivation (normative): `nonce_prefix = HKDF-Expand(ch_root[i], "qsh v1 ch nonce" || dir || uint64(rekey_counter), 16)` where `dir` is a single byte 0x00 (client→server) or 0x01 (server→client) and `rekey_counter` is the per-channel rekey counter (uint64 big-endian). The trailing 64-bit counter is little-endian and increments per protected frame; it MUST NOT wrap inside a key epoch. If it would approach wrap before a scheduled rekey threshold, a rekey MUST be initiated early.
	- Implementations MUST ensure the per-epoch counter never overflows; practical wrap is unreachable with mandated rekey triggers but this invariant is normative.

Directional Keys

-  Derive distinct c2s and s2c keys; do not rely on nonce partitioning alone.

Rekeying (Per Direction)

- Trigger after 1 MiB plaintext sent OR 30 s since last rekey (whichever first).
- Chaining:
  -	`k_ch' = HKDF-Expand(k_ch, "qsh v1 ch rekey" || uint64(counter), key_len)` where counter starts at 0.
- Forward secrecy window limited to last interval.
	- `k_ch` denotes the current directional traffic key (not a static root). Each rekey replaces it, yielding limited forward secrecy. The counter is encoded as 8-byte big-endian. Independent counters are maintained per channel and per direction. Implementations SHOULD monitor both byte and time thresholds; whichever (1 MiB plaintext in that direction OR 30 s since last rekey) occurs first triggers REKEY_REQ.

Confirm Tags

- `client_confirm` / `server_confirm` are AEAD tags over transcript_hash with empty plaintext, AAD = transcript_hash.
- Keys:
  -	`confirm_key_client = HKDF-Expand(hs_secret, "qsh v1 confirm client", 32)`
  -	`confirm_key_server = HKDF-Expand(hs_secret, "qsh v1 confirm server", 32)`
- Nonce = 24 zero bytes.
	- Two distinct HKDF-Expand operations (different labels) produce independent 32-byte AEAD keys for the confirm tags.

Exporter

- `export(bytes L, context) = HKDF-Expand(app_secret, "qsh v1 exp" || context, L)` with L ≤ 256.
- `context` length MUST be ≤ 64 bytes (arbitrary octets permitted). Empty context allowed. Longer contexts ⇒ PROTOCOL_ERROR.

0-RTT
- Not supported. Resumption tickets (OPTIONAL, Stage 3) still require fresh hybrid KEM.

Forbidden Deviations

- No alternative algorithms, no negotiation extensions under `qshq/1` or `qsht/1`.
- Nonce construction and chaining MUST match this spec.
- Hybrid algorithm public labels (documentation only) use lowercase concatenation without separators (e.g. `x25519+mlkem768`, `ed25519+mldsa44`). These labels NEVER appear on the wire in v1.
- ALPN tokens (`qshq/1`, `qsht/1`) are lowercase and versioned; future modes (e.g. PQ-only) will use distinct ALPNs (e.g. `qshq/1-pq`).

⸻

## 4. Identity & Trust

- Host identity
-	Static hybrid signing key pinned on first connect (TOFU-plus).
- Rotation: new key must be signed by old key.
-	User identity
-	Authorized hybrid keys (authorized_keys equivalent), or
-	Short-lived user certs (10–60 min) signed by a qsh-CA.
-	No passwords, PAM, or policy engines. Privilege enforcement is the host’s job.

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
ch_root[i]     = HKDF-Expand(app_secret, "qsh v1 ch root" || encode_varint(stream_id), L_root)
# Initial directional traffic keys (epoch 0):
k_ch_c2s_0     = HKDF-Expand(ch_root[i], "qsh v1 ch key c2s", 32)
k_ch_s2c_0     = HKDF-Expand(ch_root[i], "qsh v1 ch key s2c", 32)
```
Channel directional keys derived from `ch_root[i]` (details §6.3).

Transcript hash bytes:
```
transcript_hash = SHA-384( canon_cbor(HELLO_no_pad) ||
							canon_cbor(ACCEPT_no_pad) ||
							canon_cbor(FINISH_CLIENT_no_pad) )
```
Padding excluded. ALPN token and transport (QUIC vs TCP) affect context via distinct outer conditions and are thereby bound. Unknown keys (ignored semantically) still appear in canonical CBOR and are thus bound.
FINISH_SERVER is excluded from the transcript hash by design to avoid circular dependencies with the confirm tag computation and because its fields (server_confirm plus optional ticket/padding) carry no additional identity or negotiation material. All security-relevant negotiation inputs are finalized prior to FINISH_SERVER.

Key / length constants (normative):
* `L_app` = 32 bytes (application root secret length)
* Export interface derives outputs directly from `app_secret` per request (no persistent `export_secret`).
* `L_root` = 32 bytes (per-channel root output length)
* Directional traffic AEAD keys = 32 bytes; nonce prefixes = 16 bytes
* `encode_varint(stream_id)` uses QUIC variable-length integer encoding (RFC 9000). Stream IDs in QUIC already embed initiator parity (even=client, odd=server).
* Host and user certificate chains MUST be CBOR arrays even if length 1.
* `user_auth` MUST include exactly one of `raw_keys` or `user_cert_chain`.

⸻

## 6. Channels

Multiplex multiple logical channels per connection.
* QUIC: each bidirectional stream (even=client init, odd=server) is a channel; stream 0 MAY carry control only.
* TCP fallback (Stage 2): single TLS connection with QUIC varint framed substreams.

### 6.1 Channel Types

v1 required: 

- TTY (interactive shell), 
- EXEC (single command). EXEC exit status reported via CTRL `exit` signal.
Future: 

- QFTP (minimal file protocol multiplexed within one channel)
- PFWD (port forwarding, direction field).

### 6.2 Control / Data Frames (deterministic CBOR)

```
OPEN { id, kind, cmd?, env?, winsize?, pad? }
ACCEPT { id, features, initial_window }
REJECT { id, code, reason? }
DATA { id, seq, ciphertext }         # seq uint64 (wrap modulo 2^64)
CTRL { id, signal, payload? }        # signals: WINCH, SIGINT, EOF, CLOSE, WINDOW_UPDATE, EXIT
REKEY_REQ { id, counter }
REKEY_ACK { id, counter }
```

- WINDOW_UPDATE uses CTRL with payload { delta: uint64 } (delta bytes additional credit). 
- EXIT carries payload { code: int, msg?: text }.
- OPEN.cmd max 256 bytes UTF-8 NFC. Environment constraints §8.
On the wire all frame *type* identifiers are lowercase ASCII text strings inside the CBOR map under the key `t` (normative encoding notationally elided above for readability). The abbreviated uppercase form used in this document is editorial only. A canonical encoding example is shown below:

```
{ t:"open", id: 4, kind:"exec", cmd:"uname -a", env:{}, pad:h'00' }
```

Mandatory OPEN fields by `kind`:
* `tty`: `kind`, `id`; OPTIONAL: `winsize`, `env`, `pad`
* `exec`: `kind`, `id`, `cmd`; OPTIONAL: `env`, `pad`
* Future `qftp` / `pfwd`: specified in later stages (MUST be ignored by v1 if unknown)

ACCEPT `features`: CBOR array of lowercase feature tokens (e.g. `[]` for none). Reserved tokens (future): `resize`, `utf8`, `color256`. Unknown features MUST be ignored.

Flow control:
* `initial_window` is bytes of application payload credit the receiver grants initially and MUST be present and > 0 (else PROTOCOL_ERROR channel scope).
* WINDOW_UPDATE deltas are strictly positive (delta > 0) and add to remaining credit; zero deltas MUST be ignored.
* Recommended defaults: `initial_window` = 131072 (128 KiB); WINDOW_UPDATE granularity ≥ 4096 bytes.

Frame type registry (for AAD frame_type_byte §6.4):
```
0x00 data
0x01 ctrl
0x02 confirm
0x03 rekey_req
0x04 rekey_ack
0x05..0x7f reserved
0x80..0xff experimental (MUST NOT appear on public wire)
```
Unknown frame types ⇒ connection-scope PROTOCOL_ERROR.

`OPEN.winsize` (if present) = `{ cols:uint, rows:uint }` both 1..=10000. For `tty` optional; for `exec` MUST NOT appear (ignored if supplied).

`ACCEPT.features` are advisory hints (unknown ignored). Tokens like `resize`, `utf8`, `color256` signal support only.

DATA sequence numbers: start at 0; wrap forbidden. Soft threshold `seq ≥ 2^63` SHOULD prompt graceful channel replacement before overflow.

### 6.3 Rekeying

Per direction triggers (1 MiB OR 30 s). Either peer may initiate on threshold crossing. Race: if both send REKEY_REQ concurrently, lower channel id wins; other discards.

Procedure:

1. Initiator sends REKEY_REQ { counter = next } under old key.
2. Receiver derives tentative new key via chaining, replies REKEY_ACK.
3. Both switch after ACK; old-key DATA accepted until all seq < cutover_seq consumed.

Chaining:
`k_ch' = HKDF-Expand(k_ch, "qsh v1 ch rekey" || uint64(counter), key_len)`

Nonce counters reset to 0 post rekey. If ACK not received within 500 ms, retransmit; after (RECOMMENDED) 3 attempts, close channel with DECRYPT_FAIL. (See §7 for escalation policy.)

Rekey cutover:
* Let `old_last_seq` be highest seq observed under old key for that direction.
* First new-key frame uses `seq = old_last_seq + 1`.
* Receiver selects key: if `seq ≤ old_last_seq` use old key else new key; decryption failure ⇒ DECRYPT_FAIL.
* Old key material SHOULD be retained until all frames with `seq ≤ old_last_seq` processed.

Epoch safety caps (directional): rekey MUST occur before sending > 64 MiB plaintext OR > 2^31 frames in one epoch, regardless of normal thresholds.

### 6.4 AEAD Associated Data (AAD)

For every encrypted payload (DATA frame ciphertext and confirm tags; CTRL frames with sensitive payloads) the Associated Data (AAD) is constructed without serializing an epoch field:

```
aad = concat(
	transcript_hash_prefix,          # 16 bytes = first 16 of transcript_hash
	frame_type_byte,                 # 1 byte registry (0=data,1=ctrl,2=confirm)
	uint64_be(channel_id),
	(seq? -> uint64_be(seq)),        # present only for data frames
	(signal? -> signal_byte),        # present only for ctrl frames
	uint64_be(rekey_counter)         # implicit epoch (not in the CBOR frame)
)
```
Where:
* `rekey_counter` is the per-direction chaining counter (big-endian) – identical to the HKDF label counter.
* `frame_type_byte` from registry (§6.2). Unknown frame type ⇒ PROTOCOL_ERROR.
* `signal_byte` from registry (§6.5). Unknown signals ignored (frame processed without side-effects beyond logging).
This binary AAD format avoids double-encoding CBOR while keeping a stable, unambiguous binding. Implementations MUST verify AAD exactly; any mismatch is a fatal DECRYPT_FAIL for that channel. Confirm tags (type 0x02) omit channel_id, seq, signal; they are per-connection only.

### 6.5 CTRL Signals

Canonical lowercase signal names (wire values):
* `winch`  – terminal size change (`payload` { cols:uint, rows:uint })
* `sigint` – interrupt request (no payload)
* `eof`    – sender will send no more DATA frames (directional half-close)
* `close`  – orderly full channel shutdown request (no further data either direction)
* `window_update` – flow control credit increase (`payload` { delta:uint64 })
* `exit`   – execution terminated (`payload` { code:int, msg?:text })

Rules:
* `exit` MUST appear exactly once for `exec` channels after process termination and SHOULD precede or coincide with `close`.
* `window_update` deltas MUST be > 0; zero deltas ignored.
* Receipt of duplicate `exit` is a PROTOCOL_ERROR (channel scope).
* After sending `close`, an endpoint MUST NOT send further DATA (MAY send final `window_update` or `exit` if race).
* Unknown signals MUST be ignored (optionally logged at debug).

Signal registry (signal_byte values used in AAD):
```
0x00 winch
0x01 sigint
0x02 eof
0x03 close
0x04 window_update
0x05 exit
0x06..0x7f reserved
0x80..0xff experimental
```


⸻

## 7. Error Handling & Codes

Errors encoded as integers referencing a registry. Suggested symbolic mapping:
- Connection: 
  - PROTOCOL_ERROR
  - BAD_IDENTITY (on-wire indistinguishable from generic failure for privacy)
  - REPLAY
  - TIMEOUT.
- Channel: 
  - PERMISSION_DENIED
  - NO_SUCH_CMD
  - RESOURCE_LIMIT
  - DECRYPT_FAIL.

Numeric registry (initial allocation guidance):
```
0  PROTOCOL_ERROR
1  BAD_IDENTITY        # indistinguishable on wire; may be remapped to generic code externally
2  REPLAY
3  TIMEOUT
32 PERMISSION_DENIED
33 NO_SUCH_CMD
34 RESOURCE_LIMIT
35 DECRYPT_FAIL
```
Codes < 64 reserved for core; 64–127 reserved for future spec; 128–255 implementation/vendor experiments (MUST NOT appear on the public wire unless negotiated in future versions). Unknown codes at the receiver MUST be treated as generic channel or connection failure (same semantics as PROTOCOL_ERROR at that scope) without disclosing the numeric value to higher privilege domains unless needed for logging.

DECRYPT_FAIL escalation is based on consecutive channel closures attributed to DECRYPT_FAIL within a rolling 60 s window. Any successfully closed (non-error) channel resets the consecutive counter. Upon reaching ≥3, the implementation MUST terminate the connection with PROTOCOL_ERROR (locally recorded as DECRYPT_FAIL escalation) and SHOULD emit a security log event including aggregate stats.

After PROTOCOL_ERROR client SHOULD attempt fallback transport once. BAD_IDENTITY remains indistinguishable on-wire from generic failure.

⸻

## 8. Encoding, Padding, Environment & Privacy

Deterministic CBOR: definite-length maps, canonical key ordering, reject non-canonical encodings.
Unknown keys ignored (forward compat) yet bound by transcript hash.

Padding: Optional `pad` field (byte string). Adaptive distribution among {1,2,4} KiB bucket sizes RECOMMENDED (non-uniform if improves cover traffic). Padding excluded from transcript hash.

Environment Variable Sanitization:
* Names MUST match `[A-Z0-9_]{1,64}` (ASCII). Reject control chars / NUL. Lowercase names are invalid (client MUST send uppercase; server MAY reject otherwise).
* Values ≤ 4096 bytes, UTF-8 NFC.
* Duplicate names (case-sensitive) → reject entire env set (no last-wins).
* Server MAY whitelist additional names/prefixes (config `AllowClientEnv`).
* Disallowed / stripped by default (normative v1 list – may expand in impl docs):
	- All dynamic loader variables: `LD_*` (e.g. `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `LD_DEBUG`, `GCONV_PATH`)
	- macOS loader variables: `DYLD_*` (e.g. `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`)
	- Shell injection / env override: `BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`
	- qsh reserved prefix: `QSH_*` (client-provided values stripped)
	- Toolchain path injection (default blocked unless allowed): `PYTHONPATH`, `PERL5LIB`, `NODE_OPTIONS`, `JAVA_TOOL_OPTIONS` (non-exhaustive)
	- Sensitive socket / agent hooks: `SSH_AUTH_SOCK`, `GIT_SSH`, `GIT_SSH_COMMAND`
* Allowed with validation: `TERM` (from a whitelist), locale/time (`LANG`, `LC_*`), `TZ` (≤128 bytes printable), others explicitly whitelisted.
* `PATH` and `HOME` default to server-defined; client values ignored unless `AllowClientEnv PATH,HOME` configured.

Capabilities: advisory; ordering fixed (lexicographic). Unknown ignored.
All control frame type identifiers (e.g. `open`, `accept`, `reject`, `data`, `ctrl`, `rekey_req`, `rekey_ack`) and handshake field keys are lowercase text strings on the wire. Uppercase tokens in this document are editorial.

Keepalives: Encrypted keepalive (empty DATA/CTRL) every 30 s RECOMMENDED for TTY smoothing.

Privacy Logging Modes: `privacy-minimal` (no client IP for successful sessions), `standard` (IP:port), `enterprise` (IP:port+CIDR tags). Failed auth/security events SHOULD always log source IP (auditing / fail2ban). Provide hashing/redaction options.

Length Limits:
* Handshake (pre-padding) < 2 KiB target.
* OPEN.cmd ≤ 256 bytes.
* Env var count ≤ 64.
* (Future QFTP) path length ≤ 512 bytes.

⸻

## 9. Operational Defaults & Limits

Ports: 22/UDP (QUIC), 22/TCP (fallback). 
Attempt QUIC; if no ACCEPT within 300–500 ms, start TCP.

QUIC params (RECOMMENDED defaults): 

- max_idle_timeout=30s
- initial_max_data=1 MiB
- initial_max_streams_bidi=100.

Rekey thresholds: 

- 1 MiB / 30 s per direction.

Resumption tickets (Stage 3): 

- single-use
- default lifetime 600 s
- target size ≤512 bytes, 
- bound to (user key hash, host key fingerprint, ALPN, nonces, capabilities, timestamp). 
- Server tracks nonces until expiry (replay prevention).
 - Ticket AEAD key derivation (provisional): `ticket_key = HKDF-Expand(server_ticket_secret, "qsh v1 ticket key", 32)` where `server_ticket_secret` is a long-lived random 32-byte value rotated operationally (e.g., daily). Ticket payload carries a unique 96-bit nonce; server maintains a replay set until expiry. Tickets do NOT reduce round trips (still a fresh KEM) but allow skipping server-side expensive auth DB lookups.

Ticket payload schema (canonical CBOR before encryption):
```
ticket_plain = {
	ver: 1,
	iat: uint,        # issued_at (epoch seconds)
	exp: uint,        # expires_at (epoch seconds)
	nonce: bstr(12),  # unique per ticket (96-bit)
	user_hash: bstr,
	host_fp: bstr,
	alpn: text,       # "qshq/1" | "qsht/1"
	caps: [text, ...],
	rand: bstr(16)
}
```
AEAD parameters:
* key: `ticket_key`
* nonce: 24 bytes = 12 zero prefix || nonce (or unique random 24-byte value ensuring global uniqueness)
* AAD: `host_fp || alpn`
Single-use enforcement: reject reuse of `(nonce, host_fp)` until expiry.

Memory cap unauthenticated connection ≤256 KiB.

Logging: JSON lines with canonical field order (e.g. time, level, path, user?, host, rtt_ms, addr?).
Canonical field order prefix:
```
time, level, event, conn_id, channel_id?, user?, host, remote_addr?, alpn, transport, bytes_in, bytes_out, reason?, duration_ms?
```
Additional fields MAY follow but MUST NOT reorder this prefix. `remote_addr` omitted for successful sessions in `privacy-minimal` mode.

⸻

## 10. Future Extensions (Non-Normative)

- QFTP (minimal file subsystem) – new capability string `QFTP`.
- PFWD (port forwarding) – capability `PFWD` with direction/address fields.
- Host key rotation object: `{ new_host_key, old_host_key_signature, valid_from? }` (overlap grace window). If old key compromised without signature, out-of-band re-bootstrap required.
	- Rotation object schema (Stage 3):
		```
		{
			new_host_key: bstr,                # hybrid public key encoding
			old_host_key_signature: { ed25519: bstr, mldsa44: bstr },
			valid_from?: uint,                 # epoch seconds (client MAY accept early if within 24h skew tolerance)
			grace_s?: uint                     # OPTIONAL suggested overlap duration
		}
		```
		Clients MUST verify signatures over canonical CBOR of the object with padding excluded. If signature missing: hard fail. Suggested grace overlap 7–30 days.
	- Default grace window if `grace_s` omitted: 30 days (2,592,000 seconds).
- Resumption tickets (Stage 3) as in §9.
- Transparency logs for host key pinning.
- Post-quantum-only mode via new ALPN (e.g. `qshq/1-pq`).
- Reserved CBOR keys for v2+ extensions (ignore unknown under v1).
	- v1 reserves (MUST NOT use) any handshake map key beginning with `_v2_` for future evolution; implementations MUST ignore (and transcript-bind) any such unknown keys if received.

⸻

## 11. Security Considerations

qsh v1 is designed as a security-first replacement for SSH. This section documents the rationale behind key choices and highlights rules implementers must follow.

### No Cipher Negotiation
qsh v1 uses a fixed cryptographic suite (see §3) to eliminate downgrade risk; no cipher/hash/key negotiation occurs.

### No 0-RTT
Early data (0-RTT) is disallowed; each connection performs a fresh hybrid KEM even with tickets (§9) for simpler replay control.

### Per-Channel Rekey
Directional sub-keys derived from channel root; forward-secret chaining narrows exposure window.

### Hybrid Cryptography
See §3 for exact hybrid algorithms; requiring both halves mitigates single-family compromise risk.

### Transcript Binding
Hybrid signatures + confirm tags bind pre-FINISH_SERVER handshake (HELLO/ACCEPT/FINISH_CLIENT) excluding padding, plus implicit ALPN & transport context (see §5.2).

### Host Key Continuity
TOFU-plus pinning. Rotation (Stage 3) requires signed rotation object; absence => hard fail.

### Authorized Keys
- Users authenticate with raw hybrid keys listed in `authorized_keys`.  
- Revocation is handled by removing entries from this file.  
- No passwords or interactive prompts are allowed.

### Preface and Legacy Rejects
See §2 for preface behavior rationale (fast legacy fail, reduced fingerprinting).

### Deterministic Encoding
Non-canonical CBOR MUST be rejected. Unknown keys ignored but still bound.

### Padding and Privacy
Padding buckets and keepalives (§8) plus canonical capability ordering (HELLO) reduce passive fingerprinting.

### Replay & Nonce Handling
FINISH replay detection via stored nonces/tickets (single-use). Nonce counters reset on rekey.

### Environment Security
Environment rules (§8) block loader/toolchain injection and reject duplicates to eliminate ambiguity.

### Forbidden Changes
Implementations MUST NOT: add negotiable cipher lists, disable rekeying, permit 0-RTT app data, accept non-deterministic CBOR, or modify nonce/key schedule. Doing so breaks interoperability/security.

**Note:** Future versions (e.g., qsh v2) may define different suites; v1 MUST follow this specification exactly.

---

12. License

This specification and reference implementation are released under the MIT License.

⸻

13. Author

Maintained by @haukened (David Haukeness).