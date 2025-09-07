qsh Protocol Specification (v1)

QuicShell (qsh) is a modern secure remote shell protocol, designed as a successor to SSH.
This document describes version 1 of the wire protocol and expected server behavior.

⸻

1. Ports & Transports
	•	Default ports
	•	22/UDP — preferred transport, qsh over QUIC (ALPN=qshq/1)
	•	22/TCP — fallback transport, qsh over TCP (ALPN=qsht/1)
	•	Client connection order
	1.	Attempt QUIC on UDP/22.
	2.	If no ACCEPT within ~300–500 ms, attempt TCP/22 in parallel.
	3.	First successful handshake wins; abort the other.

⸻

2. Legacy Compatibility
	•	On TCP connect, the server always sends the ASCII preface:
QSH1\n
	•	This causes legacy SSH clients to fail quickly with “Protocol mismatch.”
	•	After sending the preface, the server expects a qsh HELLO.
If none arrives or data is invalid within 2s, the server closes the connection.
	•	No other reject messages are sent. Constant behavior minimizes fingerprinting.

⸻

3. Cryptographic Profile

qsh v1 fixes the cryptographic suite; no negotiation is supported.
	•	Key exchange (hybrid KEM): X25519 + ML-KEM-768
	•	Signatures (host & user): Ed25519 + ML-DSA-44 (Dilithium-2)
	•	KDF: HKDF-SHA-384 with domain-separated labels
	•	AEAD: XChaCha20-Poly1305 for handshake confirms and channel data
	•	Rekeying: per-channel rekey after 1 MiB or 30 s, whichever first
	•	0-RTT: not allowed
	•	Resumption tickets: single-use, short-lived, still require fresh KEM

⸻

4. Identity & Trust
	•	Host identity
	•	Static hybrid signing key pinned on first connect (TOFU-plus).
	•	Rotation: new key must be signed by old key.
	•	User identity
	•	Authorized hybrid keys (authorized_keys equivalent), or
	•	Short-lived user certs (10–60 min) signed by a qsh-CA.
	•	No passwords, PAM, or policy engines. Privilege enforcement is the host’s job.

⸻

5. Handshake Flow

All handshake messages are CBOR maps, length-prefixed.

5.1 Messages

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

5.2 Key Schedule

hs_secret    = HKDF-Extract(x25519_shared || mlkem_shared, "qsh v1 hs")
app_secret   = HKDF(hs_secret, "qsh v1 app")
export_secret= HKDF(hs_secret, "qsh v1 exp")
ch_root[i]   = HKDF(app_secret, "qsh v1 ch root" || stream_id)

	•	Transcript hash = SHA-384(HELLO || ACCEPT || FINISH_CLIENT)
	•	Both client and server sign the transcript hash with hybrid sigs.
	•	Confirms (client_confirm, server_confirm) are AEAD tags over transcript hash.

⸻

6. Channels

qsh multiplexes multiple channels per session.
	•	QUIC transport: each channel = QUIC stream
	•	TCP transport: minimal varint header mux, one TCP connection

6.1 Channel Types
	•	TTY — interactive shell
	•	EXEC — single command execution
	•	SFTP — file transfer subsystem
	•	PFWD — port forwarding

6.2 Control Frames
	•	OPEN { id, kind, cmd?, target?, env?, winsize? }
	•	ACCEPT { id, features, initial_window }
	•	REJECT { id, code, reason }
	•	DATA { id, seq, ciphertext } (AEAD-sealed)
	•	CTRL { id, signal } (WINCH, SIGINT, EOF, CLOSE, WINDOW_UPDATE)
	•	REKEY_REQ { id, counter } / REKEY_ACK { id, counter }

6.3 Rekeying

k_ch' = HKDF(k_ch, "qsh v1 ch rekey" || counter)

Unacked rekey → channel closure.

⸻

7. Error Handling
	•	Connection-level: PROTOCOL_ERROR, BAD_IDENTITY, REPLAY, TIMEOUT
	•	Channel-level: PERMISSION_DENIED, NO_SUCH_CMD, RESOURCE_LIMIT, DECRYPT_FAIL
	•	Any decrypt failure closes that channel; ≥3 such closures drop the whole connection.

⸻

8. Padding & Privacy
	•	Handshake messages padded to 1–2–4 KB buckets.
	•	Optional fixed-rate encrypted keepalives to blur idle TTY traffic.
	•	Usernames never sent in cleartext.

⸻

9. Operational Defaults
	•	Ports: 22/UDP (QUIC) and 22/TCP (fallback).
	•	Handshake timeout: 400 ms before racing TCP.
	•	Rekey: 1 MiB or 30 s.
	•	Resumption tickets: 10 min, single-use.
	•	Server logs one line per connect: {path=quic|tcp, user=..., host=..., rtt_ms=...}

⸻

10. Future Extensions
	•	QUIC-only fast path on 22/UDP.
	•	Transparency logs for host key pinning.
	•	Post-quantum-only mode (drop classical curves).
⸻

11. License

This specification and reference implementation are released under the MIT License.

⸻

12. Author

Maintained by @haukened (David Haukeness).