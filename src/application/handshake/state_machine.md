# Handshake State Machine (qsh v1)

Authoritative overview of the `HandshakeFsm` states, events, and legal
transitions. This complements (does not replace) the normative protocol
definition in `docs/spec.md`. If an inconsistency is ever observed, update the
spec first, then reconcile the implementation and this document.

## Goals

- Make control‑flow auditable (security review & fuzz target design).
- Provide a single table the tests can be validated against.
- Clarify when cryptographic side‑effects (PRK mix, key derivation, confirm
	tag seal/verify, sequence counter advancement) occur.

## Roles

Two roles exist: `Client` (initiator) and `Server` (responder). Role impacts:

- Permitted event set.
- Which side seals vs verifies each confirm tag.
- Which directional sequence counters advance (`client_write`, `server_write`,
	`client_read`, `server_read`).

## States

| State | Meaning (coarse progress) |
|-------|---------------------------|
| `Start` | No messages processed. |
| `SentHello` | Client: HELLO absorbed after send. (Server never enters; it moves to `GotHello`.) |
| `GotHello` | Server absorbed inbound HELLO. (Client mirror for symmetry only used indirectly.) |
| `SentAccept` | Server absorbed outbound ACCEPT. (Client mirror after receiving; then transitions to `GotAccept`.) |
| `GotAccept` | Client absorbed inbound ACCEPT. |
| `SentFinishClient` | Client sealed & absorbed FINISH_CLIENT (contains client confirm). |
| `GotFinishClient` | Server verified client confirm & absorbed FINISH_CLIENT. |
| `SentFinishServer` | Server sealed & absorbed FINISH_SERVER (contains server confirm). (Client will move directly to `ReadyToComplete` instead of mirroring this intermediate.) |
| `ReadyToComplete` | All required handshake messages + confirm(s) processed; key schedule material available; ready for `complete()`. |
| `Complete` | Transport keys installed into `KeySink`; handshake finalized. |

States are **monotonic**; regression is debug‑asserted and impossible via the
public API.

## Events

Internal events (enum `HandshakeEvent`) drive transitions:

| Event | Trigger (public API) | Role | Description |
|-------|----------------------|------|-------------|
| `ClientSendHello` | `on_client_send_hello` | Client | Absorb outbound HELLO. |
| `ClientRecvAccept` | `on_accept` | Client | Absorb inbound ACCEPT. |
| `ClientSendFinishClient` | `build_finish_client` | Client | Seal client confirm, absorb FINISH_CLIENT. |
| `ClientRecvFinishServer` | `on_finish_server` | Client | Verify server confirm, absorb FINISH_SERVER. |
| `ServerRecvHello` | `on_hello` | Server | Absorb inbound HELLO. |
| `ServerSendAccept` | `on_server_send_accept` | Server | Absorb outbound ACCEPT. |
| `ServerRecvFinishClient` | `on_finish_client` | Server | Verify client confirm, absorb FINISH_CLIENT. |
| `ServerSendFinishServer` | `build_finish_server` | Server | Seal server confirm, absorb FINISH_SERVER. |
| `MarkReady` | `ready()` (tests / orchestration convenience) | Both | Coerce/ensure advancement to `ReadyToComplete`. Idempotent / forward‑only. |
| `Complete` | `complete()` | Both | Install keys & finalize. |

## Transition Tables

### Client Role

| Current State | Event | Next State | Side Effects |
|---------------|-------|-----------|--------------|
| `Start` | `ClientSendHello` | `SentHello` | Encode+absorb HELLO. |
| `SentHello` | `ClientRecvAccept` | `GotAccept` | Encode+absorb ACCEPT. |
| `GotAccept` | `ClientSendFinishClient` | `SentFinishClient` | Derive (lazy) write keys (if PRK ready); seal client confirm; advance `client_write` seq; absorb FINISH_CLIENT. |
| `GotAccept` | `ClientRecvFinishServer` | `ReadyToComplete` | Derive (lazy) write keys (if needed); verify server confirm; advance `server_read` seq; absorb FINISH_SERVER. (Allows server sending FINISH_SERVER before client sends FINISH_CLIENT in edge orchestrations? No—client must send its finish first; see next row.) |
| `SentFinishClient` | `ClientRecvFinishServer` | `ReadyToComplete` | Verify server confirm; advance `server_read` seq; absorb FINISH_SERVER. |
| (any) | `MarkReady` | `ReadyToComplete` | No crypto side effects; purely a state coercion (only forward). |
| `ReadyToComplete` | `Complete` | `Complete` | PRK + write key ensure (if still lazy), install keys into `KeySink`, set starting seq counters. |

```mermaid
flowchart LR
  1[Start]
  2[SentHello]
  3[GotAccept]
  4[SentFinishClient]
  5[ReadyToComplete]
  6[Complete]
  1 -- ClientSendHello --> 2
  2 -- ClientRecvAccept --> 3
  3 -- ClientSendFinishClient --> 4
  4 -- ClientRecvFinishServer --> 5
  5 -- Complete --> 6
```

Note: The client path intentionally permits receiving `FINISH_SERVER` after it
has locally moved to `SentFinishClient` to accommodate timing where the server
optimistically produces FINISH_SERVER quickly after verifying the client
confirm (common case). The FSM still enforces that a server confirm cannot be
processed before ACCEPT is received.

### Server Role

| Current State | Event | Next State | Side Effects |
|---------------|-------|-----------|--------------|
| `Start` | `ServerRecvHello` | `GotHello` | Encode+absorb HELLO. |
| `GotHello` | `ServerSendAccept` | `SentAccept` | Encode+absorb ACCEPT. |
| `SentAccept` | `ServerRecvFinishClient` | `GotFinishClient` | Derive (lazy) write keys; verify client confirm; advance `client_read` seq; absorb FINISH_CLIENT. |
| `GotFinishClient` | `ServerSendFinishServer` | `ReadyToComplete` | Seal server confirm; advance `server_write` seq; absorb FINISH_SERVER. |
| (any) | `MarkReady` | `ReadyToComplete` | No crypto side effects. |
| `ReadyToComplete` | `Complete` | `Complete` | Ensure PRK & write keys; install keys; set starting seq counters. |

```mermaid
flowchart LR
  1[Start]
  2[GotHello]
  3[SentAccept]
  4[GotFinishClient]
  5[ReadyToComplete]
  6[Complete]
  1 -- ServerRecvHello --> 2
  2 -- ServerSendAccept --> 3
  3 -- ServerRecvFinishClient --> 4
  4 -- ReadyToComplete --> 5
  5 -- Complete --> 6
```

### Invalid Transitions

Any (state, event) pair not listed above yields
`ApplicationHandshakeError::ValidationError("invalid transition")` except for
explicit state validation guards in confirm handlers that produce more specific
messages (e.g., "invalid state for FINISH_CLIENT"). Future work will unify
messages to the format `invalid state: <operation>` (see TODO list).

### MarkReady Semantics

`MarkReady` is a *soft* event used by tests or orchestration layers that want
to force `ReadyToComplete` after all necessary messages/confirm logic has run.
If invoked early it still forces advancement but never skips mandatory crypto
side effects because those only occur inside the message handlers and confirm
processing (`build_*` / `on_*`). Thus calling `ready()` prematurely has no
security impact—it cannot conjure keys or confirms.

## Lazy Key Derivation & PRK

- PRK (`prk_from`) is set by `set_hybrid_shared()` (external) or synthesized
	inside `complete()` if still absent (using current transcript hash & shared
	secret passed to `complete()`).
- `WriteKeys` are derived once on first need (any confirm seal/verify or
	during `complete()`) via `derive_keys(th, prk)` and cached (`writes`).
- Subsequent confirm operations reuse the cached `WriteKeys` without recompute.

## Confirm Tags & Sequence Counters

Direction mappings:

| Confirm Role | AEAD Key Used | Sequence Counter Advanced |
|--------------|---------------|---------------------------|
| `ClientSends` | `writes.client` | `client_write` (send) OR `client_read` when verifying on server |
| `ServerSends` | `writes.server` | `server_write` (send) OR `server_read` when verifying on client |

Counters increment only after **successful** seal/verify. Failed verification
does not advance (preventing gap forging).

### Detailed Sequence Semantics (Expanded)

This subsection formalizes the implicit rules above so fuzzers and external
implementations can mechanically validate behavior.

Initial values (at `HandshakeState::Start`):

| Counter | Meaning | Initial |
|---------|---------|---------|
| `next_cli_write` | Client sending (its confirm) | 0 |
| `next_srv_write` | Server sending (its confirm) | 0 |
| `next_cli_read`  | Server reading client confirm | 0 |
| `next_srv_read`  | Client reading server confirm | 0 |

Per-event delta table (only events that mutate counters listed):

| Event | Affected Counter | Delta | Reason |
|-------|------------------|-------|--------|
| `ClientSendFinishClient` | `next_cli_write` | +1 | Successful seal of client confirm consumes one nonce. |
| `ServerRecvFinishClient` | `next_cli_read`  | +1 | Successful verify of client confirm consumes one nonce. |
| `ServerSendFinishServer` | `next_srv_write` | +1 | Successful seal of server confirm consumes one nonce. |
| `ClientRecvFinishServer` | `next_srv_read`  | +1 | Successful verify of server confirm consumes one nonce. |

All other events MUST NOT change any sequence counter. Failed confirm
verification leaves counters unchanged (caller retries only by restarting the
handshake; no roll‑forward on failure is permitted).

Installation semantics (`complete()`):

* Only `next_cli_write` and `next_srv_write` are exported via
  `KeySink::set_seqs` at completion. Their values represent the *next* unused
  send sequence number for each direction (i.e., already advanced past any
  confirm tag use during the handshake itself). Read counters remain internal
  pending future ADR on inbound transport sequencing.
* No counter is ever reset or decremented; monotonicity is enforced by design
  (single writer per counter, linear increment sites).

Invariants:

1. (Uniqueness) For each `(direction, role)` pair the tuple `(aead_key, seq)`
  is never reused. Guaranteed because only one increment site exists per
  counter and keys are fixed post-derivation.
2. (Alignment) `next_cli_write >= next_cli_read` and `next_srv_write >= next_srv_read`
  are not required and not guaranteed; write/read progress depends on who
  sends first (client confirm typically precedes server confirm, but network
  reordering of FINISH frames still preserves per-direction order since each
  direction has exactly one frame during handshake).
3. (Bounded Use) Handshake uses at most one sequence number per direction for
  confirm traffic; post-handshake application data begins immediately at the
  exported starting sequence number.
4. (Lazy Derivation Safety) Key derivation occurs before any seal/verify that
  references the key; no increment occurs without a derived key.
5. (Transcript Stability) `transcript_hash()` exposure is restricted until
  after all potential confirm frames are processed, ensuring the hash binds
  the exact sequence of absorbed canonical encodings.

Rationale for gating `transcript_hash()` until `ReadyToComplete`:

Premature access risks external code binding channel semantics (e.g., exported
auth contexts) to a transcript that may still grow with confirm frames. By
restricting access we eliminate TOCTOU style races on the transcript surface.

Wrap / overflow: The `Seq` type is a thin wrapper over a 64‑bit counter in the
current implementation. Given the handshake consumes at most one (or two) units
per direction, wrap is impossible during the handshake phase; application data
handling (future spec section) will define rekey / wrap mitigation before any
practical exhaustion boundary is approached.

## Completion

`complete(th, hybrid_shared)` performs (in order):

1. State validation (`ReadyToComplete`).
2. PRK ensure (derive if absent from earlier explicit call).
3. Write key ensure (derive if not already cached by confirm path).
4. Move keys into `KeySink::install_keys` (consuming cached copy).
5. Seed starting send sequence counters via `KeySink::set_seqs` using the *next*
	 (post‑confirm) write counters accumulated so far.
6. Transition → `Complete` (idempotent via state check; second call would fail).

Read sequence counters (`client_read`, `server_read`) are internal only at this
stage; installation defers until transport layer binding requirements are
finalized (future ADR may extend `KeySink`).

## Sequence Diagram (Nominal Success Path)

```mermaid
sequenceDiagram
	autonumber
	participant C as Client
	participant S as Server

	C->>S: HELLO
	note over C,S: encode + absorb canonical HELLO

	S->>C: ACCEPT
	note over C,S: encode + absorb canonical ACCEPT

	C->>S: FINISH_CLIENT (client_confirm)
	note over C,S: Client seals confirm

	S->>C: FINISH_SERVER (server_confirm)
	note over C,S: Server seals confirm

	C->>C: complete()

	S->>S: complete()
	note over C,S: ensure PRK + write keys
```

## Security Review Checklist

When auditing changes to the FSM, ensure:

1. No new backward transitions were added (monotonicity preserved).
2. Confirm verification always precedes absorption of the FINISH frame.
3. Sequence counters only advance exactly once per successful confirm op.
4. Lazy derivation cannot occur with an uninitialized transcript hash.
5. Error messages do not leak secret material (they currently do not include
	 key / tag bytes; only coarse reasons).
6. `ready()` cannot bypass required confirm verification (it cannot).

## Future Improvements (Tracked in TODO List)

- Unify invalid state error message format.
- Expose a read‑only `transcript_hash()` accessor for external diagnostics.
- Potentially export a machine‑readable transition map for fuzz orchestration.

