use crate::ports::crypto::Seq;
use crate::protocol::handshake::keyschedule::DirectionKeys;

/// Port abstraction used by the handshake FSM to accumulate the canonical
/// transcript.
///
/// Responsibilities:
/// - Accept already *canonical* CBOR (deterministic encoding) bytes via
///   `absorb_canonical()`.
/// - Provide the running transcript hash (`SHA-384`) through `hash()`.
///
/// Design notes:
/// - The FSM never feeds non‑canonical data; canonicalization occurs in the
///   wire layer (`HandshakeWire`) before calling `absorb_canonical()`.
/// - A 48‑byte array is returned directly to avoid allocation and signal the
///   fixed hash length.
///
/// Safety / Invariants:
/// - Callers MUST only pass canonical (RFC 8949 deterministic) CBOR bytes.
/// - Implementations MUST treat identical byte slices identically; no internal
///   re‑encoding is permitted.
pub trait TranscriptPort {
    /// Absorb already canonical CBOR bytes into the transcript state.
    ///
    /// Input:
    /// - `bytes`: Deterministically encoded CBOR for a single handshake
    ///   structure (e.g., `HELLO`, `ACCEPT`, `FINISH_CLIENT`, `FINISH_SERVER`).
    fn absorb_canonical(&mut self, bytes: &[u8]);

    /// Return the current transcript hash (`SHA-384`) as a fixed 48‑byte array.
    ///
    /// This value is stable unless additional messages are absorbed.
    fn hash(&self) -> [u8; 48];
}

/// Sink interface the handshake FSM uses to install derived write keys and
/// initialize sequence counters once the handshake cryptographic context is
/// ready.
///
/// Implemented by an application connection / session object that owns the
/// transport phase encryption state after the handshake.
///
/// Contract:
/// - `install_keys()` is called exactly once per successful handshake with the
///   freshly derived client/server `DirectionKeys`.
/// - `set_seqs()` follows (or is combined) to seed starting `Seq` counters for
///   post‑handshake protected frames.
///
/// Error Handling:
/// - The trait uses no return values; implementors should ensure infallible
///   storage (e.g., internal assignment) or panic only on unrecoverable logic
///   errors (documented in their own module).
pub trait KeySink {
    /// Install the negotiated write direction keys.
    ///
    /// Inputs:
    /// - `client_write`: Keys the client uses to protect outbound traffic
    ///   (client → server direction).
    /// - `server_write`: Keys the server uses to protect outbound traffic
    ///   (server → client direction).
    fn install_keys(&mut self, client_write: DirectionKeys, server_write: DirectionKeys);

    /// Set initial sequence counters for application data protection.
    ///
    /// Inputs:
    /// - `client_seq`: Initial sequence the client will use to send.
    /// - `server_seq`: Initial sequence the server will use to send.
    fn set_seqs(&mut self, client_seq: Seq, server_seq: Seq);
}

/// Endpoint role during the handshake (`Client` or `Server`).
///
/// Affects:
/// - Allowed state transitions.
/// - Which side produces / verifies specific confirm tags.
/// - Direction of `Seq` counters advanced during confirm sealing / verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Acts as the initiator: sends `HELLO`, later `FINISH_CLIENT`, verifies the
    /// server confirm, then produces client confirm.
    Client,
    /// Acts as the responder: receives `HELLO`, sends `ACCEPT`, verifies client
    /// confirm, then produces server confirm.
    Server,
}

/// Coarse states of the handshake finite state machine (`HandshakeFsm`).
///
/// Each state corresponds to progress in message exchange and key schedule
/// readiness. Transitions are monotonic; regression is prevented with a
/// debug assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state before any message is sent or received.
    Start,
    /// Client has sent `HELLO` (client side) OR server has observed its own
    /// sent `HELLO` (not used on server side; server instead moves to `GotHello`).
    SentHello,
    /// Server received `HELLO` (server side view) OR client internal mirror.
    GotHello,
    /// Server has sent `ACCEPT` OR client mirror after encoding absorption.
    SentAccept,
    /// Client received `ACCEPT` (client side) OR server internal mirror.
    GotAccept,
    /// Client has sent `FINISH_CLIENT`.
    SentFinishClient,
    /// Server received `FINISH_CLIENT`.
    GotFinishClient,
    /// Server has sent `FINISH_SERVER`.
    SentFinishServer,
    /// Both sides possess everything required to call `complete()` (keys & PRK
    /// established; confirm tags handled).
    ReadyToComplete,
    /// Final state: keys installed into `KeySink`; handshake finished.
    Complete,
}

/// Internal events that drive transitions inside `HandshakeFsm`.
///
/// These are not on‑wire values; they are logical triggers invoked by public
/// API methods (e.g., `on_hello`, `build_finish_client`) or test shims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    /// Client sending `HELLO`.
    ClientSendHello,
    /// Client receiving `ACCEPT`.
    ClientRecvAccept,
    /// Client sending `FINISH_CLIENT` (after confirm tag sealed & absorbed).
    ClientSendFinishClient,
    /// Client receiving `FINISH_SERVER` (after verify + absorb).
    ClientRecvFinishServer,
    /// Server receiving `HELLO`.
    ServerRecvHello,
    /// Server sending `ACCEPT`.
    ServerSendAccept,
    /// Server receiving `FINISH_CLIENT`.
    ServerRecvFinishClient,
    /// Server sending `FINISH_SERVER`.
    ServerSendFinishServer,
    /// Marker event to coerce transition into `ReadyToComplete` (idempotent /
    /// tolerant of being invoked slightly early by API convenience methods).
    MarkReady,
    /// Finalization event transitioning `ReadyToComplete` → `Complete`.
    Complete,
}
