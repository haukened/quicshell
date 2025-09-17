// (All handshake port traits relocated to `ports::handshake`; this file now
// only defines role/state/event enums for the FSM.)

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
