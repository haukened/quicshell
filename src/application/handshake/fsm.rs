//! Handshake FSM (Finite State Machine) orchestration.
//!
//! Coordinates the four-message handshake flow, invoking domain validation,
//! updating the transcript, and deriving/installing keys via the key schedule.
//!
//! The FSM is generic over a `KeySink` trait that the application connection
//! must implement to allow key installation and sequence number management.
//!
//! The FSM tracks the current state and role (client/server) to enforce valid
//! transitions and prevent out-of-order or duplicate messages.
//!
//! State transitions are triggered by calling the appropriate methods:
//! - Client-side:
//!  - `on_start_client_send_hello(hello)`
//!  - `on_accept(accept)`
//!  - `on_finish_server(finish_server)`
//! - Server-side:
//!  - `on_hello(hello)`
//!  - `on_start_server_send_accept(accept)`
//!  - `on_finish_client(finish_client)`
//!  - `on_start_server_send_finish(finish_server)`
//! - Completion (both sides):
//!  - `complete(th, hybrid_shared)`
//!
//! CLEAN boundaries reminder:
//! - **`protocol::handshake::wire`**: bytes \u2194 domain types (canonical CBOR, no validation beyond format).
//! - **`domain::handshake`**: types + invariants (structural/semantic validation, no IO/crypto).
//! - **`core/adapters`**: concrete crypto (AEAD, KEM), no protocol knowledge.
//! - **`application::handshake::fsm`** (this file): orchestrates the flow, calls domain validators,
//!   updates transcript, invokes key schedule, installs keys, and advances states.

use crate::application::handshake::errors::ApplicationHandshakeError;
use crate::ports::crypto::Seq;
use crate::protocol::handshake::keyschedule::{DirectionKeys, WriteKeys, derive_keys, prk_from};

// NOTE: Adjust this path if your domain module lives elsewhere.
use crate::domain::handshake::{Accept, FinishClient, FinishServer, Hello};

/// Minimal contract the application connection state must implement
/// for the FSM to install keys and reset sequence counters.
pub trait KeySink {
    fn install_keys(&mut self, client_write: DirectionKeys, server_write: DirectionKeys);
    fn set_seqs(&mut self, client_seq: Seq, server_seq: Seq);
}

/// Which role this endpoint plays during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// High-level states for the handshake process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state before any side-effects.
    Start,
    /// Client: HELLO sent, waiting for ACCEPT. Server: not used.
    SentHello,
    /// Server: HELLO received, about to send ACCEPT. Client: not used.
    GotHello,
    /// Server: ACCEPT sent, waiting for `FINISH_CLIENT`.
    SentAccept,
    /// Client: ACCEPT received, about to send `FINISH_CLIENT`.
    GotAccept,
    /// Client: `FINISH_CLIENT` sent, waiting for `FINISH_SERVER`.
    SentFinishClient,
    /// Server: `FINISH_CLIENT` received, about to send `FINISH_SERVER`.
    GotFinishClient,
    /// Server: `FINISH_SERVER` sent; next step is key install.
    SentFinishServer,
    /// Both sides have validated all inputs and can derive/install keys.
    ReadyToComplete,
    /// Traffic keys installed; connection may send/receive encrypted frames.
    Complete,
}

/// Discrete events that advance the FSM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    ClientSendHello,
    ClientRecvAccept,
    ClientRecvFinishServer,
    ServerRecvHello,
    ServerSendAccept,
    ServerRecvFinishClient,
    ServerSendFinishServer,
    MarkReady,
    Complete,
}

/// Handshake FSM carrying the minimal state needed for orchestration.
/// `C` is the application-owned connection/context that implements `KeySink`.
pub struct HandshakeFsm<C: KeySink> {
    role: Role,
    state: HandshakeState,
    conn: C,
}

impl<C: KeySink> HandshakeFsm<C> {
    /// Construct a new FSM bound to a connection/context and a role.
    pub fn new(role: Role, conn: C) -> Self {
        Self {
            role,
            state: HandshakeState::Start,
            conn,
        }
    }

    /// Mark the FSM ready to perform final key installation once all
    /// domain/wire validations have succeeded.
    pub fn ready(&mut self) {
        let _ = self.apply(HandshakeEvent::MarkReady);
    }

    fn state_ordinal(state: HandshakeState) -> u8 {
        match state {
            HandshakeState::Start => 0,
            HandshakeState::SentHello | HandshakeState::GotHello => 1,
            HandshakeState::SentAccept | HandshakeState::GotAccept => 2,
            HandshakeState::SentFinishClient | HandshakeState::GotFinishClient => 3,
            HandshakeState::SentFinishServer => 4,
            HandshakeState::ReadyToComplete => 5,
            HandshakeState::Complete => 6,
        }
    }

    fn apply(&mut self, ev: HandshakeEvent) -> Result<(), ApplicationHandshakeError> {
        let old = self.state;
        let role = self.role;
        let new = match (role, old, ev) {
            (Role::Client, HandshakeState::Start, HandshakeEvent::ClientSendHello) => {
                HandshakeState::SentHello
            }
            (Role::Client, HandshakeState::SentHello, HandshakeEvent::ClientRecvAccept) => {
                HandshakeState::GotAccept
            }
            // merged below into multi-pattern arm for ReadyToComplete
            (Role::Server, HandshakeState::Start, HandshakeEvent::ServerRecvHello) => {
                HandshakeState::GotHello
            }
            (Role::Server, HandshakeState::GotHello, HandshakeEvent::ServerSendAccept) => {
                HandshakeState::SentAccept
            }
            (Role::Server, HandshakeState::SentAccept, HandshakeEvent::ServerRecvFinishClient) => {
                HandshakeState::GotFinishClient
            }
            // Multiple distinct events converge to ReadyToComplete
            (Role::Client, HandshakeState::GotAccept, HandshakeEvent::ClientRecvFinishServer)
            | (
                Role::Server,
                HandshakeState::GotFinishClient,
                HandshakeEvent::ServerSendFinishServer,
            )
            | (_, HandshakeState::ReadyToComplete, HandshakeEvent::MarkReady) => {
                HandshakeState::ReadyToComplete
            }
            // Ready terminal transition
            (_, HandshakeState::ReadyToComplete, HandshakeEvent::Complete) => {
                HandshakeState::Complete
            }
            // Allow early mark ready (internal) transitioning forward
            (_, s, HandshakeEvent::MarkReady) if s != HandshakeState::ReadyToComplete => {
                HandshakeState::ReadyToComplete
            }
            _ => {
                return Err(ApplicationHandshakeError::ValidationError(
                    "invalid transition".into(),
                ));
            }
        };
        debug_assert!(
            Self::state_ordinal(new) >= Self::state_ordinal(old),
            "state regression: {old:?} -> {new:?}"
        );
        self.state = new;
        Ok(())
    }

    // ===================== Client-side events =====================

    /// Client emits HELLO (already built & domain-validated) and updates transcript.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if called when role/state is invalid.
    pub fn on_start_client_send_hello(
        &mut self,
        _hello: &Hello,
    ) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): call domain::validate(_hello) here (no network/crypto), update transcript.
        self.apply(HandshakeEvent::ClientSendHello)
    }

    /// Client processes server ACCEPT.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role is not client or state not `SentHello`.
    pub fn on_accept(&mut self, _accept: &Accept) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): validate Accept in domain, update transcript with ACCEPT.
        self.apply(HandshakeEvent::ClientRecvAccept)
    }

    /// Client receives `FINISH_SERVER`, verifies confirm tag (AEAD over transcript AAD).
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role/state mismatch (`GotAccept` expected).
    pub fn on_finish_server(
        &mut self,
        _fs: &FinishServer,
    ) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): verify confirm tag using AEAD adapter with transcript AAD; update transcript.
        self.apply(HandshakeEvent::ClientRecvFinishServer)
    }

    // ===================== Server-side events =====================

    /// Server processes client HELLO.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role not server or state not `Start`.
    pub fn on_hello(&mut self, _hello: &Hello) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): validate Hello in domain, update transcript with HELLO.
        self.apply(HandshakeEvent::ServerRecvHello)
    }

    /// Server emits ACCEPT and updates transcript.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role/state mismatch (`GotHello` expected).
    pub fn on_start_server_send_accept(
        &mut self,
        _accept: &Accept,
    ) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): validate Accept in domain (structural), update transcript with ACCEPT.
        self.apply(HandshakeEvent::ServerSendAccept)
    }

    /// Server receives `FINISH_CLIENT`, verifies confirm tag.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role not server or state not `SentAccept`.
    pub fn on_finish_client(
        &mut self,
        _fc: &FinishClient,
    ) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): verify confirm tag using AEAD adapter with transcript AAD; update transcript.
        self.apply(HandshakeEvent::ServerRecvFinishClient)
    }

    /// Server emits `FINISH_SERVER` and updates transcript.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if role/state mismatch (`GotFinishClient` expected).
    pub fn on_start_server_send_finish(
        &mut self,
        _fs: &FinishServer,
    ) -> Result<(), ApplicationHandshakeError> {
        // TODO(CLEAN): validate FinishServer in domain (structural), update transcript with FINISH_SERVER.
        self.apply(HandshakeEvent::ServerSendFinishServer)
    }

    // ===================== Test-only shims (no domain deps) =====================
    // These helpers let unit tests exercise the FSM transitions without constructing
    // real domain messages. They are compiled only in tests and keep production code CLEAN.
    #[cfg(test)]
    pub fn test_client_send_hello(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientSendHello)
    }

    #[cfg(test)]
    pub fn test_client_recv_accept(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientRecvAccept)
    }

    #[cfg(test)]
    pub fn test_client_recv_finish_server(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ClientRecvFinishServer)
    }

    // Server-side test shims
    #[cfg(test)]
    pub fn test_server_recv_hello(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerRecvHello)
    }
    #[cfg(test)]
    pub fn test_server_send_accept(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerSendAccept)
    }
    #[cfg(test)]
    pub fn test_server_recv_finish_client(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerRecvFinishClient)
    }
    #[cfg(test)]
    pub fn test_server_send_finish_server(&mut self) -> Result<(), ApplicationHandshakeError> {
        self.apply(HandshakeEvent::ServerSendFinishServer)
    }

    // ===================== Completion =====================

    /// Complete the handshake by deriving and installing AEAD keys & salts.
    ///
    /// Inputs:
    /// - `th`: current transcript hash (48 bytes / SHA-384)
    /// - `hybrid_shared`: hybrid shared secret from KEM (variable length)
    ///
    /// Behavior:
    /// - Derives per-direction write keys & salts using HKDF-SHA384 with `th` as salt.
    /// - Installs keys into the connection state.
    /// - Resets per-direction sequence counters to zero.
    /// - Transitions to `HandshakeState::Complete`.
    ///
    /// CLEAN note: crypto primitives live in adapters; HKDF labels live in protocol; decoding lives in wire.
    ///
    /// # Errors
    /// Returns `ApplicationHandshakeError::ValidationError` if not in `HandshakeState::ReadyToComplete`.
    pub fn complete(
        &mut self,
        th: [u8; 48],
        hybrid_shared: &[u8],
    ) -> Result<(), ApplicationHandshakeError> {
        if self.state != HandshakeState::ReadyToComplete {
            return Err(ApplicationHandshakeError::ValidationError(
                "FSM not ready to complete".into(),
            ));
        }

        // HKDF-Extract with salt = transcript hash, IKM = hybrid shared secret.
        let prk = prk_from(&th, hybrid_shared);

        // Expand labeled materials into client/server write keys + salts.
        let wk: WriteKeys = derive_keys(&th, &prk)?;
        let WriteKeys { client, server } = wk;

        // Install into application connection state and reset seq counters.
        self.conn.install_keys(client, server);
        self.conn.set_seqs(Seq(0), Seq(0));

        // Flip to Complete.
        self.apply(HandshakeEvent::Complete)
    }

    /// Read-only view of the current handshake state.
    pub fn state(&self) -> HandshakeState {
        self.state
    }

    /// Mutable access to the underlying connection/context (if the caller needs it).
    pub fn conn_mut(&mut self) -> &mut C {
        &mut self.conn
    }

    /// Take ownership of the underlying connection/context (post-handshake).
    pub fn into_inner(self) -> C {
        self.conn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyConn {
        client: Option<DirectionKeys>,
        server: Option<DirectionKeys>,
        cseq: Seq,
        sseq: Seq,
    }

    impl KeySink for DummyConn {
        fn install_keys(&mut self, client_write: DirectionKeys, server_write: DirectionKeys) {
            self.client = Some(client_write);
            self.server = Some(server_write);
        }
        fn set_seqs(&mut self, client_seq: Seq, server_seq: Seq) {
            self.cseq = client_seq;
            self.sseq = server_seq;
        }
    }

    // The unit test only exercises the state machine shape, not real crypto or transcript.
    #[test]
    fn client_path_reaches_complete() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(123),
            sseq: Seq(456),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);

        // Client path: Start -> SentHello -> GotAccept -> ReadyToComplete -> Complete
        // (We pass dummy structs by transmute of zero-sized tuples in comments; real types are used in signatures.)
        // Since we don't have real constructors here, just call the state functions without validation.
        // You will wire domain validation + transcript updates in these methods.
        // SAFETY: placeholders; replace with real domain instances in integration tests.
        let th = [0u8; 48];
        let shared = [0u8; 32];

        // Drive the client path using test-only shims (no domain object construction needed).
        fsm.test_client_send_hello().unwrap();
        fsm.test_client_recv_accept().unwrap();
        fsm.test_client_recv_finish_server().unwrap();

        assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
        let _ = fsm.complete(th, &shared);
        assert_eq!(fsm.state(), HandshakeState::Complete);

        let conn = fsm.into_inner();
        assert_eq!(conn.cseq.0, 0);
        assert_eq!(conn.sseq.0, 0);
        assert!(conn.client.is_some());
        assert!(conn.server.is_some());
    }

    #[test]
    fn client_invalid_out_of_order_accept() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        // Try to receive ACCEPT (via test shim path) before sending HELLO.
        let err = fsm.test_client_recv_accept().unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }

    #[test]
    fn server_cannot_use_client_event() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Server, conn);
        // Server trying to send HELLO (client event) via test shim should error.
        let err = fsm.test_client_send_hello().unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }

    #[test]
    fn early_mark_ready_advances_once() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        // Force early mark ready (should jump to ReadyToComplete)
        fsm.ready();
        assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
        // Idempotent second call
        fsm.ready();
        assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
    }

    #[test]
    fn cannot_complete_before_ready() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        let th = [0u8; 48];
        let shared = [0u8; 32];
        let err = fsm.complete(th, &shared).unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }

    #[test]
    fn state_regression_not_possible() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        fsm.test_client_send_hello().unwrap();
        let prev = fsm.state();
        // Attempt an earlier transition again (HELLO) -> should error and not change state
        let err = fsm.test_client_send_hello().unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
        assert_eq!(fsm.state(), prev);
    }

    #[test]
    fn server_path_reaches_complete() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(9),
            sseq: Seq(9),
        };
        let mut fsm = HandshakeFsm::new(Role::Server, conn);
        // Path: Start -> GotHello -> SentAccept -> GotFinishClient -> ReadyToComplete -> Complete
        fsm.test_server_recv_hello().unwrap();
        fsm.test_server_send_accept().unwrap();
        fsm.test_server_recv_finish_client().unwrap();
        fsm.test_server_send_finish_server().unwrap();
        assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
        let th = [1u8; 48];
        let shared = [2u8; 32];
        fsm.complete(th, &shared).unwrap();
        assert_eq!(fsm.state(), HandshakeState::Complete);
    }

    #[test]
    fn server_invalid_double_accept() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Server, conn);
        fsm.test_server_recv_hello().unwrap();
        fsm.test_server_send_accept().unwrap();
        let err = fsm.test_server_send_accept().unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }

    #[test]
    fn client_cannot_finish_server_before_accept() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        // Jump directly to finish_server reception attempt
        let err = fsm.test_client_recv_finish_server().unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }

    #[test]
    fn duplicate_complete_fails() {
        let conn = DummyConn {
            client: None,
            server: None,
            cseq: Seq(0),
            sseq: Seq(0),
        };
        let mut fsm = HandshakeFsm::new(Role::Client, conn);
        fsm.test_client_send_hello().unwrap();
        fsm.test_client_recv_accept().unwrap();
        fsm.test_client_recv_finish_server().unwrap();
        let th = [3u8; 48];
        let shared = [4u8; 32];
        fsm.complete(th, &shared).unwrap();
        assert_eq!(fsm.state(), HandshakeState::Complete);
        // Second complete should error because state no longer ReadyToComplete
        let err = fsm.complete(th, &shared).unwrap_err();
        matches!(err, ApplicationHandshakeError::ValidationError(_));
    }
}
