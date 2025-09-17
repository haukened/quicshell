//! Handshake boundary port traits and lightweight enums shared by application
//! (FSM orchestration) and lower protocol/adapters.
//!
//! This module centralizes the transcript and wire encoding abstractions so
//! that protocol code (canonical encoding, hashing) does not import from the
//! application layer, preserving CLEAN dependency direction. The handshake
//! finite state machine lives in `application::handshake`; only the pure
//! boundary contracts needed by protocol/adapters reside here.
use crate::domain::handshake::{Accept, FinishClient, FinishServer, Hello};

/// Error type for handshake wire encoding operations.
#[derive(thiserror::Error, Debug)]
pub enum WireError {
    /// Underlying canonical encoding / codec failure (stringified cause).
    #[error("codec error: {0}")]
    Codec(String),
}

/// Borrowing enum over all handshake message variants for transcript encoding.
pub enum HandshakeTranscriptRef<'a> {
    /// Borrowed `HELLO` message.
    Hello(&'a Hello),
    /// Borrowed `ACCEPT` message.
    Accept(&'a Accept),
    /// Borrowed `FINISH_CLIENT` message.
    FinishClient(&'a FinishClient),
    /// Borrowed `FINISH_SERVER` message.
    FinishServer(&'a FinishServer),
}

/// Port abstraction used to accumulate the canonical transcript hash.
///
/// Responsibilities:
/// - Accept already *canonical* (deterministic CBOR) bytes via
///   `absorb_canonical()`.
/// - Provide the running transcript hash (SHA-384) through `hash()`.
///
/// Invariants / Safety:
/// - Callers MUST pass only deterministic CBOR encodings of entire handshake
///   structures (`HELLO`, `ACCEPT`, `FINISH_CLIENT`, `FINISH_SERVER`).
/// - Implementations MUST treat identical byte slices deterministically and
///   MUST NOT perform internal re-encoding.
pub trait TranscriptPort {
    /// Absorb canonical CBOR bytes for a single handshake structure.
    fn absorb_canonical(&mut self, bytes: &[u8]);
    /// Return the current transcript hash (fixed 48-byte SHA-384 output).
    fn hash(&self) -> [u8; 48];
}

/// Wire-level canonical transcript encoder abstraction.
pub trait HandshakeWire {
    /// Encode canonical (pad-stripped) bytes for any handshake message.
    ///
    /// Errors:
    /// - `WireError::Codec` if canonical encoding fails.
    fn encode_transcript(&self, msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError>;
}

/// Sink interface allowing the handshake FSM to install derived write keys
/// and initial sequence counters into an owning connection/session. The
/// concrete `WriteKeys` type lives in the protocol layer; the FSM passes the
/// composite object to this sink exactly once on success. This trait remains
/// here because it forms part of the boundary contract outward from the FSM.
pub trait KeySink {
    /// Install negotiated composite write keys (both directions).
    fn install_write_keys(&mut self, keys: crate::protocol::handshake::keyschedule::WriteKeys);
    /// Set initial sequence counters for application data protection.
    fn set_seqs(
        &mut self,
        client_seq: crate::ports::crypto::Seq,
        server_seq: crate::ports::crypto::Seq,
    );
}
