use thiserror::Error;

use crate::core::cbor::CodecError;
use crate::core::crypto::hkdf::HkdfError;
use crate::ports::crypto::AeadError;
use crate::protocol::handshake::transcript::TranscriptError;

/// High-level errors that can occur during the handshake orchestration (FSM).
#[derive(Debug, Error)]
pub enum ApplicationHandshakeError {
    #[error("transcript mismatch or invalid")]
    TranscriptInvalid,

    #[error("KEM failure: {0}")]
    KemFailure(String),

    #[error("AEAD failure: {0}")]
    AeadFailure(#[from] AeadError),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    #[error("transcript error: {0}")]
    Transcript(#[from] TranscriptError),

    #[error("key schedule error: {0}")]
    Hkdf(#[from] HkdfError),

    #[error("handshake timed out")]
    Timeout,

    #[error("handshake was cancelled")]
    Cancelled,
}
