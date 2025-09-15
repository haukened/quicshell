use crate::domain::handshake::{Accept, FinishClient, FinishServer, Hello};

#[derive(thiserror::Error, Debug)]
pub enum WireError {
    #[error("codec error: {0}")]
    Codec(String),
}

/// Borrowing enum over all handshake message types for a unified transcript encoder.
pub enum HandshakeTranscriptRef<'a> {
    Hello(&'a Hello),
    Accept(&'a Accept),
    FinishClient(&'a FinishClient),
    FinishServer(&'a FinishServer),
}

pub trait HandshakeWire {
    /// Encode canonical (pad-stripped) transcript bytes for any handshake message.
    ///
    /// # Errors
    /// Returns `WireError::Codec` if encoding fails or canonicalization cannot be produced.
    fn encode_transcript(&self, msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError>;
}
