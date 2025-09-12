//! Handshake transcript (SHA-384) over pad-stripped canonical CBOR encodings.
//!
//! ## Responsibilities
//! - Consume pad-stripped **canonical CBOR** encodings for HELLO/ACCEPT/FINISH* from
//!   `protocol::handshake::wire::encode_transcript_*`.
//! - Maintain a running **SHA-384** over those bytes, in strict message order.
//! - Provide the current transcript hash (`th()`) for the key schedule.
//! - Provide **AAD** bytes for confirm-tag AEAD (client/server), which include a tiny
//!   context prefix and the confirm frame type byte, but **not** the entire frame.
//!
//! ## Non-responsibilities
//! - No CBOR encoding logic (delegated to `core::cbor` + `protocol::handshake::wire`).
//! - No domain validation (application layer must validate before use).
//! - No AEAD/HKDF—the crypto adapter consumes `th()` and AAD.

use crate::domain::handshake::{Accept, FinishClient, FinishServer, Hello};
use crate::protocol::handshake::wire::{
    FrameType, encode_transcript_accept, encode_transcript_finish_client,
    encode_transcript_finish_server, encode_transcript_hello,
};
use sha2::{Digest, Sha384};

/// qsh protocol string prefix for AAD.
const AAD_PREFIX: &[u8] = b"QSH"; // ASCII literal, stable across versions
/// Current protocol version for AAD context.
const AAD_VERSION: u8 = 0x01; // v1

/// Transcript over the handshake control-plane.
#[derive(Clone, Debug)]
pub struct Transcript {
    hasher: Sha384,
}

impl Transcript {
    /// Create a new, empty transcript (SHA-384 state).
    #[must_use]
    pub fn new() -> Self {
        Self {
            hasher: Sha384::new(),
        }
    }

    /// Return the current transcript hash (SHA-384) without consuming the state.
    #[must_use]
    pub fn th(&self) -> [u8; 48] {
        let clone = self.hasher.clone();
        let digest = clone.finalize();
        let mut out = [0u8; 48];
        out.copy_from_slice(&digest);
        out
    }

    /// Feed `HELLO` (pad stripped) into the transcript.
    ///
    /// # Errors
    /// Returns `Err` if CBOR wire encoding of the `HELLO` message fails.
    pub fn push_hello(&mut self, hello: &Hello) -> Result<(), TranscriptError> {
        let bytes = encode_transcript_hello(hello)?;
        self.hasher.update(&bytes);
        Ok(())
    }

    /// Feed `ACCEPT` (pad stripped) into the transcript.
    ///
    /// # Errors
    /// Returns `Err` if CBOR wire encoding of the `ACCEPT` message fails.
    pub fn push_accept(&mut self, accept: &Accept) -> Result<(), TranscriptError> {
        let bytes = encode_transcript_accept(accept)?;
        self.hasher.update(&bytes);
        Ok(())
    }

    /// Feed `FINISH_CLIENT` (pad stripped) into the transcript.
    ///
    /// # Errors
    /// Returns `Err` if CBOR wire encoding of the `FINISH_CLIENT` message fails.
    pub fn push_finish_client(&mut self, fc: &FinishClient) -> Result<(), TranscriptError> {
        let bytes = encode_transcript_finish_client(fc)?;
        self.hasher.update(&bytes);
        Ok(())
    }

    /// Feed `FINISH_SERVER` (pad stripped) into the transcript.
    ///
    /// # Errors
    /// Returns `Err` if CBOR wire encoding of the `FINISH_SERVER` message fails.
    pub fn push_finish_server(&mut self, fs: &FinishServer) -> Result<(), TranscriptError> {
        let bytes = encode_transcript_finish_server(fs)?;
        self.hasher.update(&bytes);
        Ok(())
    }

    /// AAD for the client confirm tag AEAD.
    ///
    /// Layout (stable):
    /// ```text
    ///   AAD := b"QSH" || version:u8 || frame_type:u8 || th:48
    /// ```
    /// where `frame_type` is `FrameType::FinishClient as u8` for the client confirm.
    #[must_use]
    pub fn aad_client_confirm(&self) -> [u8; 3 + 1 + 1 + 48] {
        self.aad_for(FrameType::FinishClient)
    }

    /// AAD for the server confirm tag AEAD.
    ///
    /// Layout (stable):
    /// ```text
    ///   AAD := b"QSH" || version:u8 || frame_type:u8 || th:48
    /// ```
    /// where `frame_type` is `FrameType::FinishServer as u8` for the server confirm.
    #[must_use]
    pub fn aad_server_confirm(&self) -> [u8; 3 + 1 + 1 + 48] {
        self.aad_for(FrameType::FinishServer)
    }

    fn aad_for(&self, ft: FrameType) -> [u8; 3 + 1 + 1 + 48] {
        let mut out = [0u8; 3 + 1 + 1 + 48];
        // prefix
        out[..3].copy_from_slice(AAD_PREFIX);
        // version
        out[3] = AAD_VERSION;
        // frame type byte
        out[4] = ft as u8;
        // transcript hash
        out[5..].copy_from_slice(&self.th());
        out
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur while producing transcript bytes.
#[derive(thiserror::Error, Debug)]
pub enum TranscriptError {
    #[error("wire-encode error: {0}")]
    Wire(#[from] crate::core::cbor::CodecError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{mk_accept, mk_finish_client, mk_finish_server, mk_hello};

    #[test]
    fn hello_pad_stripping_produces_same_hash() {
        let mut t1 = Transcript::new();
        let mut h = mk_hello();
        // no pad
        t1.push_hello(&h).unwrap();
        let th1 = t1.th();

        // with pad present (wire::encode_transcript_hello will strip it)
        let mut t2 = Transcript::new();
        h.pad = Some(vec![0xaa; 8]);
        t2.push_hello(&h).unwrap();
        let th2 = t2.th();

        assert_eq!(th1, th2, "pad MUST NOT affect transcript");
    }

    #[test]
    fn aad_client_vs_server_are_distinct_and_include_th() {
        let mut t = Transcript::new();
        let h = mk_hello();
        t.push_hello(&h).unwrap();
        let a_client = t.aad_client_confirm();
        let a_server = t.aad_server_confirm();
        assert_ne!(a_client, a_server, "client/server AAD must differ");
        // header is 3 + 1 + 1, trailing 48 bytes are the transcript hash
        assert_eq!(&a_client[0..3], b"QSH");
        assert_eq!(a_client[3], 0x01);
        assert_eq!(a_client[4], FrameType::FinishClient as u8);
        assert_eq!(&a_client[5..], &t.th());
        assert_eq!(&a_server[5..], &t.th());
    }

    #[test]
    fn accept_affects_transcript() {
        let mut t = Transcript::new();
        let h = mk_hello();
        t.push_hello(&h).unwrap();
        let th_before = t.th();

        let a = mk_accept();
        t.push_accept(&a).unwrap();
        let th_after = t.th();
        assert_ne!(th_before, th_after, "ACCEPT must update transcript");
    }

    #[test]
    fn padded_accept_and_unpadded_accept_produce_same_increment() {
        let mut t1 = Transcript::new();
        t1.push_hello(&mk_hello()).unwrap();
        let a = mk_accept();
        t1.push_accept(&a).unwrap();
        let th1 = t1.th();

        let mut t2 = Transcript::new();
        t2.push_hello(&mk_hello()).unwrap();
        let a_pad = {
            let mut a2 = a.clone();
            a2.pad = Some(vec![0xbb; 16]);
            a2
        };
        t2.push_accept(&a_pad).unwrap();
        let th2 = t2.th();

        assert_eq!(th1, th2, "pad MUST NOT affect transcript for ACCEPT");
    }

    #[test]
    fn finish_client_updates_transcript_and_pad_stripped() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();
        let h = mk_hello();
        t1.push_hello(&h).unwrap();
        t2.push_hello(&h).unwrap();
        let a = mk_accept();
        t1.push_accept(&a).unwrap();
        t2.push_accept(&a).unwrap();
        let th_before = t1.th();

        // Unpadded finish client
        let fc = mk_finish_client();
        t1.push_finish_client(&fc).unwrap();

        // Padded variant
        let mut fc_pad = fc.clone();
        fc_pad.pad = Some(vec![0xAA; 32]);
        t2.push_finish_client(&fc_pad).unwrap();

        let th_after_unpadded = t1.th();
        let th_after_padded = t2.th();
        assert_ne!(
            th_before, th_after_unpadded,
            "FINISH_CLIENT must update transcript"
        );
        assert_eq!(
            th_after_unpadded, th_after_padded,
            "pad MUST NOT affect transcript for FINISH_CLIENT"
        );
    }

    #[test]
    fn finish_server_updates_transcript_and_pad_stripped() {
        let mut t1 = Transcript::new();
        let mut t2 = Transcript::new();
        let h = mk_hello();
        t1.push_hello(&h).unwrap();
        t2.push_hello(&h).unwrap();
        let a = mk_accept();
        t1.push_accept(&a).unwrap();
        t2.push_accept(&a).unwrap();
        let fc = mk_finish_client();
        t1.push_finish_client(&fc).unwrap();
        t2.push_finish_client(&fc).unwrap();
        let th_before = t1.th();

        // Unpadded finish server
        let fs = mk_finish_server();
        t1.push_finish_server(&fs).unwrap();

        // Padded variant
        let mut fs_pad = fs.clone();
        fs_pad.pad = Some(vec![0xBB; 24]);
        t2.push_finish_server(&fs_pad).unwrap();

        let th_after_unpadded = t1.th();
        let th_after_padded = t2.th();
        assert_ne!(
            th_before, th_after_unpadded,
            "FINISH_SERVER must update transcript"
        );
        assert_eq!(
            th_after_unpadded, th_after_padded,
            "pad MUST NOT affect transcript for FINISH_SERVER"
        );
    }
}
