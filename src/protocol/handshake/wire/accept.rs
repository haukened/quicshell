//! Wire encoding for ACCEPT (stubs)

use crate::core::cbor::{from_cbor, to_cbor, CodecError};
use crate::domain::handshake::Accept;
use super::frame::{FrameType, prepend_frame, split_frame};

pub fn encode_wire_accept(a: &Accept) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(a)?;
    Ok(prepend_frame(FrameType::Accept, cbor))
}

pub fn decode_wire_accept(bytes: &[u8]) -> Result<Accept, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::Accept {
        return Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected ACCEPT frame",
        ))));
    }
    from_cbor(payload)
}

pub fn encode_transcript_accept(a: &Accept) -> Result<Vec<u8>, CodecError> {
    let mut tmp = a.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}