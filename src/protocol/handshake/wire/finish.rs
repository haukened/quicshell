//! Wire encoding for FINISH_CLIENT / FINISH_SERVER (stubs)

use crate::core::cbor::{to_cbor, from_cbor, CodecError};
use crate::domain::handshake::{FinishClient, FinishServer};
use super::frame::{FrameType, prepend_frame, split_frame};

pub fn encode_wire_finish_client(fc: &FinishClient) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(fc)?;
    Ok(prepend_frame(FrameType::FinishClient, cbor))
}

pub fn decode_wire_finish_client(bytes: &[u8]) -> Result<FinishClient, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::FinishClient {
        return Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected FINISH_CLIENT frame",
        ))));
    }
    from_cbor(payload)
}

pub fn encode_wire_finish_server(fs: &FinishServer) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(fs)?;
    Ok(prepend_frame(FrameType::FinishServer, cbor))
}

pub fn decode_wire_finish_server(bytes: &[u8]) -> Result<FinishServer, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::FinishServer {
        return Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected FINISH_SERVER frame",
        ))));
    }
    from_cbor(payload)
}

pub fn encode_transcript_finish_client(fc: &FinishClient) -> Result<Vec<u8>, CodecError> {
    let mut tmp = fc.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}

pub fn encode_transcript_finish_server(fs: &FinishServer) -> Result<Vec<u8>, CodecError> {
    let mut tmp = fs.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}