//! Handshake frame preamble and helpers.

use crate::core::cbor::CodecError; // if/when you rename to core::cbor, update this path

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Hello        = 0x01,
    Accept       = 0x02,
    FinishClient = 0x03,
    FinishServer = 0x04,
}

impl TryFrom<u8> for FrameType {
    type Error = CodecError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Accept),
            0x03 => Ok(Self::FinishClient),
            0x04 => Ok(Self::FinishServer),
            _ => Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown handshake frame type: 0x{v:02x}"),
            )))),
        }
    }
}

#[inline]
pub fn prepend_frame(ft: FrameType, payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(ft as u8);
    out.extend_from_slice(&payload);
    out
}

#[inline]
pub fn split_frame(input: &[u8]) -> Result<(FrameType, &[u8]), CodecError> {
    if input.is_empty() {
        return Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "empty handshake frame",
        ))));
    }
    let ft = FrameType::try_from(input[0])?;
    Ok((ft, &input[1..]))
}