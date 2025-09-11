//! Handshake frame utilities.
//!
//! This module defines the `FrameType` discriminant used during the handshake
//! phase along with helper functions for framing and deframing raw payloads.
//!
//! Frames on the wire are encoded as:
//!   [ 1-byte frame type | variable-length payload ]
//!
//! The first byte is mapped to `FrameType`. Unknown or missing discriminants
//! yield a `CodecError::De` with an underlying `std::io::Error` describing the
//! issue (either `InvalidData` for unknown types or `UnexpectedEof` for empty
//! input).
//!
//! Provided helpers:
//! - `FrameType` enum: Enumerates all supported handshake frame kinds.
//! - `TryFrom<u8> for FrameType`: Safe conversion from raw discriminant.
//! - `prepend_frame`: Prefixes a payload with its frame type byte.
//! - `split_frame`: Splits a raw buffer into `(FrameType, payload)`.
//!
//! Typical usage when encoding:
//! ```ignore
//! let raw_payload = serialize_handshake_hello(...)?;
//! let framed = prepend_frame(FrameType::Hello, raw_payload);
//! transport.send(&framed).await?;
//! ```
//!
//! Typical usage when decoding:
//! ```ignore
//! let (ty, body) = split_frame(&incoming_bytes)?;
//! match ty {
//!     FrameType::Hello => handle_hello(body)?,
//!     FrameType::Accept => handle_accept(body)?,
//!     FrameType::FinishClient => handle_finish_client(body)?,
//!     FrameType::FinishServer => handle_finish_server(body)?,
//! }
//! ```
//!
//! Error semantics:
//! - Empty input: `UnexpectedEof` via `CodecError::De`.
//! - Unknown discriminant: `InvalidData` via `CodecError::De` with a hex tag.
//!
//! Invariants / guarantees:
//! - `prepend_frame` always allocates exactly `1 + payload.len()` capacity.
//! - `split_frame` never copies the payload; it returns a slice into the input.
//! - `FrameType` values are stable and explicitly assigned (`repr(u8)`).
//!
//! Extension guidance:
//! - When adding a new frame type, append a new explicit discriminant.
//! - Update the `TryFrom<u8>` match and any higher-level dispatch logic.
//! - Consider versioning if wire compatibility becomes a concern.
//!
//! Performance notes:
//! - All helpers are `#[inline]` to encourage monomorphization in hot paths.
//! - Conversion and slicing are zero-copy aside from the single-byte push in
//!   `prepend_frame`.
//!   Handshake frame preamble and helpers.

use crate::core::cbor::CodecError;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// A HELLO frame, sent by the client to initiate a handshake.
    Hello = 0x01,
    /// An ACCEPT frame, sent by the server in response to a HELLO.
    Accept = 0x02,
    /// A `FINISH_CLIENT` frame, sent by the client to finalize the handshake.
    FinishClient = 0x03,
    /// A `FINISH_SERVER` frame, sent by the server to finalize the handshake.
    FinishServer = 0x04,
}

/// Attempts to convert a raw `u8` value into a `FrameType`.
///
/// Supported mappings:
/// - `0x01` => `FrameType::Hello`
/// - `0x02` => `FrameType::Accept`
/// - `0x03` => `FrameType::FinishClient`
/// - `0x04` => `FrameType::FinishServer`
///
/// Any other value results in a `CodecError::De` wrapping an `std::io::Error`
/// of kind `InvalidData`, with a message indicating the unknown frame type.
///
/// This is typically used when decoding handshake frames from the wire, ensuring
/// that only recognized frame discriminants are accepted.
impl TryFrom<u8> for FrameType {
    type Error = CodecError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Hello),
            0x02 => Ok(Self::Accept),
            0x03 => Ok(Self::FinishClient),
            0x04 => Ok(Self::FinishServer),
            _ => Err(CodecError::De(ciborium::de::Error::Io(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown handshake frame type: 0x{v:02x}"),
                ),
            ))),
        }
    }
}

/// Prepends a frame type byte to the given payload, returning a new `Vec<u8>`.
///
/// # Errors
///
/// This function is infallible; the section is present to satisfy pedantic lint expectations.
#[must_use]
#[inline]
pub fn prepend_frame(ft: FrameType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(ft as u8);
    out.extend_from_slice(payload);
    out
}

/// Splits a raw input buffer into its frame type and payload.
///
/// # Errors
///
/// * Returns an error if the input is empty.
/// * Returns an error if the frame type byte is unknown.
/// * Returns CBOR-style decode errors propagated via `CodecError::De`.
#[inline]
pub fn split_frame(input: &[u8]) -> Result<(FrameType, &[u8]), CodecError> {
    if input.is_empty() {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty handshake frame"),
        )));
    }
    let ft = FrameType::try_from(input[0])?;
    Ok((ft, &input[1..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn try_from_u8_known_values() {
        assert_eq!(FrameType::try_from(0x01).unwrap(), FrameType::Hello);
        assert_eq!(FrameType::try_from(0x02).unwrap(), FrameType::Accept);
        assert_eq!(FrameType::try_from(0x03).unwrap(), FrameType::FinishClient);
        assert_eq!(FrameType::try_from(0x04).unwrap(), FrameType::FinishServer);
    }

    #[test]
    fn try_from_u8_unknown_value() {
        let err = FrameType::try_from(0xFF).unwrap_err();
        match err {
            CodecError::De(ciborium::de::Error::Io(io_err)) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
                assert!(io_err.to_string().contains("unknown handshake frame type"));
            }
            _ => panic!("expected CodecError::De with Io error"),
        }
    }

    #[test]
    fn prepend_a_frame() {
        let payload = [0xAA, 0xBB, 0xCC];
        let framed = prepend_frame(FrameType::Accept, &payload);
        assert_eq!(framed[0], FrameType::Accept as u8);
        assert_eq!(&framed[1..], &payload);
    }

    #[test]
    fn split_a_frame() {
        let framed = vec![FrameType::FinishClient as u8, 0xDE, 0xAD, 0xBE, 0xEF];
        let (ft, payload) = split_frame(&framed).unwrap();
        assert_eq!(ft, FrameType::FinishClient);
        assert_eq!(payload, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn split_empty_frame_fails() {
        let err = split_frame(&[]).unwrap_err();
        match err {
            CodecError::De(ciborium::de::Error::Io(io_err)) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
                assert!(io_err.to_string().contains("empty handshake frame"));
            }
            _ => panic!("expected CodecError::De with Io error"),
        }
    }

    #[test]
    fn prepend_capacity_exact() {
        let payload = [0u8; 8];
        let framed = prepend_frame(FrameType::Hello, &payload);
        assert_eq!(framed.len(), 1 + payload.len());
        assert_eq!(&framed[1..], &payload);
    }

    #[test]
    fn split_frame_zero_copy_slice() {
        let payload = [1, 2, 3];
        let framed = prepend_frame(FrameType::FinishServer, &payload);
        let ptr_base = framed.as_ptr();
        let (_ft, slice) = split_frame(&framed).unwrap();
        let ptr_slice = slice.as_ptr();
        assert_eq!(
            unsafe { ptr_slice.offset(-1) },
            ptr_base,
            "slice should be view into original buffer"
        );
    }

    proptest! {
        #[test]
        fn prop_round_trip(data in prop::collection::vec(any::<u8>(), 0..128)) {
            let framed = prepend_frame(FrameType::Accept, &data);
            let (ty, body) = split_frame(&framed).unwrap();
            prop_assert_eq!(ty, FrameType::Accept);
            prop_assert_eq!(body, &data[..]);
        }
    }
}
