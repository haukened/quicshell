//! core/codec/codec.rs — generic CBOR codec helpers used across qsh
//!
//! This module is *infrastructure*, not domain-specific:
//! - `to_cbor` serializes any `T: Serialize` using **ciborium** (deterministic by default).
//! - `from_cbor` deserializes, always strict (no trailing bytes) and
//!   always rejects non-canonical encodings (fail when bytes are not the unique deterministic form).
//!
//! 🔎 Notes:
//! - `from_cbor` expects exactly the CBOR payload (no framing/preambles). If you have a frame preamble, strip it
//!   before calling `from_cbor` (the protocol adapter does this).
//! - `ciborium` emits deterministic/canonical encodings by default.

use serde::{Serialize, de::DeserializeOwned};
use std::io::Cursor;

/// Errors produced by the generic codec.
#[derive(thiserror::Error, Debug)]
pub enum CodecError {
    /// Error produced during serialization.
    #[error("CBOR serialize error: {0}")]
    Ser(#[from] ciborium::ser::Error<std::io::Error>),

    /// Error produced during deserialization.
    #[error("CBOR deserialize error: {0}")]
    De(#[from] ciborium::de::Error<std::io::Error>),

    /// The input bytes were well-formed CBOR but not in deterministic form while
    /// decoding.
    #[error("CBOR input is not in canonical/deterministic form")]
    NonCanonical,
}

/// Serialize any `T: Serialize` to CBOR bytes (deterministic under ciborium).
///
/// # Errors
///
/// Returns a [`CodecError::Ser`] if serialization fails.
pub fn to_cbor<T: Serialize>(v: &T) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(v, &mut buf)?;
    Ok(buf)
}

/// Deserialize any `T: DeserializeOwned + Serialize` from CBOR bytes.
///
/// This function always enforces strict decoding:
/// * Rejects trailing garbage after a valid item.
/// * Rejects non-canonical encodings by re-encoding deterministically and
///   requiring an exact byte-for-byte match to the input.
///
/// # Errors
///
/// * [`CodecError::De`] if deserialization fails or there are trailing bytes.
/// * [`CodecError::NonCanonical`] if the input is well‑formed but not canonical.
pub fn from_cbor<T: DeserializeOwned + Serialize>(b: &[u8]) -> Result<T, CodecError> {
    let mut cur = Cursor::new(b);
    let value: T = ciborium::de::from_reader(&mut cur)?;
    // Strict: no trailing bytes
    let pos = usize::try_from(cur.position()).map_err(|_| {
        CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "cursor position overflow",
        )))
    })?;
    if pos != b.len() {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing bytes after CBOR value",
            ),
        )));
    }
    // Canonical enforcement: deterministic re-encode must match input
    // see docs/canonical_cbor.md for rationale
    let canon = to_cbor(&value)?;
    if canon != b {
        return Err(CodecError::NonCanonical);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Demo {
        a: u8,
        b: u8,
    }

    #[test]
    fn roundtrip_deterministic_ok() {
        let v = Demo { a: 1, b: 2 };
        let bytes = to_cbor(&v).unwrap();
        let out: Demo = from_cbor(&bytes).unwrap();
        assert_eq!(v, out);
    }

    #[test]
    fn strict_rejects_trailing() {
        let v = Demo { a: 3, b: 4 };
        let mut bytes = to_cbor(&v).unwrap();
        // append another CBOR item (an int 0)
        let mut tail = Vec::new();
        ciborium::ser::into_writer(&0u8, &mut tail).unwrap();
        bytes.extend_from_slice(&tail);
        let err = from_cbor::<Demo>(&bytes).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("trailing"));
    }

    #[test]
    fn deterministic_and_strict_decode_ok() {
        let v = Demo { a: 5, b: 6 };
        // ciborium is deterministic; repeated encodes should be identical
        let bytes1 = to_cbor(&v).unwrap();
        let bytes2 = to_cbor(&v).unwrap();
        assert_eq!(bytes1, bytes2);
        // And strict canonical decode should accept our own bytes
        let _out: Demo = from_cbor(&bytes1).unwrap();
    }
}
