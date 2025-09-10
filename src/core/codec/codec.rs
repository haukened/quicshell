//! core/codec/codec.rs — generic CBOR codec helpers used across qsh
//!
//! This module is *infrastructure*, not domain-specific:
//! - `to_cbor` serializes any `T: Serialize` using **ciborium** (deterministic by default).
//! - `from_cbor` deserializes with optional **strict** (no trailing bytes) and
//!   **reject_noncano** (fail when bytes are not the unique deterministic form).
//!
//! 🔎 Notes:
//! - `reject_noncano` is meaningful only when you pass **exactly** the CBOR
//!   payload (no framing/preambles). If you have a frame preamble, strip it
//!   before calling `from_cbor` (the protocol adapter does this).
//! - `ciborium` emits deterministic/canonical encodings by default, so
//!   `CborMode::Canonical` and `CborMode::Default` are equivalent here. The
//!   enum is kept for forward compatibility.

use serde::{de::DeserializeOwned, Serialize};
use std::io::Cursor;

/// Controls how CBOR is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborMode {
    /// Deterministic/canonical form (ciborium default).
    Canonical,
    /// Library default (same as Canonical for ciborium).
    Default,
}

/// Options for decoding CBOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOpts {
    /// If true, reject any trailing bytes after a successful decode.
    pub strict: bool,
    /// If true, re-encode the decoded value deterministically and fail if the
    /// input bytes are not byte-for-byte identical to that encoding.
    pub reject_noncano: bool,
}

/// Common decode policies.
pub const STRICT_CANON: DecodeOpts = DecodeOpts { strict: true, reject_noncano: true };
pub const STRICT_ALLOW_NONCANON: DecodeOpts = DecodeOpts { strict: true, reject_noncano: false };

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
    /// `DecodeOpts.reject_noncano` was set.
    #[error("CBOR input is not in canonical/deterministic form")]
    NonCanonical,
}

/// Serialize any `T: Serialize` to CBOR bytes (deterministic by default under ciborium).
pub fn to_cbor<T: Serialize>(v: &T, _mode: CborMode) -> Result<Vec<u8>, CodecError> {
    let mut buf = Vec::with_capacity(256);
    ciborium::ser::into_writer(v, &mut buf)?;
    Ok(buf)
}

/// Convenience: canonical (deterministic) CBOR bytes for `v`.
pub fn to_cbor_canonical<T: Serialize>(v: &T) -> Result<Vec<u8>, CodecError> {
    to_cbor(v, CborMode::Canonical)
}

/// Deserialize any `T: DeserializeOwned` from CBOR bytes using options.
///
/// * When `opts.strict` is true, this rejects trailing garbage after a valid item.
/// * When `opts.reject_noncano` is true, this re-encodes the decoded value in a
///   deterministic manner and requires an exact byte-for-byte match to the input.
/// * When `opts.reject_noncano` is true, `T` must also implement `Serialize` so we can re-encode.
pub fn from_cbor<T: DeserializeOwned + Serialize>(b: &[u8], opts: DecodeOpts) -> Result<T, CodecError> {
    let mut cur = Cursor::new(b);
    let value: T = ciborium::de::from_reader(&mut cur)?;

    if opts.strict {
        // Strict mode: reject any trailing bytes after a single CBOR item.
        if (cur.position() as usize) != b.len() {
            return Err(CodecError::De(ciborium::de::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trailing bytes after CBOR value",
            ))));
        }
    }

    if opts.reject_noncano {
        let canon = to_cbor_canonical(&value)?;
        if canon != b {
            return Err(CodecError::NonCanonical);
        }
    }

    Ok(value)
}

/// Convenience: strict + canonical decode.
pub fn from_cbor_strict_canonical<T: DeserializeOwned + Serialize>(b: &[u8]) -> Result<T, CodecError> {
    from_cbor(b, STRICT_CANON)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Demo { a: u8, b: u8 }

    #[test]
    fn roundtrip_deterministic_ok() {
        let v = Demo { a: 1, b: 2 };
        let bytes = to_cbor_canonical(&v).unwrap();
        let out: Demo = from_cbor_strict_canonical(&bytes).unwrap();
        assert_eq!(v, out);
    }

    #[test]
    fn strict_rejects_trailing() {
        let v = Demo { a: 3, b: 4 };
        let mut bytes = to_cbor_canonical(&v).unwrap();
        // append another CBOR item (an int 0)
        let mut tail = Vec::new();
        ciborium::ser::into_writer(&0u8, &mut tail).unwrap();
        bytes.extend_from_slice(&tail);
        let err = from_cbor::<Demo>(&bytes, STRICT_CANON).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("trailing"));
    }

    #[test]
    fn noncanonical_reencode_compare_is_ok_with_ciborium() {
        let v = Demo { a: 5, b: 6 };
        // ciborium is deterministic, so encoding then decoding with STRICT_CANON is OK.
        let bytes = to_cbor(&v, CborMode::Default).unwrap();
        let res = from_cbor::<Demo>(&bytes, STRICT_CANON);
        assert!(res.is_ok());
    }
}
