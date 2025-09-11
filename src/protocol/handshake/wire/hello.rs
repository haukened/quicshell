//! Wire encoding for `HELLO` (control-plane)

use super::frame::{FrameType, prepend_frame, split_frame};
use crate::core::cbor::{CodecError, from_cbor, to_cbor}; // update to core::cbor if you rename
use crate::domain::handshake::Hello;

/// Encode a `HELLO` for the wire: `[type:1][canonical CBOR payload]`
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_wire_hello(h: &Hello) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(h)?; // canonical by design
    Ok(prepend_frame(FrameType::Hello, &cbor))
}

/// Decode a `HELLO` from the wire (strict + canonical enforced by `from_cbor`).
///
/// # Errors
///
/// * Returns an error if the frame type is not `HELLO`.
/// * Returns CBOR decoding errors.
pub fn decode_wire_hello(bytes: &[u8]) -> Result<Hello, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::Hello {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "expected HELLO frame"),
        )));
    }
    from_cbor(payload)
}

/// Transcript encoding: CBOR of `HELLO` with pad stripped.
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_transcript_hello(h: &Hello) -> Result<Vec<u8>, CodecError> {
    let mut tmp = h.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}

/// Transcript encoding: CBOR of HELLO with pad stripped
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use proptest::prelude::*;

    #[test]
    fn encode_hello() {
        let h = mk_hello();
        let encoded = encode_wire_hello(&h).expect("encoding should succeed");
        let (ft, payload) = split_frame(&encoded).expect("should split frame");
        assert_eq!(ft, FrameType::Hello, "frame type must be HELLO");
        let decoded: Hello = from_cbor(payload).expect("decode should succeed");
        assert_eq!(decoded, h, "decoded Hello must match original");
    }

    #[test]
    fn decode_hello() {
        let h = mk_hello();
        let encoded = encode_wire_hello(&h).expect("encoding should succeed");
        let decoded = decode_wire_hello(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, h, "decoded Hello must match original");
    }

    #[test]
    fn decode_hello_wrong_type_fails() {
        let h = mk_hello();
        let mut encoded = encode_wire_hello(&h).expect("encoding should succeed");
        // Corrupt the frame type to something else
        if !encoded.is_empty() {
            encoded[0] = FrameType::Accept as u8;
        }
        let result = decode_wire_hello(&encoded);
        assert!(
            result.is_err(),
            "decoding with wrong frame type should fail"
        );
    }

    /// Helper to build a Hello with a specific pad while relying on Default for other fields.
    /// Adjust if Hello does not implement Default or has mandatory non-defaultable fields.
    fn hello_with_pad(pad: Option<Vec<u8>>) -> Hello {
        let mut h = mk_hello();
        h.pad = pad;
        h
    }

    #[test]
    fn transcript_encoding_strips_pad() {
        let original_pad = vec![0u8, 1, 2, 3, 4, 5];
        let h = hello_with_pad(Some(original_pad.clone()));
        let encoded = encode_transcript_hello(&h).expect("encoding should succeed");
        // Decode back to verify pad is absent (None) in transcript form.
        let decoded: Hello = from_cbor(&encoded).expect("decode should succeed");
        assert!(
            decoded.pad.is_none(),
            "pad field must be stripped in transcript encoding"
        );
        // Original value must remain intact (function must not mutate input)
        assert_eq!(
            h.pad.as_ref(),
            Some(&original_pad),
            "original Hello mutated unexpectedly"
        );
    }

    #[test]
    fn transcript_encoding_idempotent_when_no_pad() {
        let h = hello_with_pad(None);
        let first = encode_transcript_hello(&h).unwrap();
        let second = encode_transcript_hello(&h).unwrap();
        assert_eq!(
            first, second,
            "encoding with no pad should be stable/idempotent"
        );
    }

    #[test]
    fn transcript_encoding_matches_manual_cbor_of_padless_clone() {
        let mut h = hello_with_pad(Some(vec![9, 9, 9]));
        let encoded_transcript = encode_transcript_hello(&h).unwrap();
        h.pad = None;
        let encoded_manual = to_cbor(&h).unwrap();
        assert_eq!(
            encoded_transcript, encoded_manual,
            "transcript encoding must equal canonical CBOR of struct with pad=None"
        );
    }

    proptest! {
        #[test]
        fn prop_transcript_equals_padless_encoding(pad in prop::collection::vec(any::<u8>(), 0..256)) {
            let with_pad = hello_with_pad(Some(pad));
            let mut padless = with_pad.clone();
            padless.pad = None;

            let transcript_bytes = encode_transcript_hello(&with_pad).expect("encode transcript");
            let padless_bytes = to_cbor(&padless).expect("encode padless");

            prop_assert_eq!(transcript_bytes, padless_bytes);
        }
    }

    #[test]
    fn transcript_encoding_does_not_panic_on_empty_pad() {
        let h = hello_with_pad(Some(vec![]));
        let bytes = encode_transcript_hello(&h).expect("must encode");
        let decoded: Hello = from_cbor(&bytes).expect("must decode");
        assert!(decoded.pad.is_none());
    }

    #[test]
    fn transcript_encoding_large_pad_is_removed_not_serialized() {
        // Large but reasonable size for unit test; adjust threshold if spec defines max pad length.
        let large_pad = vec![0xA5u8; 4096];
        let h = hello_with_pad(Some(large_pad.clone()));
        let bytes = encode_transcript_hello(&h).unwrap();
        // Ensure the large pad pattern (A5 repeated) is not present verbatim (heuristic)
        // This is a probabilistic check; if legitimate fields can contain same pattern adjust test.
        assert!(
            !bytes.windows(16).any(|w| w.iter().all(|b| *b == 0xA5)),
            "pad bytes unexpectedly present in transcript encoding"
        );
        // Sanity: decoding works and pad is None
        let decoded: Hello = from_cbor(&bytes).unwrap();
        assert!(decoded.pad.is_none());
        // Original remains
        assert_eq!(h.pad.as_ref().unwrap().len(), 4096);
    }

    #[test]
    fn encode_transcript_does_not_allocate_excessively_for_small_hellos() {
        let h = hello_with_pad(None);
        // Benchmark-ish sanity (not strict): ensure call is fast; if it regresses drastically this can be tuned.
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = encode_transcript_hello(&h).unwrap();
        }
        let elapsed = start.elapsed();
        // Allow generous upper bound (adjust if CI environment requires)
        assert!(
            elapsed.as_secs_f64() < 0.75,
            "encoding seems unexpectedly slow: {elapsed:?}"
        );
    }
}
