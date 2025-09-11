//! Wire encoding for `ACCEPT` (stubs)

use super::frame::{FrameType, prepend_frame, split_frame};
use crate::core::cbor::{CodecError, from_cbor, to_cbor};
use crate::domain::handshake::Accept;

/// Encode an `ACCEPT` frame.
///
/// # Errors
///
/// Returns any CBOR serialization errors.
pub fn encode_wire_accept(a: &Accept) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(a)?;
    Ok(prepend_frame(FrameType::Accept, &cbor))
}

/// Decode an `ACCEPT` frame from raw bytes.
///
/// # Errors
///
/// * Returns an error if the frame type is not `ACCEPT`.
/// * Returns CBOR decoding errors.
pub fn decode_wire_accept(bytes: &[u8]) -> Result<Accept, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::Accept {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "expected ACCEPT frame"),
        )));
    }
    from_cbor(payload)
}

/// Encode an ACCEPT object for inclusion in the transcript hash, excluding padding.
///
/// The `pad` field MUST be excluded from the transcript per ADR-0006 so
/// transcript stability is not affected by variable-length padding.
/// Encode an `ACCEPT` message for transcript hashing (padding stripped).
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_transcript_accept(a: &Accept) -> Result<Vec<u8>, CodecError> {
    let mut tmp = a.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mk_accept;

    #[test]
    fn encode_accept() {
        let a = mk_accept();
        let encoded = encode_wire_accept(&a).expect("encoding should succeed");
        let (ft, payload) = split_frame(&encoded).expect("should split frame");
        assert_eq!(ft, FrameType::Accept, "frame type must be ACCEPT");
        assert_eq!(
            from_cbor::<Accept>(payload).expect("decode should succeed"),
            a,
            "decoded Accept must match original"
        );
    }

    #[test]
    fn decode_accept() {
        let a = mk_accept();
        let encoded = encode_wire_accept(&a).expect("encoding should succeed");
        let decoded = decode_wire_accept(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, a, "decoded Accept must match original");
    }

    #[test]
    fn decode_rejects_wrong_frame_type() {
        let a = mk_accept();
        // Produce raw CBOR for Accept
        let cbor = to_cbor(&a).expect("cbor encode");
        // Wrap with an incorrect frame type (e.g., Hello if distinct)
        let wrong = prepend_frame(FrameType::Hello, &cbor);
        let err = decode_wire_accept(&wrong).expect_err("must fail on wrong frame type");
        let msg = format!("{err}");
        assert!(
            msg.contains("expected ACCEPT frame"),
            "error message should mention expected ACCEPT frame, got: {msg}"
        );
    }

    #[test]
    fn decode_rejects_truncated_frame() {
        // Provide too-short data to split_frame; expect an error.
        let bytes = [0x01u8];
        assert!(
            decode_wire_accept(&bytes).is_err(),
            "decoding truncated frame must error"
        );
    }

    #[test]
    fn transcript_excludes_pad() {
        let mut a = mk_accept();
        // Ensure we set a non-empty pad (length/contents chosen arbitrarily)
        a.pad = Some(vec![0xAA; 16]);
        let full_wire = encode_wire_accept(&a).expect("wire encode");
        let (_ft, payload) = split_frame(&full_wire).expect("split");
        let decoded_full: Accept = from_cbor(payload).expect("cbor decode");
        assert_eq!(
            decoded_full.pad, a.pad,
            "regular wire encoding MUST retain pad"
        );

        let transcript = encode_transcript_accept(&a).expect("transcript encode");
        let stripped: Accept = from_cbor(&transcript).expect("transcript decode");
        assert!(
            stripped.pad.is_none(),
            "transcript form MUST have pad stripped"
        );
    }

    #[test]
    fn transcript_stable_across_different_padding() {
        let mut a1 = mk_accept();
        let mut a2 = a1.clone();
        a1.pad = Some(vec![0x11; 8]);
        a2.pad = Some(vec![0x22; 64]);

        let t1 = encode_transcript_accept(&a1).expect("t1 encode");
        let t2 = encode_transcript_accept(&a2).expect("t2 encode");
        assert_eq!(
            t1, t2,
            "transcript encodings must be identical when only pad differs"
        );
    }

    #[test]
    fn transcript_matches_wire_without_pad_when_original_has_none() {
        let a = mk_accept(); // Assume mk_accept() produces Accept with pad = None
        assert!(
            a.pad.is_none(),
            "precondition: mk_accept() should yield no pad"
        );
        let transcript = encode_transcript_accept(&a).expect("transcript encode");
        let full_wire = encode_wire_accept(&a).expect("wire encode");
        let (_ft, payload) = split_frame(&full_wire).expect("split");
        assert_eq!(
            transcript, payload,
            "when pad is None the transcript encoding should equal CBOR payload"
        );
    }

    #[test]
    fn wire_and_transcript_differ_when_pad_present() {
        let mut a = mk_accept();
        a.pad = Some(vec![0x55; 5]);
        let wire = encode_wire_accept(&a).expect("wire encode");
        let (_ft, payload) = split_frame(&wire).expect("split");
        let transcript = encode_transcript_accept(&a).expect("transcript encode");
        assert_ne!(
            transcript, payload,
            "wire CBOR (with pad) must differ from transcript (without pad)"
        );
    }
}
