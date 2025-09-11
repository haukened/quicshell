//! Wire encoding for `FINISH_CLIENT` / `FINISH_SERVER` (stubs)

use super::frame::{FrameType, prepend_frame, split_frame};
use crate::core::cbor::{CodecError, from_cbor, to_cbor};
use crate::domain::handshake::{FinishClient, FinishServer};

/// Encode a `FINISH_CLIENT` frame.
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_wire_finish_client(fc: &FinishClient) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(fc)?;
    Ok(prepend_frame(FrameType::FinishClient, &cbor))
}

/// Decode a `FINISH_CLIENT` frame.
///
/// # Errors
///
/// * Returns an error if the frame type is not `FINISH_CLIENT`.
/// * Returns CBOR decoding errors.
pub fn decode_wire_finish_client(bytes: &[u8]) -> Result<FinishClient, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::FinishClient {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected FINISH_CLIENT frame",
            ),
        )));
    }
    from_cbor(payload)
}

/// Encode a `FINISH_SERVER` frame.
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_wire_finish_server(fs: &FinishServer) -> Result<Vec<u8>, CodecError> {
    let cbor = to_cbor(fs)?;
    Ok(prepend_frame(FrameType::FinishServer, &cbor))
}

/// Decode a `FINISH_SERVER` frame.
///
/// # Errors
///
/// * Returns an error if the frame type is not `FINISH_SERVER`.
/// * Returns CBOR decoding errors.
pub fn decode_wire_finish_server(bytes: &[u8]) -> Result<FinishServer, CodecError> {
    let (ft, payload) = split_frame(bytes)?;
    if ft != FrameType::FinishServer {
        return Err(CodecError::De(ciborium::de::Error::Io(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected FINISH_SERVER frame",
            ),
        )));
    }
    from_cbor(payload)
}

/// Encode a `FINISH_CLIENT` message for transcript hashing (padding stripped).
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_transcript_finish_client(fc: &FinishClient) -> Result<Vec<u8>, CodecError> {
    let mut tmp = fc.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}

/// Encode a `FINISH_SERVER` message for transcript hashing (padding stripped).
///
/// # Errors
///
/// Returns CBOR serialization errors.
pub fn encode_transcript_finish_server(fs: &FinishServer) -> Result<Vec<u8>, CodecError> {
    let mut tmp = fs.clone();
    tmp.pad = None;
    to_cbor(&tmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{mk_finish_client, mk_finish_server};
    use proptest::prelude::*;

    #[test]
    fn client_enc_finish() {
        let fc = mk_finish_client();
        let encoded = encode_wire_finish_client(&fc).expect("encoding should succeed");
        let (ft, payload) = split_frame(&encoded).expect("should split frame");
        assert_eq!(
            ft,
            FrameType::FinishClient,
            "frame type must be FINISH_CLIENT"
        );
        let decoded: FinishClient = from_cbor(payload).expect("decode should succeed");
        assert_eq!(decoded, fc, "decoded FinishClient must match original");
    }

    #[test]
    fn server_enc_finish() {
        let fs = mk_finish_server();
        let encoded = encode_wire_finish_server(&fs).expect("encoding should succeed");
        let (ft, payload) = split_frame(&encoded).expect("should split frame");
        assert_eq!(
            ft,
            FrameType::FinishServer,
            "frame type must be FINISH_SERVER"
        );
        let decoded: FinishServer = from_cbor(payload).expect("decode should succeed");
        assert_eq!(decoded, fs, "decoded FinishServer must match original");
    }

    #[test]
    fn client_decode_finish() {
        let fc = mk_finish_client();
        let encoded = encode_wire_finish_client(&fc).expect("encoding should succeed");
        let decoded = decode_wire_finish_client(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, fc, "decoded FinishClient must match original");
    }

    #[test]
    fn client_decode_finish_fail() {
        let fc = mk_finish_client();
        let mut encoded = encode_wire_finish_client(&fc).expect("encoding should succeed");
        // Corrupt the frame type to something else
        if !encoded.is_empty() {
            encoded[0] = FrameType::Accept as u8;
        }
        let result = decode_wire_finish_client(&encoded);
        assert!(
            result.is_err(),
            "decoding with wrong frame type should fail"
        );
    }

    #[test]
    fn server_decode_finish() {
        let fs = mk_finish_server();
        let encoded = encode_wire_finish_server(&fs).expect("encoding should succeed");
        let decoded = decode_wire_finish_server(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, fs, "decoded FinishServer must match original");
    }

    #[test]
    fn server_decode_finish_fail() {
        let fs = mk_finish_server();
        let mut encoded = encode_wire_finish_server(&fs).expect("encoding should succeed");
        // Corrupt the frame type to something else
        if !encoded.is_empty() {
            encoded[0] = FrameType::Accept as u8;
        }
        let result = decode_wire_finish_server(&encoded);
        assert!(
            result.is_err(),
            "decoding with wrong frame type should fail"
        );
    }

    #[test]
    fn client_transcript_encoding_strips_pad() {
        let fc = mk_finish_client();
        let encoded = encode_transcript_finish_client(&fc).expect("encoding should succeed");
        let decoded: FinishClient = from_cbor(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, fc, "decoded FinishClient must match original");
        assert!(
            decoded.pad.is_none(),
            "transcript encoding should strip pad"
        );
    }

    #[test]
    fn server_transcript_encoding_strips_pad() {
        let fs = mk_finish_server();
        let encoded = encode_transcript_finish_server(&fs).expect("encoding should succeed");
        let decoded: FinishServer = from_cbor(&encoded).expect("decoding should succeed");
        assert_eq!(decoded, fs, "decoded FinishServer must match original");
        assert!(
            decoded.pad.is_none(),
            "transcript encoding should strip pad"
        );
    }

    // ---- Additional edge / security oriented tests ----

    #[test]
    fn finish_client_transcript_idempotent_no_pad() {
        let fc = mk_finish_client();
        let t1 = encode_transcript_finish_client(&fc).unwrap();
        let t2 = encode_transcript_finish_client(&fc).unwrap();
        assert_eq!(t1, t2, "idempotent encoding expected");
    }

    #[test]
    fn finish_server_transcript_idempotent_no_pad() {
        let fs = mk_finish_server();
        let t1 = encode_transcript_finish_server(&fs).unwrap();
        let t2 = encode_transcript_finish_server(&fs).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn finish_client_transcript_strips_and_preserves_original() {
        let mut fc = mk_finish_client();
        fc.pad = Some(vec![7, 7, 7]);
        let original_clone = fc.clone();
        let transcript = encode_transcript_finish_client(&fc).unwrap();
        let mut padless = fc.clone();
        padless.pad = None;
        assert_eq!(transcript, to_cbor(&padless).unwrap());
        assert_eq!(original_clone.pad.unwrap(), vec![7, 7, 7]);
    }

    #[test]
    fn finish_server_transcript_strips_and_preserves_original() {
        let mut fs = mk_finish_server();
        fs.pad = Some(vec![9, 9]);
        let original_clone = fs.clone();
        let transcript = encode_transcript_finish_server(&fs).unwrap();
        let mut padless = fs.clone();
        padless.pad = None;
        assert_eq!(transcript, to_cbor(&padless).unwrap());
        assert_eq!(original_clone.pad.unwrap(), vec![9, 9]);
    }

    #[test]
    fn decode_finish_client_truncated_payload() {
        // frame type only, no CBOR body
        let data = vec![FrameType::FinishClient as u8];
        let err = decode_wire_finish_client(&data).unwrap_err();
        matches!(err, CodecError::De(_));
    }

    #[test]
    fn decode_finish_server_truncated_payload() {
        let data = vec![FrameType::FinishServer as u8];
        let err = decode_wire_finish_server(&data).unwrap_err();
        matches!(err, CodecError::De(_));
    }

    proptest! {
        #[test]
    fn prop_finish_client_transcript_equals_padless(pad in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut fc = mk_finish_client(); fc.pad = Some(pad.clone());
            let mut padless = fc.clone(); padless.pad = None;
            prop_assert_eq!(encode_transcript_finish_client(&fc).unwrap(), to_cbor(&padless).unwrap());
        }
        #[test]
        fn prop_finish_server_transcript_equals_padless(pad in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut fs = mk_finish_server(); fs.pad = Some(pad.clone());
            let mut padless = fs.clone(); padless.pad = None;
            prop_assert_eq!(encode_transcript_finish_server(&fs).unwrap(), to_cbor(&padless).unwrap());
        }
    }
}
