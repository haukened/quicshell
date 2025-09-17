use crate::ports::handshake::{HandshakeTranscriptRef, HandshakeWire, WireError};
use crate::protocol::handshake::wire::{
    encode_transcript_accept, encode_transcript_finish_client, encode_transcript_finish_server,
    encode_transcript_hello,
};

pub struct WireAdapter;

impl HandshakeWire for WireAdapter {
    fn encode_transcript(&self, msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError> {
        use HandshakeTranscriptRef::{Accept, FinishClient, FinishServer, Hello};
        let r = match msg {
            Hello(h) => encode_transcript_hello(h),
            Accept(a) => encode_transcript_accept(a),
            FinishClient(fc) => encode_transcript_finish_client(fc),
            FinishServer(fs) => encode_transcript_finish_server(fs),
        };
        r.map_err(|e| WireError::Codec(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::cbor::to_cbor;
    use crate::protocol::handshake::wire::{
        encode_transcript_finish_client, encode_transcript_finish_server,
    };
    use crate::test_support::{mk_finish_client, mk_finish_server};
    use proptest::prelude::*;

    #[test]
    fn client_adapter_matches_direct_and_preserves_original() {
        let mut fc = mk_finish_client();
        fc.pad = Some(vec![1, 2, 3]);
        let original = fc.clone();
        let adap = WireAdapter;
        let via_adapter = adap
            .encode_transcript(HandshakeTranscriptRef::FinishClient(&fc))
            .unwrap();
        let direct = encode_transcript_finish_client(&fc).unwrap();
        assert_eq!(via_adapter, direct, "adapter must delegate exactly");
        assert_eq!(original, fc, "adapter must not mutate input");
        // Pad stripped in transcript form
        let mut padless = fc.clone();
        padless.pad = None;
        assert_eq!(via_adapter, to_cbor(&padless).unwrap());
    }

    #[test]
    fn server_adapter_matches_direct_and_preserves_original() {
        let mut fs = mk_finish_server();
        fs.pad = Some(vec![9, 9, 9]);
        let original = fs.clone();
        let adap = WireAdapter;
        let via_adapter = adap
            .encode_transcript(HandshakeTranscriptRef::FinishServer(&fs))
            .unwrap();
        let direct = encode_transcript_finish_server(&fs).unwrap();
        assert_eq!(via_adapter, direct);
        assert_eq!(original, fs);
        let mut padless = fs.clone();
        padless.pad = None;
        assert_eq!(via_adapter, to_cbor(&padless).unwrap());
    }

    #[test]
    fn idempotent_client_encoding() {
        let fc = mk_finish_client();
        let adap = WireAdapter;
        let a = adap
            .encode_transcript(HandshakeTranscriptRef::FinishClient(&fc))
            .unwrap();
        let b = adap
            .encode_transcript(HandshakeTranscriptRef::FinishClient(&fc))
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn idempotent_server_encoding() {
        let fs = mk_finish_server();
        let adap = WireAdapter;
        let a = adap
            .encode_transcript(HandshakeTranscriptRef::FinishServer(&fs))
            .unwrap();
        let b = adap
            .encode_transcript(HandshakeTranscriptRef::FinishServer(&fs))
            .unwrap();
        assert_eq!(a, b);
    }

    proptest! {
        #[test]
        fn prop_client_pad_removed(pad in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut fc = mk_finish_client(); fc.pad = Some(pad.clone());
            let adap = WireAdapter;
            let encoded = adap
                .encode_transcript(HandshakeTranscriptRef::FinishClient(&fc))
                .unwrap();
            let mut padless = fc.clone(); padless.pad = None;
            prop_assert_eq!(encoded, to_cbor(&padless).unwrap());
        }

        #[test]
        fn prop_server_pad_removed(pad in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut fs = mk_finish_server(); fs.pad = Some(pad.clone());
            let adap = WireAdapter;
            let encoded = adap
                .encode_transcript(HandshakeTranscriptRef::FinishServer(&fs))
                .unwrap();
            let mut padless = fs.clone(); padless.pad = None;
            prop_assert_eq!(encoded, to_cbor(&padless).unwrap());
        }
    }
}
