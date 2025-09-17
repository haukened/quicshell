#![allow(clippy::missing_errors_doc)]
use super::*;
use crate::application::handshake::ApplicationHandshakeError;
use crate::ports::crypto::{AEAD_TAG_LEN, AeadError, AeadKey, AeadSeal, NonceSalt, Seq};
use crate::ports::handshake::{
    HandshakeTranscriptRef, HandshakeWire, KeySink, TranscriptPort, WireError,
};
use crate::protocol::handshake::keyschedule::{DirectionKeys, WriteKeys};
use crate::test_support::support::{mk_accept, mk_finish_client, mk_finish_server, mk_hello};

// ---------------- Test Doubles ----------------

#[derive(Default)]
struct DummyConn {
    installed: Option<WriteKeys>,
    seqs: Option<(Seq, Seq)>,
}

impl KeySink for DummyConn {
    fn install_write_keys(&mut self, keys: WriteKeys) {
        self.installed = Some(keys);
    }
    fn set_seqs(&mut self, client_seq: Seq, server_seq: Seq) {
        self.seqs = Some((client_seq, server_seq));
    }
}

#[derive(Clone, Copy)]
struct DummyTranscript([u8; 48]);
impl DummyTranscript {
    fn new() -> Self {
        Self([0u8; 48])
    }
}
impl TranscriptPort for DummyTranscript {
    fn absorb_canonical(&mut self, bytes: &[u8]) {
        // very small mixing
        for (i, b) in bytes.iter().enumerate() {
            self.0[i % 48] ^= *b;
        }
    }
    fn hash(&self) -> [u8; 48] {
        self.0
    }
}

#[derive(Clone, Default)]
struct DummyAead {
    fail_seal: bool,
    fail_open: bool,
}
impl AeadSeal for DummyAead {
    fn seal_in_place(
        &self,
        _key: &AeadKey,
        _salt: NonceSalt,
        _seq: Seq,
        _aad: &[u8],
        _buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        Ok(())
    }
    fn open_in_place(
        &self,
        _key: &AeadKey,
        _salt: NonceSalt,
        _seq: Seq,
        _aad: &[u8],
        _buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        Ok(())
    }
    fn seal_detached_tag(
        &self,
        _key: &AeadKey,
        _salt: NonceSalt,
        _seq: Seq,
        aad: &[u8],
    ) -> Result<[u8; AEAD_TAG_LEN], AeadError> {
        if self.fail_seal {
            return Err(AeadError::Internal);
        }
        let mut tag = [0u8; AEAD_TAG_LEN];
        for (i, b) in aad.iter().take(AEAD_TAG_LEN).enumerate() {
            tag[i] = *b;
        }
        Ok(tag)
    }
    fn open_detached_tag(
        &self,
        _key: &AeadKey,
        _salt: NonceSalt,
        _seq: Seq,
        aad: &[u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadError> {
        if self.fail_open {
            return Err(AeadError::TagMismatch);
        }
        if aad.first() != Some(&tag[0]) {
            return Err(AeadError::TagMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct OkWire;
impl HandshakeWire for OkWire {
    fn encode_transcript(&self, msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError> {
        // deterministic tiny encoding based on variant tag
        let tag = match msg {
            HandshakeTranscriptRef::Hello(_) => b"H".as_slice(),
            HandshakeTranscriptRef::Accept(_) => b"A".as_slice(),
            HandshakeTranscriptRef::FinishClient(_) => b"FC".as_slice(),
            HandshakeTranscriptRef::FinishServer(_) => b"FS".as_slice(),
        };
        Ok(tag.to_vec())
    }
}

#[derive(Clone, Default)]
struct FailingWire;
impl HandshakeWire for FailingWire {
    fn encode_transcript(&self, _msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError> {
        Err(WireError::Codec("boom".into()))
    }
}

fn wk() -> WriteKeys {
    WriteKeys {
        client: DirectionKeys {
            key: AeadKey([1u8; 32]),
            salt: NonceSalt([1u8; 16]),
        },
        server: DirectionKeys {
            key: AeadKey([2u8; 32]),
            salt: NonceSalt([2u8; 16]),
        },
    }
}

fn new_client_ok() -> HandshakeFsm<DummyConn, DummyTranscript, DummyAead, OkWire> {
    HandshakeFsm::new(
        Role::Client,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead::default(),
        OkWire,
    )
}
fn new_server_ok() -> HandshakeFsm<DummyConn, DummyTranscript, DummyAead, OkWire> {
    HandshakeFsm::new(
        Role::Server,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead::default(),
        OkWire,
    )
}

// --------------- Tests ---------------

#[test]
fn wire_encode_failure_propagates() {
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead::default(),
        FailingWire,
    );
    let h = mk_hello();
    let err = fsm.on_client_send_hello(&h).unwrap_err();
    match err {
        ApplicationHandshakeError::ValidationError(s) => {
            assert!(s.contains("wire: encode HELLO failed"))
        }
        _ => panic!("unexpected err"),
    }
}

#[test]
fn invalid_transition_rejected() {
    // Server trying to send accept before hello processed
    let a = mk_accept();
    let mut srv = new_server_ok();
    let err = srv.on_server_send_accept(&a).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn finish_client_wrong_state() {
    // Client building finish before accept
    let mut cli = new_client_ok();
    let fc = mk_finish_client();
    let err = cli.build_finish_client(fc).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn verify_server_confirm_failure() {
    // Force failure by using fail_open AEAD
    let mut cli: HandshakeFsm<_, _, _, _> = HandshakeFsm::new(
        Role::Client,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead {
            fail_seal: false,
            fail_open: true,
        },
        OkWire,
    );
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    // derive keys early
    cli.prk = Some([9u8; 48]);
    cli.writes = Some(wk());
    let fs = mk_finish_server(); // tag will not verify
    let err = cli.on_finish_server(&fs).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn build_finish_client_seal_failure() {
    let mut cli: HandshakeFsm<_, _, _, _> = HandshakeFsm::new(
        Role::Client,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead {
            fail_seal: true,
            fail_open: false,
        },
        OkWire,
    );
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    cli.prk = Some([3u8; 48]);
    let fc = mk_finish_client();
    let err = cli.build_finish_client(fc).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn tag_wrong_length_triggers_error() {
    // Directly call verify_confirm private path by crafting a FinishServer with wrong len
    // Achieved by mutating server_confirm after building correct one then truncating
    let mut cli = new_client_ok();
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    cli.prk = Some([7u8; 48]);
    cli.writes = Some(wk());
    let mut fs = mk_finish_server();
    fs.server_confirm = vec![1, 2, 3]; // invalid length
    let err = cli.on_finish_server(&fs).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn complete_without_ready_state_fails() {
    let mut cli = new_client_ok();
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    cli.prk = Some([1u8; 48]);
    cli.writes = Some(wk());
    assert!(cli.transcript_hash().is_err());
    let err = cli.complete([0u8; 48], b"hs").unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn successful_complete_installs_keys() {
    // Happy path minimal to ensure success still works
    let mut cli = new_client_ok();
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    // mark ready (simulate finish exchange earlier)
    cli.ready();
    let th = cli.transcript_hash().unwrap();
    let shared = [5u8; 32];
    cli.complete(th, &shared).unwrap();
    assert!(cli.conn.installed.is_some());
}

#[test]
fn full_finish_exchange_success_paths() {
    // Exercise successful confirm tag seal/verify for both client and server and reuse of derived keys.
    let mut client = new_client_ok();
    let mut server = new_server_ok();
    let hello = mk_hello();
    client.on_client_send_hello(&hello).unwrap();
    server.on_hello(&hello).unwrap();
    let accept = mk_accept();
    server.on_server_send_accept(&accept).unwrap();
    client.on_accept(&accept).unwrap();
    // Inject shared secret via dedicated API for both (ensures identical PRK derivation using same transcript hash).
    let shared = b"hybrid-shared-material";
    client.set_hybrid_shared(shared);
    server.set_hybrid_shared(shared);
    // Client builds finish_client (derives keys first time for client path).
    let fc = client.build_finish_client(mk_finish_client()).unwrap();
    // Server verifies finish_client (derives keys for first time, success path verify_confirm + absorb).
    server.on_finish_client(&fc).unwrap();
    // Server now allowed to build finish_server after GotFinishClient state.
    let fs = server.build_finish_server(mk_finish_server()).unwrap();
    client.on_finish_server(&fs).unwrap();
    assert_eq!(client.state(), HandshakeState::ReadyToComplete);
    assert_eq!(server.state(), HandshakeState::ReadyToComplete);
}

#[test]
fn derive_keys_cache_reuse() {
    // Ensure second invocation of derive_keys_and_th does not overwrite cached keys.
    let mut client = new_client_ok();
    let hello = mk_hello();
    client.on_client_send_hello(&hello).unwrap();
    let accept = mk_accept();
    client.on_accept(&accept).unwrap();
    client.set_hybrid_shared(b"shared");
    // First derive via building finish client.
    let before = client.writes.clone();
    let fc = client.build_finish_client(mk_finish_client()).unwrap();
    assert!(client.writes.is_some());
    let first = client.writes.clone();
    // Second path (verify server finish) will call derive_keys_and_th again but should not change cached value.
    // Construct a server finish matching existing keys: build minimal server FSM to produce valid confirm.
    let mut server = new_server_ok();
    server.on_hello(&hello).unwrap();
    server.on_server_send_accept(&accept).unwrap();
    server.set_hybrid_shared(b"shared");
    // Server needs to verify client's finish to reach state allowing build_finish_server
    server.on_finish_client(&fc).unwrap();
    let fs = server.build_finish_server(mk_finish_server()).unwrap();
    client.on_finish_server(&fs).unwrap();
    let second = client.writes.clone();
    assert_eq!(first.unwrap().client.key.0, second.unwrap().client.key.0);
    assert!(before.is_none());
}

#[test]
fn ready_idempotent_and_early() {
    // Call ready before normal finish exchange to exercise MarkReady branch from non-ready state.
    let mut client = new_client_ok();
    client.ready();
    assert_eq!(client.state(), HandshakeState::ReadyToComplete);
    // Call again to exercise MarkReady when already ReadyToComplete.
    client.ready();
    assert_eq!(client.state(), HandshakeState::ReadyToComplete);
}

#[test]
fn complete_with_existing_prk_and_writes_skips_derivation() {
    let mut client = new_client_ok();
    client.ready();
    // Pre-install PRK and writes to hit complete() branches that skip derivation logic.
    client.prk = Some([0xAA; 48]);
    client.writes = Some(wk());
    let th = client.transcript_hash().unwrap();
    client.complete(th, b"ignored-shared").unwrap();
    assert_eq!(client.state(), HandshakeState::Complete);
}

#[test]
fn transcript_sync_end_to_end() {
    let mut client = new_client_ok();
    let mut server = new_server_ok();
    let hello = mk_hello();
    client.on_client_send_hello(&hello).unwrap();
    server.on_hello(&hello).unwrap();
    let accept = mk_accept();
    server.on_server_send_accept(&accept).unwrap();
    client.on_accept(&accept).unwrap();
    // After ACCEPT we are NOT yet ReadyToComplete; transcript_hash must be unavailable.
    assert!(client.transcript_hash().is_err());
    assert!(server.transcript_hash().is_err());
    let shared = b"sync-shared";
    client.set_hybrid_shared(shared);
    server.set_hybrid_shared(shared);
    let fc = client.build_finish_client(mk_finish_client()).unwrap();
    server.on_finish_client(&fc).unwrap();
    let fs = server.build_finish_server(mk_finish_server()).unwrap();
    client.on_finish_server(&fs).unwrap();
    // Now both sides should be ReadyToComplete and transcript_hash must succeed.
    let th_client_final = client.transcript_hash().unwrap();
    let th_server_final = server.transcript_hash().unwrap();
    assert_eq!(
        th_client_final, th_server_final,
        "final transcript hashes diverged"
    );
}

#[test]
fn wire_failure_on_accept_only() {
    // Wire that succeeds once (HELLO) then fails on next encode (ACCEPT) to cover encode_absorb error branch distinct from initial hello test
    #[derive(Default, Clone)]
    struct OneFailWire {
        calls: std::cell::Cell<u8>,
    }
    impl HandshakeWire for OneFailWire {
        fn encode_transcript(&self, msg: HandshakeTranscriptRef<'_>) -> Result<Vec<u8>, WireError> {
            let c = self.calls.get();
            self.calls.set(c + 1);
            if c >= 1 {
                return Err(WireError::Codec("second-call".into()));
            }
            Ok(match msg {
                HandshakeTranscriptRef::Hello(_) => b"H".to_vec(),
                _ => b"X".to_vec(),
            })
        }
    }
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        DummyConn::default(),
        DummyTranscript::new(),
        DummyAead::default(),
        OneFailWire::default(),
    );
    let h = mk_hello();
    fsm.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    let err = fsm.on_accept(&a).unwrap_err();
    matches!(err, ApplicationHandshakeError::ValidationError(_));
}

#[test]
fn build_finish_client_prk_missing_error() {
    // Reach GotAccept without calling set_hybrid_shared then attempt build_finish_client.
    let mut cli = new_client_ok();
    let h = mk_hello();
    cli.on_client_send_hello(&h).unwrap();
    let a = mk_accept();
    cli.on_accept(&a).unwrap();
    // PRK not set → derive_keys_and_th should fail.
    let err = cli.build_finish_client(mk_finish_client()).unwrap_err();
    match err {
        ApplicationHandshakeError::ValidationError(s) => {
            assert!(s.contains("prerequisite missing: prk"))
        }
        _ => panic!("unexpected error kind"),
    }
}

#[test]
fn server_on_finish_client_prk_missing_error() {
    // Server processes hello + accept send, then receives finish_client before shared secret is set.
    let mut srv = new_server_ok();
    let h = mk_hello();
    srv.on_hello(&h).unwrap();
    let a = mk_accept();
    srv.on_server_send_accept(&a).unwrap();
    let fc = mk_finish_client();
    let err = srv.on_finish_client(&fc).unwrap_err();
    match err {
        ApplicationHandshakeError::ValidationError(s) => {
            assert!(s.contains("prerequisite missing: prk"))
        }
        _ => panic!("unexpected error kind"),
    }
}

#[test]
fn complete_with_prk_only_derives_writes() {
    // Cover branch where prk Some, writes None inside complete().
    let mut cli = new_client_ok();
    cli.ready();
    cli.prk = Some([3u8; 48]);
    assert!(cli.writes.is_none());
    let th = cli.transcript_hash().unwrap();
    cli.complete(th, b"ignored").unwrap();
    assert!(cli.state() == HandshakeState::Complete);
}

#[test]
fn get_mutable_conn() {
    let mut cli = new_client_ok();
    let conn: &mut DummyConn = cli.conn_mut();
    assert!(conn.installed.is_none());
    assert!(conn.seqs.is_none());
    conn.set_seqs(Seq(5), Seq(10));
    assert!(conn.seqs == Some((Seq(5), Seq(10))));
}

#[test]
fn consume_fsm_returns_conn() {
    let cli = new_client_ok();
    let conn = cli.into_inner();
    let benchmark_conn = DummyConn::default();
    assert_eq!(conn.installed, benchmark_conn.installed);
}
