//! Integration-style tests exercising public FSM methods with real domain message constructors.

use quicshell::application::TranscriptPort;
use quicshell::application::handshake::errors::ApplicationHandshakeError;
use quicshell::application::handshake::fsm::{HandshakeFsm, HandshakeState, Role};
use quicshell::domain::handshake::{Accept, FinishClient, FinishServer, Hello, UserAuth};
use quicshell::ports::crypto::{AeadError, AeadKey, AeadSeal, NonceSalt, Seq};
use quicshell::protocol::handshake::keyschedule::DirectionKeys;
use quicshell::protocol::handshake::wire::adapter::WireAdapter;
use quicshell::test_support::{mk_cap, mk_kem, mk_keys, mk_nonce};

struct DummyConn {
    client: Option<DirectionKeys>,
    server: Option<DirectionKeys>,
    cseq: Seq,
    sseq: Seq,
}

// Dummy transcript (XOR-based) for test purposes only.
struct DummyTranscript {
    h: [u8; 48],
}
impl TranscriptPort for DummyTranscript {
    fn absorb_canonical(&mut self, bytes: &[u8]) {
        for (i, b) in bytes.iter().enumerate().take(48) {
            self.h[i] ^= b;
        }
    }
    fn hash(&self) -> [u8; 48] {
        self.h
    }
}

// Dummy AEAD that performs no encryption; satisfies trait for FSM construction in tests.
struct DummyAead;
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
        _aad: &[u8],
    ) -> Result<[u8; 16], AeadError> {
        Ok([0u8; 16])
    }
    fn open_detached_tag(
        &self,
        _key: &AeadKey,
        _salt: NonceSalt,
        _seq: Seq,
        _aad: &[u8],
        _tag: &[u8; 16],
    ) -> Result<(), AeadError> {
        Ok(())
    }
}

impl quicshell::application::handshake::fsm::KeySink for DummyConn {
    fn install_keys(&mut self, client_write: DirectionKeys, server_write: DirectionKeys) {
        self.client = Some(client_write);
        self.server = Some(server_write);
    }
    fn set_seqs(&mut self, client_seq: Seq, server_seq: Seq) {
        self.cseq = client_seq;
        self.sseq = server_seq;
    }
}

fn build_hello() -> Hello {
    let (kem_c, _kem_s, _kem_ct) = mk_kem();
    let nonce = mk_nonce();
    let caps = vec![mk_cap("EXEC"), mk_cap("TTY")];
    Hello::new(kem_c, nonce, caps, None).expect("valid hello")
}

fn build_accept() -> Accept {
    let (_kem_c, kem_s, _kem_ct) = mk_kem();
    Accept::new(kem_s, vec![vec![1u8; 1]], mk_nonce(), None, None, None).expect("valid accept")
}

// Helper to discover tag length via constructing a valid FinishServer then using its field length.
fn tag_len() -> usize {
    // 32 chosen; if invalid length, constructor will error and test will fail early.
    // We try a reasonable typical AEAD tag length guesses. Actual is validated in finish.rs tests.
    // Instead of hard-coding private constant, build a valid message and read length.
    // brute force attempt set of common lengths
    for cand in [16usize, 32, 48] {
        if FinishServer::new(vec![0u8; cand], None, None).is_ok() {
            return cand;
        }
    }
    panic!("Could not determine AEAD tag length");
}

fn build_finish_client() -> FinishClient {
    let (_kem_c, _kem_s, kem_ct) = mk_kem();
    let (raw_keys, sig) = mk_keys();
    let ua = UserAuth::RawKeys { raw_keys, sig };
    let len = tag_len();
    FinishClient::new(kem_ct, ua, vec![0u8; len], None).expect("valid finish_client")
}

fn build_finish_server() -> FinishServer {
    let len = tag_len();
    FinishServer::new(vec![0u8; len], None, None).expect("valid finish_server")
}

#[test]
fn client_public_happy_path() {
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(7),
        sseq: Seq(8),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    let hello = build_hello();
    let accept = build_accept();
    let finish_server = build_finish_server();

    fsm.on_start_client_send_hello(&hello).unwrap();
    fsm.on_accept(&accept).unwrap();
    // Simulate hybrid KEM shared secret becoming available (PRK derives from th + shared)
    let shared = [9u8; 32];
    fsm.set_hybrid_shared(&shared);
    fsm.on_finish_server(&finish_server).unwrap();
    assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);

    let th = [5u8; 48];
    let shared = [9u8; 32];
    fsm.complete(th, &shared).unwrap();
    assert_eq!(fsm.state(), HandshakeState::Complete);
}

#[test]
fn client_public_invalid_sequences() {
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(0),
        sseq: Seq(0),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    let accept = build_accept();
    let finish_server = build_finish_server();
    // ACCEPT before HELLO
    assert!(matches!(
        fsm.on_accept(&accept),
        Err(ApplicationHandshakeError::ValidationError(_))
    ));
    // FINISH_SERVER before HELLO
    assert!(matches!(
        fsm.on_finish_server(&finish_server),
        Err(ApplicationHandshakeError::ValidationError(_))
    ));
    // Now send HELLO then try FINISH_SERVER skipping ACCEPT
    let hello = build_hello();
    fsm.on_start_client_send_hello(&hello).unwrap();
    assert!(matches!(
        fsm.on_finish_server(&finish_server),
        Err(ApplicationHandshakeError::ValidationError(_))
    ));
}

#[test]
fn client_public_ready_idempotent_and_early() {
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(0),
        sseq: Seq(0),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    // Early ready jumps directly
    fsm.ready();
    assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
    // Idempotent
    fsm.ready();
    assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);
    // After marked ready, attempting hello should error and leave state
    let hello = build_hello();
    assert!(fsm.on_start_client_send_hello(&hello).is_err());
}

#[test]
fn server_public_happy_path() {
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(11),
        sseq: Seq(12),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Server,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    let hello = build_hello();
    let accept = build_accept();
    let finish_client = build_finish_client();
    let finish_server = build_finish_server();

    fsm.on_hello(&hello).unwrap();
    // Simulate hybrid KEM shared secret becoming available on server
    let shared = [7u8; 32];
    fsm.set_hybrid_shared(&shared);
    fsm.on_start_server_send_accept(&accept).unwrap();
    fsm.on_finish_client(&finish_client).unwrap();
    let _fs = fsm.build_finish_server(finish_server).unwrap();
    assert_eq!(fsm.state(), HandshakeState::ReadyToComplete);

    let th = [2u8; 48];
    let shared = [7u8; 32];
    fsm.complete(th, &shared).unwrap();
    assert_eq!(fsm.state(), HandshakeState::Complete);
}

#[test]
fn server_public_invalid_sequences() {
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(0),
        sseq: Seq(0),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Server,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    let accept = build_accept();
    let finish_client = build_finish_client();
    // ACCEPT before HELLO
    assert!(fsm.on_start_server_send_accept(&accept).is_err());
    // FINISH_CLIENT before ACCEPT
    assert!(fsm.on_finish_client(&finish_client).is_err());
}

#[test]
fn public_generic_error_via_cross_role_call() {
    // Client role calling a server-only public method
    let conn = DummyConn {
        client: None,
        server: None,
        cseq: Seq(0),
        sseq: Seq(0),
    };
    let mut fsm = HandshakeFsm::new(
        Role::Client,
        conn,
        DummyTranscript { h: [0; 48] },
        DummyAead,
        WireAdapter,
    );
    let accept = build_accept();
    assert!(fsm.on_start_server_send_accept(&accept).is_err());
}
