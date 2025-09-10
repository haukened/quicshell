use quicshell::core::protocol::handshake::types::*;
use serde_cbor::{from_slice, to_vec, value::to_value, Value};
use std::collections::BTreeMap;

fn bytes_of(b: u8, len: usize) -> Vec<u8> {
    vec![b; len]
}

fn mk_cap(s: &str) -> Capability {
    Capability::parse(s).unwrap()
}

fn mk_keys() -> (Ed25519Pub, Mldsa44Pub, Ed25519Sig, Mldsa44Sig) {
    (
        Ed25519Pub([0; 32]),
        Mldsa44Pub([0; 1312]),
        Ed25519Sig([0; 64]),
        Mldsa44Sig([0; 2420]),
    )
}

fn mk_kem() -> (KemClientEphemeral, KemServerEphemeral, Mlkem768Ciphertext) {
    let x = X25519Pub([0; 32]);
    let m = Mlkem768Pub([0; 1184]);
    let client = KemClientEphemeral {
        x25519_pub: x.clone(),
        mlkem_pub: m.clone(),
    };
    let server = KemServerEphemeral { x25519_pub: x, mlkem_pub: m };
    let ct = Mlkem768Ciphertext([0; 1088]);
    (client, server, ct)
}

fn mk_nonce() -> Nonce32 {
    Nonce32([0; 32])
}

fn map(pairs: Vec<(&str, Value)>) -> Value {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(Value::Text(k.to_string()), v);
    }
    Value::Map(m)
}

#[test]
fn public_construct_valid_hello() {
    let (kem, _, _) = mk_kem();
    let caps = vec![mk_cap("EXEC"), mk_cap("TTY")];
    let h = Hello::new(kem, mk_nonce(), caps, None).unwrap();
    assert!(h.validate().is_ok());
}

#[test]
fn roundtrip_serde_hello_accept_finish() {
    let (kem_client, kem_server, _ct) = mk_kem();
    let hello = Hello::new(
        kem_client,
        mk_nonce(),
        vec![mk_cap("EXEC"), mk_cap("TTY")],
        Some(vec![1, 2]),
    )
    .unwrap();
    let h_rt: Hello = from_slice(&to_vec(&hello).unwrap()).unwrap();
    assert_eq!(hello, h_rt);

    let accept = Accept::new(
        kem_server,
        vec![vec![0]],
        mk_nonce(),
        None,
        None,
        Some(vec![3, 4]),
    )
    .unwrap();
    let a_rt: Accept = from_slice(&to_vec(&accept).unwrap()).unwrap();
    assert_eq!(accept, a_rt);

    let finish_server = FinishServer::new(bytes_of(1, 16), Some(vec![7]), Some(vec![8, 9])).unwrap();
    let fs_rt: FinishServer = from_slice(&to_vec(&finish_server).unwrap()).unwrap();
    assert_eq!(finish_server, fs_rt);
}

#[test]
fn user_auth_roundtrip_both_arms() {
    let (ed_pub, ml_pub, ed_sig, ml_sig) = mk_keys();
    let raw_val = map(vec![
        (
            "raw_keys",
            to_value(RawKeys {
                ed25519_pub: ed_pub.clone(),
                mldsa44_pub: ml_pub.clone(),
            })
            .unwrap(),
        ),
        (
            "sig",
            to_value(HybridSig {
                ed25519: ed_sig.clone(),
                mldsa44: ml_sig.clone(),
            })
            .unwrap(),
        ),
    ]);
    let raw_rt: UserAuth = from_slice(&to_vec(&raw_val).unwrap()).unwrap();
    assert_eq!(
        raw_rt,
        UserAuth::RawKeys {
            raw_keys: Box::new(RawKeys {
                ed25519_pub: ed_pub.clone(),
                mldsa44_pub: ml_pub.clone(),
            }),
            sig: Box::new(HybridSig {
                ed25519: ed_sig.clone(),
                mldsa44: ml_sig.clone(),
            }),
        }
    );

    let cert_val = map(vec![
        (
            "user_cert_chain",
            to_value(vec![vec![1, 2]]).unwrap(),
        ),
        (
            "sig",
            to_value(HybridSig {
                ed25519: ed_sig,
                mldsa44: ml_sig,
            })
            .unwrap(),
        ),
    ]);
    let cert_rt: UserAuth = from_slice(&to_vec(&cert_val).unwrap()).unwrap();
    assert_eq!(
        cert_rt,
        UserAuth::CertChain {
            user_cert_chain: vec![vec![1, 2]],
            sig: Box::new(HybridSig {
                ed25519: Ed25519Sig([0; 64]),
                mldsa44: Mldsa44Sig([0; 2420]),
            }),
        }
    );
}
