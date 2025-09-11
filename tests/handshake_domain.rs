// integration and RTT tests for handshake domain types
// unit tests live with the types they test

use quicshell::domain::handshake::*;
use std::io::Cursor;

// Test-local CBOR helpers using ciborium (deterministic by default)
fn to_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf)?;
    Ok(buf)
}
fn from_slice<T: for<'de> serde::Deserialize<'de>>(
    b: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(Cursor::new(b))
}
use serde::Serialize;

// Helper structs/enums used across tests (defined before any statements for clippy pedantic):
#[derive(Serialize)]
struct FinishClientWire<'a> {
    kem_ciphertexts: &'a KemCiphertexts,
    user_auth: UserAuthWire<'a>,
    client_confirm: &'a [u8],
    #[serde(skip_serializing_if = "Option::is_none")]
    pad: &'a Option<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum UserAuthWire<'a> {
    RawKeys {
        raw_keys: &'a RawKeys,
        sig: &'a HybridSig,
    },
    CertChain {
        user_cert_chain: &'a [Vec<u8>],
        sig: &'a HybridSig,
    },
}

#[derive(Serialize)]
#[serde(untagged)]
enum UAuthWire<'a> {
    RawKeys {
        raw_keys: &'a RawKeys,
        sig: &'a HybridSig,
    },
    CertChain {
        user_cert_chain: &'a [Vec<u8>],
        sig: &'a HybridSig,
    },
}

fn bytes_of(n: u8, len: usize) -> Vec<u8> {
    vec![n; len]
}

fn mk_cap(s: &str) -> Capability {
    Capability::parse(s).unwrap()
}

fn mk_kem() -> (KemClientEphemeral, KemServerEphemeral, KemCiphertexts) {
    let x = X25519Pub([0; 32]);
    let m = Mlkem768Pub([0; 1184]);
    let ct = Mlkem768Ciphertext([0; 1088]);
    (
        KemClientEphemeral {
            x25519_pub: x.clone(),
            mlkem_pub: m.clone(),
        },
        KemServerEphemeral {
            x25519_pub: x,
            mlkem_pub: m,
        },
        KemCiphertexts { mlkem_ct: ct },
    )
}

fn mk_keys() -> (RawKeys, HybridSig) {
    (
        RawKeys {
            ed25519_pub: Ed25519Pub([0; 32]),
            mldsa44_pub: Mldsa44Pub([0; 1312]),
        },
        HybridSig {
            ed25519: Ed25519Sig([0; 64]),
            mldsa44: Mldsa44Sig([0; 2420]),
        },
    )
}

fn mk_nonce() -> Nonce32 {
    Nonce32([0; 32])
}

#[test]
fn public_construct_valid_hello() {
    let (kem_c, _, _) = mk_kem();
    let hello = Hello::new(kem_c, mk_nonce(), vec![mk_cap("EXEC"), mk_cap("TTY")], None).unwrap();
    assert!(hello.validate().is_ok());
}

#[test]
fn roundtrip_serde_hello_accept_finish() {
    let (kem_c, kem_s, kem_ct) = mk_kem();
    let hello = Hello::new(
        kem_c,
        mk_nonce(),
        vec![mk_cap("EXEC"), mk_cap("TTY")],
        Some(bytes_of(1, 4)),
    )
    .unwrap();
    let accept = Accept::new(
        kem_s,
        vec![bytes_of(2, 2)],
        mk_nonce(),
        None,
        None,
        Some(bytes_of(3, 3)),
    )
    .unwrap();
    let (raw_keys, sig) = mk_keys();
    let finish_client = FinishClient::new(
        kem_ct.clone(),
        UserAuth::RawKeys {
            raw_keys: Box::new(raw_keys),
            sig: Box::new(sig),
        },
        bytes_of(4, 16),
        Some(bytes_of(5, 1)),
    )
    .unwrap();
    let finish_server =
        FinishServer::new(bytes_of(6, 16), Some(vec![7u8]), Some(bytes_of(8, 2))).unwrap();

    let hello_rt: Hello = from_slice(&to_vec(&hello).unwrap()).unwrap();
    assert_eq!(hello, hello_rt);
    let accept_rt: Accept = from_slice(&to_vec(&accept).unwrap()).unwrap();
    assert_eq!(accept, accept_rt);

    let fc_wire = FinishClientWire {
        kem_ciphertexts: &finish_client.kem_ciphertexts,
        user_auth: match &finish_client.user_auth {
            UserAuth::RawKeys { raw_keys, sig } => UserAuthWire::RawKeys { raw_keys, sig },
            UserAuth::CertChain {
                user_cert_chain,
                sig,
            } => UserAuthWire::CertChain {
                user_cert_chain,
                sig,
            },
        },
        client_confirm: &finish_client.client_confirm,
        pad: &finish_client.pad,
    };
    let finish_client_round_trip: FinishClient = from_slice(&to_vec(&fc_wire).unwrap()).unwrap();
    assert_eq!(finish_client, finish_client_round_trip);

    let finish_server_round_trip: FinishServer =
        from_slice(&to_vec(&finish_server).unwrap()).unwrap();
    assert_eq!(finish_server, finish_server_round_trip);
}

#[test]
fn user_auth_roundtrip_both_arms() {
    let (raw_keys, sig) = mk_keys();

    let raw_bytes = to_vec(&UAuthWire::RawKeys {
        raw_keys: &raw_keys,
        sig: &sig,
    })
    .unwrap();
    let ua_raw: UserAuth = from_slice(&raw_bytes).unwrap();
    let raw_bytes2 = to_vec(&UAuthWire::RawKeys {
        raw_keys: if let UserAuth::RawKeys { raw_keys, .. } = &ua_raw {
            raw_keys
        } else {
            panic!()
        },
        sig: if let UserAuth::RawKeys { sig, .. } = &ua_raw {
            sig
        } else {
            panic!()
        },
    })
    .unwrap();
    let ua_raw2: UserAuth = from_slice(&raw_bytes2).unwrap();
    assert_eq!(ua_raw, ua_raw2);

    let (_, sig2) = mk_keys();
    let chain_bytes = to_vec(&UAuthWire::CertChain {
        user_cert_chain: &[bytes_of(1, 1)],
        sig: &sig2,
    })
    .unwrap();
    let ua_chain: UserAuth = from_slice(&chain_bytes).unwrap();
    let chain_bytes2 = to_vec(&UAuthWire::CertChain {
        user_cert_chain: if let UserAuth::CertChain {
            user_cert_chain, ..
        } = &ua_chain
        {
            user_cert_chain
        } else {
            panic!()
        },
        sig: if let UserAuth::CertChain { sig, .. } = &ua_chain {
            sig
        } else {
            panic!()
        },
    })
    .unwrap();
    let ua_chain2: UserAuth = from_slice(&chain_bytes2).unwrap();
    assert_eq!(ua_chain, ua_chain2);
}
