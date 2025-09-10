use quicshell::domain::handshake::*;
use serde_cbor::{from_slice, to_vec};
use serde::Serialize;

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
        KemServerEphemeral { x25519_pub: x, mlkem_pub: m },
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
    let hello = Hello::new(
        kem_c,
        mk_nonce(),
        vec![mk_cap("EXEC"), mk_cap("TTY")],
        None,
    )
    .unwrap();
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
    let finish_server = FinishServer::new(
        bytes_of(6, 16),
        Some(vec![7u8]),
        Some(bytes_of(8, 2)),
    )
    .unwrap();

    let hello_rt: Hello = from_slice(&to_vec(&hello).unwrap()).unwrap();
    assert_eq!(hello, hello_rt);
    let accept_rt: Accept = from_slice(&to_vec(&accept).unwrap()).unwrap();
    assert_eq!(accept, accept_rt);

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
        RawKeys { raw_keys: &'a RawKeys, sig: &'a HybridSig },
        CertChain { user_cert_chain: &'a [Vec<u8>], sig: &'a HybridSig },
    }

    let fc_wire = FinishClientWire {
        kem_ciphertexts: &finish_client.kem_ciphertexts,
        user_auth: match &finish_client.user_auth {
            UserAuth::RawKeys { raw_keys, sig } => UserAuthWire::RawKeys {
                raw_keys,
                sig,
            },
            UserAuth::CertChain { user_cert_chain, sig } => UserAuthWire::CertChain {
                user_cert_chain,
                sig,
            },
        },
        client_confirm: &finish_client.client_confirm,
        pad: &finish_client.pad,
    };
    let fc_rt: FinishClient = from_slice(&to_vec(&fc_wire).unwrap()).unwrap();
    assert_eq!(finish_client, fc_rt);

    let fs_rt: FinishServer = from_slice(&to_vec(&finish_server).unwrap()).unwrap();
    assert_eq!(finish_server, fs_rt);
}

#[test]
fn user_auth_roundtrip_both_arms() {
    let (raw_keys, sig) = mk_keys();
    #[derive(Serialize)]
    #[serde(untagged)]
    enum UAuthWire<'a> {
        RawKeys { raw_keys: &'a RawKeys, sig: &'a HybridSig },
        CertChain { user_cert_chain: &'a [Vec<u8>], sig: &'a HybridSig },
    }

    let raw_bytes = to_vec(&UAuthWire::RawKeys {
        raw_keys: &raw_keys,
        sig: &sig,
    })
    .unwrap();
    let ua_raw: UserAuth = from_slice(&raw_bytes).unwrap();
    let raw_bytes2 = to_vec(&UAuthWire::RawKeys {
        raw_keys: match &ua_raw {
            UserAuth::RawKeys { raw_keys, .. } => raw_keys,
            _ => panic!(),
        },
        sig: match &ua_raw {
            UserAuth::RawKeys { sig, .. } => sig,
            _ => panic!(),
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
        user_cert_chain: match &ua_chain {
            UserAuth::CertChain { user_cert_chain, .. } => user_cert_chain,
            _ => panic!(),
        },
        sig: match &ua_chain {
            UserAuth::CertChain { sig, .. } => sig,
            _ => panic!(),
        },
    })
    .unwrap();
    let ua_chain2: UserAuth = from_slice(&chain_bytes2).unwrap();
    assert_eq!(ua_chain, ua_chain2);
}
