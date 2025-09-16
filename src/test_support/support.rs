#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::missing_errors_doc)]
#[allow(clippy::wildcard_imports)]
use crate::domain::handshake::*;
use std::io::Cursor;

/// Simple byte filler
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn bytes_of(b: u8, len: usize) -> Vec<u8> {
    vec![b; len]
}

/// CBOR helpers for tests (deterministic by default)
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn to_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf)?;
    Ok(buf)
}
pub fn from_slice<T: for<'de> serde::Deserialize<'de>>(
    b: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(Cursor::new(b))
}

/// Capability helper
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_cap(s: &str) -> Capability {
    Capability::parse(s).unwrap()
}

/// 32-byte zeroed nonce
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_nonce() -> HandshakeNonce {
    // Deterministic zero nonce strictly for tests.
    HandshakeNonce::try_from(&[0u8; 32][..]).unwrap()
}

/// Construct dummy KEM values (client/server ephemeral + ciphertext)
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_kem() -> (KemClientEphemeral, KemServerEphemeral, KemCiphertexts) {
    (
        KemClientEphemeral {
            x25519_pub: X25519Pub([0; 32]),
            mlkem_pub: Mlkem768Pub([0; 1184]),
        },
        KemServerEphemeral {
            x25519_pub: X25519Pub([0; 32]),
            mlkem_pub: Mlkem768Pub([0; 1184]),
        },
        KemCiphertexts {
            mlkem_ct: Mlkem768Ciphertext([0; 1088]),
        },
    )
}

/// Construct dummy keypairs + hybrid sig
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_keys() -> (Box<RawKeys>, Box<HybridSig>) {
    (
        Box::new(RawKeys {
            ed25519_pub: Ed25519Pub([0; 32]),
            mldsa44_pub: Mldsa44Pub([0; 1312]),
        }),
        Box::new(HybridSig {
            ed25519: Ed25519Sig([0; 64]),
            mldsa44: Mldsa44Sig([0; 2420]),
        }),
    )
}

/// Construct a dummy Hello with EXEC+TTY and zeroed nonce/kem
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_hello() -> Hello {
    let (kem_c, _, _) = mk_kem();
    let caps = vec![mk_cap("EXEC"), mk_cap("TTY")];
    Hello::new(kem_c, mk_nonce(), caps, None).unwrap()
}

/// Construct a dummy Accept with zeroed kem, nonce, and one dummy cert
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_accept() -> Accept {
    let (_, kem_s, _) = mk_kem();
    let certs = vec![vec![0u8; 8]];
    Accept::new(kem_s, certs, mk_nonce(), None, None, None).unwrap()
}

/// Construct a dummy `FinishClient` with dummy KEM ciphertext and raw keys+sig+
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_finish_client() -> FinishClient {
    let (_, _, kem_ct) = mk_kem();
    let (raw, sig) = mk_keys();
    FinishClient::new(
        kem_ct,
        UserAuth::RawKeys { raw_keys: raw, sig },
        vec![0u8; 16],
        None,
    )
    .unwrap()
}

/// Construct a dummy `FinishServer` with confirm tag and no ticket
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::must_use_candidate)]
pub fn mk_finish_server() -> FinishServer {
    FinishServer::new(vec![0u8; 16], None, None).unwrap()
}
