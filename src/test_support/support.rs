#![allow(dead_code)]
#![cfg(test)]
use std::io::Cursor;
use crate::domain::handshake::*;

/// Simple byte filler
pub fn bytes_of(b: u8, len: usize) -> Vec<u8> { vec![b; len] }

/// CBOR helpers for tests (deterministic by default)
pub fn to_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(v, &mut buf)?;
    Ok(buf)
}
pub fn from_slice<T: for<'de> serde::Deserialize<'de>>(b: &[u8]) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(Cursor::new(b))
}

/// Capability helper
pub fn mk_cap(s: &str) -> Capability { Capability::parse(s).unwrap() }

/// 32-byte zeroed nonce
pub fn mk_nonce() -> Nonce32 { Nonce32([0u8; 32]) }

/// Construct dummy KEM values (client/server ephemeral + ciphertext)
pub fn mk_kem() -> (KemClientEphemeral, KemServerEphemeral, KemCiphertexts) {
    (
        KemClientEphemeral { x25519_pub: X25519Pub([0; 32]), mlkem_pub: Mlkem768Pub([0; 1184]) },
        KemServerEphemeral { x25519_pub: X25519Pub([0; 32]), mlkem_pub: Mlkem768Pub([0; 1184]) },
        KemCiphertexts { mlkem_ct: Mlkem768Ciphertext([0; 1088]) },
    )
}

/// Construct dummy keypairs + hybrid sig
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
pub fn mk_hello() -> Hello {
    let (kem_c, _, _) = mk_kem();
    let caps = vec![mk_cap("EXEC"), mk_cap("TTY")];
    Hello::new(kem_c, mk_nonce(), caps, None).unwrap()
}

/// Construct a dummy Accept with zeroed kem, nonce, and one dummy cert
pub fn mk_accept() -> Accept {
    let (_, kem_s, _) = mk_kem();
    let certs = vec![vec![0u8; 8]];
    Accept::new(kem_s, certs, mk_nonce(), None, None, None).unwrap()
}

/// Construct a dummy FinishClient with dummy kem ciphertext and raw keys+sig
pub fn mk_finish_client() -> FinishClient {
    let (_, _, kem_ct) = mk_kem();
    let (raw, sig) = mk_keys();
    FinishClient::new(kem_ct, UserAuth::RawKeys { raw_keys: raw, sig }, vec![0u8; 16], None).unwrap()
}

/// Construct a dummy FinishServer with confirm tag and no ticket
pub fn mk_finish_server() -> FinishServer {
    FinishServer::new(vec![0u8; 16], None, None).unwrap()
}