use crate::domain::handshake::params::{
    ED25519_PK_LEN, ED25519_SIG_LEN, MLDSA44_PK_LEN, MLDSA44_SIG_LEN,
};
use core::fmt;
use serde::{Deserialize, Serialize}; // macro import
/// Ed25519 public key (32 bytes) for user authentication (raw key path).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519Pub(pub [u8; ED25519_PK_LEN]);
impl fmt::Debug for Ed25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Pub(..)")
    }
}
impl Ed25519Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PK_LEN] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519Sig(pub [u8; ED25519_SIG_LEN]);
impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Sig(..)")
    }
}
impl Ed25519Sig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.0
    }
}
crate::impl_large_array_newtype_serde!(Ed25519Sig, ED25519_SIG_LEN);

/// ML-DSA-44 (Dilithium level 2) public key (1312 bytes) for user authentication.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mldsa44Pub(pub [u8; MLDSA44_PK_LEN]);
impl fmt::Debug for Mldsa44Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Pub(..)")
    }
}
impl Mldsa44Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA44_PK_LEN] {
        &self.0
    }
}
crate::impl_large_array_newtype_serde!(Mldsa44Pub, MLDSA44_PK_LEN);

/// ML-DSA-44 signature (2420 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mldsa44Sig(pub [u8; MLDSA44_SIG_LEN]);
impl fmt::Debug for Mldsa44Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Sig(..)")
    }
}
impl Mldsa44Sig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA44_SIG_LEN] {
        &self.0
    }
}
crate::impl_large_array_newtype_serde!(Mldsa44Sig, MLDSA44_SIG_LEN);

/// Hybrid user authentication signature bundle (Ed25519 + ML-DSA-44).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSig {
    pub ed25519: Ed25519Sig,
    pub mldsa44: Mldsa44Sig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawKeys {
    /// User Ed25519 public key.
    pub ed25519_pub: Ed25519Pub,
    /// User ML-DSA-44 public key.
    pub mldsa44_pub: Mldsa44Pub,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::params::{ED25519_SIG_LEN, MLDSA44_PK_LEN, MLDSA44_SIG_LEN};
    use ciborium::{de::from_reader, ser::into_writer};
    use std::io::Cursor;

    #[test]
    fn large_array_length_mismatch_keys() {
        let short = vec![0u8; 10];
        let mut buf = Vec::new();
        into_writer(&short, &mut buf).unwrap();
        let err = from_reader::<Mldsa44Pub, _>(Cursor::new(&buf))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid length") && err.contains(&MLDSA44_PK_LEN.to_string()));
        let err = from_reader::<Ed25519Sig, _>(Cursor::new(&buf))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid length") && err.contains(&ED25519_SIG_LEN.to_string()));
        let err = from_reader::<Mldsa44Sig, _>(Cursor::new(&buf))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid length") && err.contains(&MLDSA44_SIG_LEN.to_string()));
    }

    #[test]
    fn serde_round_trip_keys_and_signatures_and_debug() {
        // Deterministic pseudo-data for coverage.
        let mut ed_pub_bytes = [0u8; ED25519_PK_LEN];
        for (i, b) in ed_pub_bytes.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5A;
        }
        let mut ed_sig_bytes = [0u8; ED25519_SIG_LEN];
        for (i, b) in ed_sig_bytes.iter_mut().enumerate() {
            *b = 255 - i as u8;
        }
        let mut mldsa_pub_bytes = [0u8; MLDSA44_PK_LEN];
        for (i, b) in mldsa_pub_bytes.iter_mut().enumerate() {
            *b = (i % 253) as u8;
        }
        let mut mldsa_sig_bytes = [0u8; MLDSA44_SIG_LEN];
        for (i, b) in mldsa_sig_bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let ed_pub = Ed25519Pub(ed_pub_bytes);
        let ed_sig = Ed25519Sig(ed_sig_bytes);
        let mldsa_pub = Mldsa44Pub(mldsa_pub_bytes);
        let mldsa_sig = Mldsa44Sig(mldsa_sig_bytes);

        assert_eq!(ed_pub.as_bytes().len(), ED25519_PK_LEN);
        assert_eq!(ed_sig.as_bytes().len(), ED25519_SIG_LEN);
        assert_eq!(mldsa_pub.as_bytes().len(), MLDSA44_PK_LEN);
        assert_eq!(mldsa_sig.as_bytes().len(), MLDSA44_SIG_LEN);

        let dbg_ed = format!("{:?}", ed_pub);
        assert!(dbg_ed.contains("Ed25519Pub"));
        let dbg_ed_sig = format!("{:?}", ed_sig);
        assert!(dbg_ed_sig.contains("Ed25519Sig"));
        let dbg_mldsa_pub = format!("{:?}", mldsa_pub);
        assert!(dbg_mldsa_pub.contains("Mldsa44Pub"));
        let dbg_mldsa_sig = format!("{:?}", mldsa_sig);
        assert!(dbg_mldsa_sig.contains("Mldsa44Sig"));

        let hybrid = HybridSig {
            ed25519: ed_sig.clone(),
            mldsa44: mldsa_sig.clone(),
        };
        let raw_keys = RawKeys {
            ed25519_pub: ed_pub.clone(),
            mldsa44_pub: mldsa_pub.clone(),
        };

        fn round_trip<
            T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + core::fmt::Debug,
        >(
            v: &T,
        ) {
            let mut buf = Vec::new();
            into_writer(v, &mut buf).unwrap();
            let de: T = from_reader(Cursor::new(&buf)).unwrap();
            assert_eq!(&de, v);
        }
        round_trip(&ed_sig);
        round_trip(&mldsa_pub);
        round_trip(&mldsa_sig);
        round_trip(&hybrid);
        round_trip(&raw_keys);
    }
}
