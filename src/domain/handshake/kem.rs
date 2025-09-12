use crate::domain::handshake::params::{MLKEM768_CT_LEN, MLKEM768_PK_LEN, X25519_PK_LEN};
use core::fmt;
use serde::{Deserialize, Serialize};

/// X25519 public key (fixed 32 bytes) used in hybrid KEM ephemeral key pairs.
// yes, i know X25519 isn't technically a KEM, but it's being used like one here.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct X25519Pub(pub [u8; X25519_PK_LEN]);
impl fmt::Debug for X25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Pub(..)")
    }
}
impl X25519Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PK_LEN] {
        &self.0
    }
}

/// ML-KEM-768 public key (1184 bytes) used in hybrid KEM ephemeral key pairs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mlkem768Pub(pub [u8; MLKEM768_PK_LEN]);
impl fmt::Debug for Mlkem768Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Pub(..)")
    }
}
impl Mlkem768Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PK_LEN] {
        &self.0
    }
}
crate::impl_large_array_newtype_serde!(Mlkem768Pub, MLKEM768_PK_LEN);

/// ML-KEM-768 ciphertext (1088 bytes) produced by encapsulation in `FINISH_CLIENT`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mlkem768Ciphertext(pub [u8; MLKEM768_CT_LEN]);
impl fmt::Debug for Mlkem768Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Ciphertext(..)")
    }
}
impl Mlkem768Ciphertext {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLKEM768_CT_LEN] {
        &self.0
    }
}
crate::impl_large_array_newtype_serde!(Mlkem768Ciphertext, MLKEM768_CT_LEN);

/// Ephemeral hybrid KEM public keys sent by client in `HELLO`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemClientEphemeral {
    pub x25519_pub: X25519Pub,
    pub mlkem_pub: Mlkem768Pub,
}

/// Ephemeral hybrid KEM public keys sent by server in `ACCEPT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemServerEphemeral {
    pub x25519_pub: X25519Pub,
    pub mlkem_pub: Mlkem768Pub,
}

/// Hybrid KEM ciphertexts sent by client in `FINISH_CLIENT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemCiphertexts {
    /// Hybrid KEM ML-KEM-768 ciphertext encapsulating shared secret material.
    pub mlkem_ct: Mlkem768Ciphertext,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::params::{MLKEM768_CT_LEN, MLKEM768_PK_LEN};
    use ciborium::{de::from_reader, ser::into_writer};
    use std::io::Cursor;

    #[test]
    fn large_array_length_mismatch_kem() {
        let short = vec![0u8; 10];
        let mut buf = Vec::new();
        into_writer(&short, &mut buf).unwrap();
        let err = from_reader::<Mlkem768Pub, _>(Cursor::new(&buf))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid length") && err.contains(&MLKEM768_PK_LEN.to_string()));
        let err = from_reader::<Mlkem768Ciphertext, _>(Cursor::new(&buf))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid length") && err.contains(&MLKEM768_CT_LEN.to_string()));
    }

    #[test]
    fn serde_round_trip_kem_newtypes_and_ephemeral_structs() {
        // Construct deterministic byte patterns for coverage (avoid randomness for stability).
        let mut mlkem_pk_bytes = [0u8; MLKEM768_PK_LEN];
        for (i, b) in mlkem_pk_bytes.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut mlkem_ct_bytes = [0u8; MLKEM768_CT_LEN];
        for (i, b) in mlkem_ct_bytes.iter_mut().enumerate() {
            *b = 255 - (i % 251) as u8;
        }
        let mut x25519_bytes = [0u8; X25519_PK_LEN];
        for (i, b) in x25519_bytes.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xA5;
        }

        let x_pub = X25519Pub(x25519_bytes);
        let mlkem_pub = Mlkem768Pub(mlkem_pk_bytes);
        let mlkem_ct = Mlkem768Ciphertext(mlkem_ct_bytes);

        // as_bytes() coverage assertions
        assert_eq!(x_pub.as_bytes().len(), X25519_PK_LEN);
        assert_eq!(mlkem_pub.as_bytes().len(), MLKEM768_PK_LEN);
        assert_eq!(mlkem_ct.as_bytes().len(), MLKEM768_CT_LEN);

        // Debug impl coverage
        let d1 = format!("{:?}", x_pub);
        let d2 = format!("{:?}", mlkem_pub);
        let d3 = format!("{:?}", mlkem_ct);
        assert!(d1.contains("X25519Pub"));
        assert!(d2.contains("Mlkem768Pub"));
        assert!(d3.contains("Mlkem768Ciphertext"));

        let client = KemClientEphemeral {
            x25519_pub: x_pub.clone(),
            mlkem_pub: mlkem_pub.clone(),
        };
        let server = KemServerEphemeral {
            x25519_pub: x_pub.clone(),
            mlkem_pub: mlkem_pub.clone(),
        };
        let cts = KemCiphertexts {
            mlkem_ct: mlkem_ct.clone(),
        };

        // Round trip each struct via CBOR to exercise Serialize/Deserialize derives.
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
        round_trip(&mlkem_pub);
        round_trip(&mlkem_ct);
        round_trip(&client);
        round_trip(&server);
        round_trip(&cts);
    }
}
