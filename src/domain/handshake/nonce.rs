use crate::domain::handshake::errors::HandshakeError;
use crate::domain::handshake::params::NONCE_LEN;
use aead::rand_core;
use core::fmt;
use serde::{Deserialize, Serialize};

/// 32-byte nonce used in `HELLO.client_nonce` and `ACCEPT.server_nonce`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nonce32(pub [u8; NONCE_LEN]);
impl fmt::Debug for Nonce32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce32(..)")
    }
}

impl Nonce32 {
    /// Securely generate a random nonce using the provided CSPRNG.
    #[must_use]
    pub fn random<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let mut arr = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut arr);
        Nonce32(arr)
    }

    /// Access the inner byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Create a `Nonce32` from a byte slice, validating length.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input slice length does not match `NONCE_LEN`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, HandshakeError> {
        if b.len() != NONCE_LEN {
            return Err(HandshakeError::LengthMismatch {
                field: "Nonce32",
                expected: NONCE_LEN,
                actual: b.len(),
            });
        }
        let mut arr = [0u8; NONCE_LEN];
        arr.copy_from_slice(b);
        Ok(Nonce32(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::errors::HandshakeError;
    use crate::domain::handshake::params::NONCE_LEN;
    use aead::rand_core::{CryptoRng, RngCore};

    #[test]
    fn nonce32_from_bytes_success_and_error() {
        let good = vec![1u8; NONCE_LEN];
        let n = Nonce32::from_bytes(&good).unwrap();
        assert_eq!(n.as_bytes(), &good[..]);
        // Debug formatting coverage
        let d = format!("{:?}", n);
        assert!(d.contains("Nonce32"));
        let bad = vec![2u8; NONCE_LEN - 1];
        let err = Nonce32::from_bytes(&bad).unwrap_err();
        match err {
            HandshakeError::LengthMismatch {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "Nonce32");
                assert_eq!(expected, NONCE_LEN);
                assert_eq!(actual, NONCE_LEN - 1);
            }
            _ => panic!("unexpected {err:?}"),
        }
    }

    // Minimal zero RNG for deterministic, non-random test output.
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                *b = 0;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), aead::rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for ZeroRng {}

    #[test]
    fn zrng_works() {
        let mut rng = ZeroRng;
        let mut buf = [1u8; 16];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [0u8; 16], "ZeroRng should fill with zeros");
        rng.try_fill_bytes(&mut buf).unwrap();
        assert_eq!(buf, [0u8; 16], "ZeroRng should fill with zeros");
        let n1 = rng.next_u32();
        let n2 = rng.next_u64();
        assert_eq!(n1, 0);
        assert_eq!(n2, 0);
    }

    #[test]
    fn nonce32_random_deterministic() {
        let mut rng = ZeroRng;
        let n1 = Nonce32::random(&mut rng);
        let n2 = Nonce32::random(&mut rng);
        assert_eq!(n1, n2, "ZeroRng should produce identical nonces");
        assert_eq!(n1.as_bytes().len(), NONCE_LEN);
    }

    #[test]
    fn nonce32_random() {
        let mut rng = aead::rand_core::OsRng;
        let n1 = Nonce32::random(&mut rng);
        let n2 = Nonce32::random(&mut rng);
        assert_ne!(n1, n2, "OsRng should produce different nonces");
        assert_eq!(n1.as_bytes().len(), NONCE_LEN);
        assert_eq!(n2.as_bytes().len(), NONCE_LEN);
    }
}
