use crate::domain::handshake::errors::HandshakeError;
use crate::domain::handshake::params::NONCE_LEN;
use aead::rand_core;
use core::{convert::TryFrom, fmt};
use serde::{Deserialize, Serialize};

/// 32-byte handshake freshness nonce used in `HELLO.client_nonce` and `ACCEPT.server_nonce`.
///
/// This nonce is sampled uniformly at random per handshake side and is **only**
/// used for handshake message freshness (not for AEAD payload nonces). The
/// transport / channel layer derives deterministic AEAD nonces separately from
/// `NonceSalt` + sequence counters; keep those domains distinct.
///
/// Construction options:
/// - `HandshakeNonce::random(rng)` for cryptographically strong randomness.
/// - `HandshakeNonce::try_from(&[u8])` for fallible decoding/validation from a slice.
/// - `HandshakeNonce::from([u8;32])` zero‑cost conversion from an owned array.
///
/// Trait conveniences: implements `TryFrom<&[u8]>`, `From<[u8;32]>`, `AsRef<[u8]>`.
///
/// Invariants:
/// - Always exactly 32 bytes (`NONCE_LEN`).
/// - Opaque: `Debug` redacts inner value to avoid accidental logging of raw
///   handshake entropy.
///
/// Security:
/// - Do not reuse a previously generated `HandshakeNonce` across independent handshakes.
/// - Do not confuse this with AEAD nonces; misuse can enable replay or nonce
///   collision at the encryption layer.
///
/// # Examples
/// ```
/// use quicshell::domain::handshake::HandshakeNonce;
/// use std::convert::TryFrom;
/// // Construct from array
/// let a = HandshakeNonce::try_from(&[1u8;32][..]).unwrap();
/// assert_eq!(a.as_bytes()[0], 1);
/// // Random (illustrative - not asserting entropy)
/// let mut rng = aead::rand_core::OsRng;
/// let r = HandshakeNonce::random(&mut rng);
/// assert_ne!(r.as_bytes(), a.as_bytes());
/// // Error on wrong length
/// assert!(HandshakeNonce::try_from(&[0u8; 31][..]).is_err());
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HandshakeNonce([u8; NONCE_LEN]);
impl fmt::Debug for HandshakeNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandshakeNonce(..)")
    }
}

impl fmt::Display for HandshakeNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact full value; show first 8 bytes hex for trace correlation.
        let bytes = &self.0;
        for b in bytes.iter().take(8) {
            write!(f, "{b:02x}")?;
        }
        write!(f, "…")
    }
}

impl HandshakeNonce {
    /// Securely generate a random `HandshakeNonce` using the provided CSPRNG.
    ///
    /// The caller supplies the RNG (dependency inversion for testability).
    ///
    /// # Security
    /// Each handshake participant MUST generate a fresh value; never reuse.
    #[must_use]
    pub fn random<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self {
        let mut arr = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut arr);
        HandshakeNonce(arr)
    }

    /// Access the inner byte array.
    ///
    /// This returns a reference; the caller must not assume any particular
    /// distribution beyond uniform randomness at generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl TryFrom<&[u8]> for HandshakeNonce {
    type Error = HandshakeError;

    /// Attempt to construct a `HandshakeNonce` from a byte slice.
    ///
    /// # Errors
    /// Returns `HandshakeError::LengthMismatch` if the slice length != `NONCE_LEN`.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != NONCE_LEN {
            return Err(HandshakeError::LengthMismatch {
                field: "HandshakeNonce",
                expected: NONCE_LEN,
                actual: value.len(),
            });
        }
        let mut arr = [0u8; NONCE_LEN];
        arr.copy_from_slice(value);
        Ok(HandshakeNonce(arr))
    }
}

impl From<[u8; NONCE_LEN]> for HandshakeNonce {
    /// Zero-cost conversion from an owned 32-byte array into a `HandshakeNonce`.
    fn from(value: [u8; NONCE_LEN]) -> Self {
        HandshakeNonce(value)
    }
}

impl AsRef<[u8]> for HandshakeNonce {
    /// Borrow the inner bytes as a slice (e.g., for serialization APIs).
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::errors::HandshakeError;
    use crate::domain::handshake::params::NONCE_LEN;
    use aead::rand_core::{CryptoRng, RngCore};
    use core::convert::TryFrom;

    #[test]
    fn handshake_nonce_try_from_success_and_error() {
        let good = vec![1u8; NONCE_LEN];
        let n = HandshakeNonce::try_from(good.as_slice()).unwrap();
        assert_eq!(n.as_bytes(), &good[..]);
        // Debug formatting coverage
        let d = format!("{:?}", n);
        assert!(d.contains("HandshakeNonce"));
        let bad = vec![2u8; NONCE_LEN - 1];
        let err = HandshakeNonce::try_from(bad.as_slice()).unwrap_err();
        match err {
            HandshakeError::LengthMismatch {
                field,
                expected,
                actual,
            } => {
                assert_eq!(field, "HandshakeNonce");
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
    fn handshake_nonce_random_deterministic() {
        let mut rng = ZeroRng;
        let n1 = HandshakeNonce::random(&mut rng);
        let n2 = HandshakeNonce::random(&mut rng);
        assert_eq!(n1, n2, "ZeroRng should produce identical nonces");
        assert_eq!(n1.as_bytes().len(), NONCE_LEN);
    }

    #[test]
    fn handshake_nonce_random() {
        let mut rng = aead::rand_core::OsRng;
        let n1 = HandshakeNonce::random(&mut rng);
        let n2 = HandshakeNonce::random(&mut rng);
        assert_ne!(n1, n2, "OsRng should produce different nonces");
        assert_eq!(n1.as_bytes().len(), NONCE_LEN);
        assert_eq!(n2.as_bytes().len(), NONCE_LEN);
    }

    #[test]
    fn handshake_nonce_from_array_and_asref() {
        let arr = [7u8; NONCE_LEN];
        let n: HandshakeNonce = arr.into();
        assert_eq!(n.as_bytes(), &arr);
        assert_eq!(n.as_ref(), &arr);
    }

    #[test]
    fn handshake_nonce_display_redacted() {
        let arr = [0xABu8; NONCE_LEN];
        let n: HandshakeNonce = arr.into();
        let disp = format!("{n}");
        assert!(disp.ends_with('…'));
        assert!(disp.len() > 3);
        // Should not contain full 64 hex chars (only first 8 bytes -> 16 hex chars + ellipsis)
        assert!(disp.len() < 70);
    }
}
