use crate::domain::handshake::errors::HandshakeError;
use crate::domain::handshake::params::NONCE_LEN;
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
}
