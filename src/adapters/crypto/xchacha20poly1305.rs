// src/adapters/crypto/chacha20poly1305.rs
use crate::ports::crypto::{AeadError, AeadKey, AeadSeal, NonceSalt, Seq};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit},
};

// Nonce construction helper
fn make_nonce(salt: NonceSalt, seq: Seq) -> XNonce {
    let mut n = [0u8; 24];
    // 16-byte salt then 8-byte big-endian sequence
    n[0..16].copy_from_slice(&salt.0);
    n[16..24].copy_from_slice(&seq.0.to_be_bytes());
    XNonce::from(n)
}

pub struct ChaChaAead;

/// Implements the `AeadSeal` trait for `ChaChaAead` using the `chacha20poly1305` AEAD primitive.
///
/// This implementation provides in-place authenticated encryption (`seal_in_place`)
/// and decryption (`open_in_place`) backed by the `ChaCha20Poly1305` construction.
/// Nonces are deterministically derived from a salt + sequence number pair via
/// `make_nonce`, and MUST be unique per `(key, nonce)` for security.
///
/// Security notes:
/// - Reusing a `(key, nonce)` pair catastrophically compromises confidentiality
///   and integrity. Ensure `seq` never repeats for a given `(key, salt)`.
/// - Additional Associated Data (`aad`) is integrity protected but not encrypted.
/// - The authentication tag is appended to (on seal) / expected at the end of (on open)
///   the provided `buf`.
///
/// Buffer behavior:
/// - `seal_in_place`: `buf` must initially contain the plaintext; on success it is
///   replaced with `ciphertext || tag`.
/// - `open_in_place`: `buf` must contain `ciphertext || tag`; on success it is
///   overwritten with the plaintext (truncating the tag).
///
/// Error mapping:
/// - `seal_in_place` maps any underlying failure to `AeadError::Internal`.
/// - `open_in_place` maps authentication failure (e.g., tag mismatch) to
///   `AeadError::TagMismatch`.
///
/// Parameters:
/// - `key`: AEAD key material (must be the correct length for ChaCha20-Poly1305).
/// - `salt`: Per-connection / context salt used in nonce derivation.
/// - `seq`: Monotonically increasing sequence number combined with the salt to
///   form a unique nonce.
/// - `aad`: Associated data to be authenticated (but not encrypted).
/// - `buf`: In-place input/output buffer (plaintext in, ciphertext+tag out for sealing;
///   ciphertext+tag in, plaintext out for opening).
///
/// Returns:
/// - `Ok(())` on success, after mutating `buf` in place.
/// - `Err(AeadError::Internal)` if encryption fails unexpectedly.
/// - `Err(AeadError::TagMismatch)` if decryption authentication fails.
///
/// Usage considerations:
/// - Callers should preallocate sufficient capacity in `buf` for the tag when sealing
///   (the `aead` crate’s `encrypt_in_place` handles growth, but avoiding reallocation
///   may be beneficial).
/// - Zeroing sensitive material after use (key, plaintext) is recommended if applicable.
/// - This abstraction assumes the caller enforces nonce uniqueness through `seq`.
impl AeadSeal for ChaChaAead {
    /// Encrypts `buf` in place, appends tag, returns ciphertext+tag length.
    /// This is to seal data frames, not handshake confirm tags.
    /// # Errors
    /// Returns `AeadError::Internal` if encryption fails.
    fn seal_in_place(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce = make_nonce(salt, seq);
        cipher
            .encrypt_in_place(&nonce, aad, buf)
            .map_err(|_| AeadError::Internal)
    }

    /// Decrypts `buf` in place, removes tag.
    /// This is to open data frames, not handshake confirm tags.
    /// # Errors
    /// Returns `AeadError::TagMismatch` if authentication fails.
    fn open_in_place(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce = make_nonce(salt, seq);
        cipher
            .decrypt_in_place(&nonce, aad, buf)
            .map_err(|_| AeadError::TagMismatch)
    }

    /// Produce a detached 16-byte authentication tag over **empty plaintext** with the given AAD.
    ///
    /// This is intended for handshake **confirm tags** (e.g., `FINISH_CLIENT` / `FINISH_SERVER`)
    /// where we need to authenticate the transcript via AAD without encrypting any payload.
    ///
    /// Do **not** use this for data frames—use `seal_in_place` instead.
    fn seal_detached_tag(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
    ) -> Result<[u8; 16], AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce = make_nonce(salt, seq);
        let mut empty: [u8; 0] = [];
        let tag = cipher
            .encrypt_in_place_detached(&nonce, aad, &mut empty)
            .map_err(|_| AeadError::Internal)?;
        Ok(tag.into())
    }

    /// Verify a detached 16-byte authentication tag over **empty plaintext** with the given AAD.
    ///
    /// This is the counterpart to `seal_detached_tag` and should be used when verifying
    /// handshake confirm tags. Returns `Ok(())` on success or `AeadError::TagMismatch` on failure.
    fn open_detached_tag(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AeadError> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
        let nonce = make_nonce(salt, seq);
        let mut empty: [u8; 0] = [];
        cipher
            .decrypt_in_place_detached(&nonce, aad, &mut empty, tag.into())
            .map_err(|_| AeadError::TagMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::crypto::AEAD_TAG_LEN;

    fn key() -> AeadKey {
        AeadKey([0x11; 32])
    }
    fn salt() -> NonceSalt {
        NonceSalt([
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ])
    }

    #[test]
    fn seal_open_round_trip() {
        let a = ChaChaAead;
        let mut buf = b"quicshell test payload".to_vec();
        a.seal_in_place(&key(), salt(), Seq(1), b"aad", &mut buf)
            .unwrap();
        assert!(buf.len() == b"quicshell test payload".len() + AEAD_TAG_LEN);
        a.open_in_place(&key(), salt(), Seq(1), b"aad", &mut buf)
            .unwrap();
        assert_eq!(&buf, b"quicshell test payload");
    }

    #[test]
    fn aad_mismatch_fails() {
        let a = ChaChaAead;
        let mut buf = b"data".to_vec();
        a.seal_in_place(&key(), salt(), Seq(7), b"auth", &mut buf)
            .unwrap();
        let err = a
            .open_in_place(&key(), salt(), Seq(7), b"AUTH", &mut buf)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch);
    }

    #[test]
    fn tag_corruption_detected() {
        let a = ChaChaAead;
        let mut buf = b"x".to_vec();
        a.seal_in_place(&key(), salt(), Seq(9), b"aad", &mut buf)
            .unwrap();
        // Flip a bit in the last tag byte
        *buf.last_mut().unwrap() ^= 0x80;
        let err = a
            .open_in_place(&key(), salt(), Seq(9), b"aad", &mut buf)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch);
    }

    #[test]
    fn different_nonce_changes_ciphertext() {
        let a = ChaChaAead;
        let mut p1 = b"nonce-diff".to_vec();
        let mut p2 = b"nonce-diff".to_vec();
        a.seal_in_place(&key(), salt(), Seq(10), b"aad", &mut p1)
            .unwrap();
        a.seal_in_place(&key(), salt(), Seq(11), b"aad", &mut p2)
            .unwrap();
        assert_ne!(
            p1, p2,
            "distinct sequence numbers should yield different ciphertext/tag"
        );
    }

    #[test]
    fn same_nonce_same_ciphertext() {
        // This test demonstrates that reusing the same (salt, seq) with same key + plaintext
        // produces identical ciphertext (expected for deterministic AEAD nonce construction).
        // It also implicitly warns about catastrophic nonce reuse risk.
        let a = ChaChaAead;
        let mut p1 = b"repeat".to_vec();
        let mut p2 = b"repeat".to_vec();
        a.seal_in_place(&key(), salt(), Seq(42), b"aad", &mut p1)
            .unwrap();
        a.seal_in_place(&key(), salt(), Seq(42), b"aad", &mut p2)
            .unwrap();
        assert_eq!(
            p1, p2,
            "same nonce reused -> identical ciphertext (danger in real use)"
        );
    }

    #[test]
    fn detached_tag_round_trip() {
        let a = ChaChaAead;
        let tag = a
            .seal_detached_tag(&key(), salt(), Seq(5), b"transcript-aad")
            .expect("seal tag");
        a.open_detached_tag(&key(), salt(), Seq(5), b"transcript-aad", &tag)
            .expect("open tag");
    }

    #[test]
    fn detached_tag_aad_mismatch_fails() {
        let a = ChaChaAead;
        let tag = a
            .seal_detached_tag(&key(), salt(), Seq(6), b"aad-one")
            .expect("seal tag");
        let err = a
            .open_detached_tag(&key(), salt(), Seq(6), b"aad-two", &tag)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch);
    }

    #[test]
    fn detached_tag_changes_with_nonce() {
        let a = ChaChaAead;
        let t1 = a
            .seal_detached_tag(&key(), salt(), Seq(100), b"aad")
            .expect("t1");
        let t2 = a
            .seal_detached_tag(&key(), salt(), Seq(101), b"aad")
            .expect("t2");
        assert_ne!(
            t1, t2,
            "different sequence numbers must yield different tags"
        );
    }
}
