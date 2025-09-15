// src/ports/crypto.rs
use zeroize::Zeroize;

/// Length of the authentication tag in bytes.
pub const AEAD_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Zeroize, PartialEq, Eq)]
#[zeroize(drop)]
pub struct AeadKey(pub [u8; 32]); // ChaCha20-Poly1305 key size

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceSalt(pub [u8; 16]); // XChaCha: 16B salt + 8B seq = 24B nonce

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seq(pub u64); // per-direction counter

/// Trait for in-place Authenticated Encryption with Associated Data (AEAD).
///
/// An implementor of `AeadSeal` provides symmetric encryption and decryption
/// primitives that:
/// - Use a caller-supplied key plus a (salt, sequence) pair to derive a unique nonce
/// - Authenticate both the ciphertext and caller-provided Additional Authenticated Data (AAD)
/// - Operate in-place on a growable `Vec<u8>`
///
/// Nonce construction:
/// The (`salt`, `seq`) pair MUST be unique per key for every call to `seal_in_place`.
/// Reuse (same key + salt + sequence) catastrophically compromises confidentiality
/// and integrity. Callers are responsible for enforcing uniqueness.
///
/// In-place semantics:
/// - Encryption: the buffer initially contains plaintext; after success it contains
///   ciphertext followed by the authentication tag (length grows by tag size).
/// - Decryption: the buffer initially contains ciphertext concatenated with the tag;
///   after success it is truncated back to the original plaintext length.
///
/// On error during decryption the buffer contents MUST be considered untrustworthy
/// and MUST NOT be used.
///
/// All failures return `AeadError`, never leaking secret-dependent information.
/// Timing behavior should be constant-time with respect to secret data (key,
/// plaintext, tag), aside from unavoidable data movement.
///
/// Thread safety:
/// Implementations may or may not be `Sync` / `Send`; this trait does not impose
/// thread-safety guarantees itself.
///
/// Error handling:
/// - `AeadError` typically indicates authentication failure, nonce misuse,
///   or an internal cryptographic error.
/// - Callers MUST treat any `Err` from `open_in_place` as a fatal authentication failure
///   for the associated data unit.
///
/// Security recommendations:
/// - Zeroize or otherwise securely handle `key` material outside these calls.
/// - Avoid exposing whether a failure was due to tag mismatch versus other causes.
/// - Do not log raw key, nonce, tag, or plaintext/ciphertext material.
///
/// Implementations SHOULD document:
/// - Tag length
/// - Supported key sizes
/// - Nonce derivation scheme from (`salt`, `seq`)
/// - Any limits on the maximum plaintext length
///
/// Example (conceptual):
/// ```ignore
/// let mut buf = plaintext.to_vec();
/// aead_impl.seal_in_place(&key, salt, packet_number, aad, &mut buf)?;
/// // buf now = ciphertext || tag
/// aead_impl.open_in_place(&key, salt, packet_number, aad, &mut buf)?;
/// // buf now restored to plaintext
/// ```
pub trait AeadSeal {
    /// Encrypts `buf` in place, appends tag, returns ciphertext+tag length.
    /// # Errors
    /// Returns `AeadError::Internal` if encryption fails.
    fn seal_in_place(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError>;

    /// Decrypts `buf` in place, removes tag.
    /// # Errors
    /// Returns `AeadError::TagMismatch` if authentication fails.
    fn open_in_place(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError>;

    /// Produce a detached authentication tag over **empty plaintext** with the given AAD.
    ///
    /// This is intended for handshake **confirm tags** (FINISH_*), where we authenticate
    /// the transcript via AAD without encrypting any payload.
    ///
    /// Do **not** use this for data frames — use `seal_in_place` instead.
    /// # Errors
    /// Returns `AeadError::Internal` if encryption fails.
    fn seal_detached_tag(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
    ) -> Result<[u8; AEAD_TAG_LEN], AeadError>;

    /// Verify a detached authentication tag over **empty plaintext** with the given AAD.
    ///
    /// Counterpart to `seal_detached_tag` for handshake confirm verification.
    /// Returns `Ok(())` on success or `AeadError::TagMismatch` on failure.
    /// # Errors
    /// Returns `AeadError::TagMismatch` if authentication fails.
    fn open_detached_tag(
        &self,
        key: &AeadKey,
        salt: NonceSalt,
        seq: Seq,
        aad: &[u8],
        tag: &[u8; AEAD_TAG_LEN],
    ) -> Result<(), AeadError>;
}

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("decryption failed (tag mismatch)")]
    TagMismatch,
    #[error("internal crypto error")]
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy AEAD that performs a reversible XOR with seq low byte and appends/removes a fixed tag.
    /// This is purely for exercising the trait flow; NOT secure.
    struct DummyAead;

    impl AeadSeal for DummyAead {
        fn seal_in_place(
            &self,
            _key: &AeadKey,
            salt: NonceSalt,
            seq: Seq,
            aad: &[u8],
            buf: &mut Vec<u8>,
        ) -> Result<(), AeadError> {
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            // XOR transform (toy)
            let k = seq.0 as u8 ^ salt.0[0];
            for b in buf.iter_mut() {
                *b ^= k;
            }
            // append deterministic tag = first 16 bytes of repeating k
            buf.extend(std::iter::repeat(k).take(AEAD_TAG_LEN));
            Ok(())
        }
        fn open_in_place(
            &self,
            _key: &AeadKey,
            salt: NonceSalt,
            seq: Seq,
            aad: &[u8],
            buf: &mut Vec<u8>,
        ) -> Result<(), AeadError> {
            if buf.len() < AEAD_TAG_LEN {
                return Err(AeadError::TagMismatch);
            }
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            let k = seq.0 as u8 ^ salt.0[0];
            let (ct, tag) = buf.split_at(buf.len() - AEAD_TAG_LEN);
            if !tag.iter().all(|t| *t == k) {
                return Err(AeadError::TagMismatch);
            }
            // restore plaintext
            let mut plain = ct.to_vec();
            for b in plain.iter_mut() {
                *b ^= k;
            }
            buf.truncate(ct.len());
            buf.copy_from_slice(&plain);
            Ok(())
        }

        fn seal_detached_tag(
            &self,
            _key: &AeadKey,
            salt: NonceSalt,
            seq: Seq,
            aad: &[u8],
        ) -> Result<[u8; AEAD_TAG_LEN], AeadError> {
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            let mut ah: u8 = 0;
            for b in aad {
                ah = ah.wrapping_add(*b);
            }
            let k = seq.0 as u8 ^ salt.0[0] ^ ah;
            let mut tag = [0u8; AEAD_TAG_LEN];
            tag.fill(k);
            Ok(tag)
        }

        fn open_detached_tag(
            &self,
            _key: &AeadKey,
            salt: NonceSalt,
            seq: Seq,
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> Result<(), AeadError> {
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            let mut ah: u8 = 0;
            for b in aad {
                ah = ah.wrapping_add(*b);
            }
            let k = seq.0 as u8 ^ salt.0[0] ^ ah;
            if tag.iter().all(|t| *t == k) {
                Ok(())
            } else {
                Err(AeadError::TagMismatch)
            }
        }
    }

    #[test]
    fn seal_and_open_round_trip() {
        let a = DummyAead;
        let key = AeadKey([7u8; 32]);
        let salt = NonceSalt([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let seq = Seq(5);
        let aad = b"hdr";
        let mut data = b"hello world".to_vec();
        a.seal_in_place(&key, salt, seq, aad, &mut data).unwrap();
        assert!(data.len() == "hello world".len() + AEAD_TAG_LEN);
        a.open_in_place(&key, salt, seq, aad, &mut data).unwrap();
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn open_rejects_modified_tag() {
        let a = DummyAead;
        let key = AeadKey([0u8; 32]);
        let salt = NonceSalt([9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let seq = Seq(1);
        let aad = b"aad";
        let mut data = b"abc".to_vec();
        a.seal_in_place(&key, salt, seq, aad, &mut data).unwrap();
        // corrupt last tag byte
        *data.last_mut().unwrap() ^= 0xFF;
        let err = a
            .open_in_place(&key, salt, seq, aad, &mut data)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch);
    }

    #[test]
    fn seal_errors_on_empty_aad() {
        let a = DummyAead;
        let key = AeadKey([0u8; 32]);
        let salt = NonceSalt([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let seq = Seq(0);
        let mut data = vec![1, 2, 3];
        let err = a
            .seal_in_place(&key, salt, seq, b"", &mut data)
            .unwrap_err();
        matches!(err, AeadError::Internal);
    }

    #[test]
    fn open_errors_on_short_buffer() {
        let a = DummyAead;
        let key = AeadKey([0u8; 32]);
        let salt = NonceSalt([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let seq = Seq(0);
        let mut data = vec![1, 2, 3]; // shorter than tag length
        let err = a
            .open_in_place(&key, salt, seq, b"x", &mut data)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch);
    }

    #[test]
    fn detached_tag_round_trip() {
        let a = DummyAead;
        let key = AeadKey([7u8; 32]);
        let salt = NonceSalt([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let seq = Seq(42);
        let aad = b"transcript-aad";
        let tag = a.seal_detached_tag(&key, salt, seq, aad).expect("seal tag");
        a.open_detached_tag(&key, salt, seq, aad, &tag)
            .expect("open tag");
    }

    #[test]
    fn detached_tag_aad_mismatch_fails() {
        let a = DummyAead;
        let key = AeadKey([7u8; 32]);
        let salt = NonceSalt([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let seq = Seq(7);
        let tag = a
            .seal_detached_tag(&key, salt, seq, b"A")
            .expect("seal tag");
        let err = a
            .open_detached_tag(&key, salt, seq, b"B", &tag)
            .unwrap_err();
        matches!(err, AeadError::TagMismatch | AeadError::Internal);
    }
}
