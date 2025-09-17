use crate::core::crypto::DirectionalNonceM;
use crate::ports::crypto::{AeadError, AeadKey, AeadSeal, NonceSalt, Seq};
use crate::ports::nonce_manager::{
    DirectionalNonceManager, NonceAdvance, NonceManagerConfig, NonceSeqError, NonceState,
};
use zeroize::Zeroize;

/// Outcome of a successful seal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealOutcome {
    /// Sequence number used (directional, value before increment inside nonce manager)
    pub seq: u64,
    /// Hint: size-based soft rekey threshold crossed
    pub soft_rekey_hint: bool,
    /// Hint: time-based soft rekey threshold crossed
    pub time_rekey_hint: bool,
}

/// Errors surfaced by `ChannelCrypto` operations.
#[derive(Debug, thiserror::Error)]
pub enum ChannelCryptoError {
    #[error("aead error: {0}")]
    Aead(#[from] AeadError),
    #[error("nonce sequence error: {0}")]
    Nonce(#[from] NonceSeqError),
    #[error("replay or non-monotonic sequence (expected {expected}, got {got})")]
    Replay { expected: u64, got: u64 },
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct DirectionalKeys {
    tx_key: AeadKey,
    rx_key: AeadKey,
}

/// Bidirectional per-channel cryptographic context (epoch 0 only).
///
/// Maintains independent directional AEAD keys and nonce management.
/// Enforces strict in-order sequence numbers on receive.
pub struct ChannelCrypto<A: AeadSeal> {
    aead: A,
    keys: DirectionalKeys,
    tx_nonce: DirectionalNonceM,
    rx_salt: NonceSalt,
    rx_last_seq: Option<u64>,
}

impl<A: AeadSeal> ChannelCrypto<A> {
    /// Create a new epoch-0 channel crypto context.
    ///
    /// * `aead` - AEAD implementation
    /// * `tx_key` - directional key for outbound (this side -> peer)
    /// * `tx_salt` - initial nonce salt for outbound direction
    /// * `rx_key` - directional key for inbound (peer -> this side)
    /// * `rx_salt` - initial nonce salt for inbound direction
    /// * `cfg` - nonce manager configuration (soft/hard thresholds)
    #[allow(clippy::too_many_arguments)]
    pub fn new_epoch0(
        aead: A,
        tx_key: AeadKey,
        tx_salt: NonceSalt,
        rx_key: AeadKey,
        rx_salt: NonceSalt,
        cfg: NonceManagerConfig,
    ) -> Self {
        Self {
            aead,
            keys: DirectionalKeys { tx_key, rx_key },
            tx_nonce: DirectionalNonceM::new(tx_salt, 0, cfg),
            rx_salt,
            rx_last_seq: None,
        }
    }

    /// Seal (encrypt) a payload buffer in place using next outbound sequence.
    ///
    /// On success buffer becomes `ciphertext || tag`. Returns seal outcome with hints.
    ///
    /// # Errors
    /// * Propagates underlying AEAD errors (`ChannelCryptoError::Aead`).
    /// * Returns `ChannelCryptoError::Nonce` if nonce manager signals rekey / exhaustion.
    pub fn seal(
        &mut self,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<SealOutcome, ChannelCryptoError> {
        let NonceAdvance {
            salt,
            seq,
            soft_rekey_hint,
            time_rekey_hint,
        } = self.tx_nonce.next(buf.len())?;
        self.aead
            .seal_in_place(&self.keys.tx_key, salt, seq, aad, buf)?;
        Ok(SealOutcome {
            seq: seq.0,
            soft_rekey_hint,
            time_rekey_hint,
        })
    }

    /// Open (decrypt) a payload buffer in place with the provided sequence.
    ///
    /// Enforces strict monotonic sequence (expected = `last_seq` + 1 or 0 if first).
    ///
    /// # Errors
    /// * `ChannelCryptoError::Replay` if sequence not the expected monotonic value.
    /// * Propagates underlying AEAD open errors or nonce sequencing errors.
    pub fn open(
        &mut self,
        seq: u64,
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), ChannelCryptoError> {
        let expected = self.rx_last_seq.map_or(0, |s| s + 1);
        if seq != expected {
            return Err(ChannelCryptoError::Replay { expected, got: seq });
        }
        self.aead
            .open_in_place(&self.keys.rx_key, self.rx_salt, Seq(seq), aad, buf)?;
        self.rx_last_seq = Some(seq);
        Ok(())
    }

    /// Snapshot of transmit nonce state.
    pub fn tx_state(&self) -> NonceState {
        self.tx_nonce.state()
    }

    /// Last received sequence (if any).
    pub fn rx_last_seq(&self) -> Option<u64> {
        self.rx_last_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::crypto::{AEAD_TAG_LEN, AeadError, AeadKey, AeadSeal, NonceSalt, Seq};
    use crate::ports::nonce_manager::NonceManagerConfig;

    // Minimal dummy AEAD (duplicated logic avoided; inline simple reversible op)
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
            let k = salt.0[0] ^ (seq.0 as u8);
            for b in buf.iter_mut() {
                *b ^= k;
            }
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
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            if buf.len() < AEAD_TAG_LEN {
                return Err(AeadError::TagMismatch);
            }
            let k = salt.0[0] ^ (seq.0 as u8);
            let (ct, tag) = buf.split_at(buf.len() - AEAD_TAG_LEN);
            if !tag.iter().all(|t| *t == k) {
                return Err(AeadError::TagMismatch);
            }
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
            _salt: NonceSalt,
            _seq: Seq,
            aad: &[u8],
        ) -> Result<[u8; AEAD_TAG_LEN], AeadError> {
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            Ok([0u8; AEAD_TAG_LEN])
        }
        fn open_detached_tag(
            &self,
            _key: &AeadKey,
            _salt: NonceSalt,
            _seq: Seq,
            aad: &[u8],
            tag: &[u8; AEAD_TAG_LEN],
        ) -> Result<(), AeadError> {
            if aad.is_empty() {
                return Err(AeadError::Internal);
            }
            if tag.iter().any(|b| *b != 0) {
                return Err(AeadError::TagMismatch);
            }
            Ok(())
        }
    }

    fn key(val: u8) -> AeadKey {
        AeadKey([val; 32])
    }
    fn salt(val: u8) -> NonceSalt {
        NonceSalt([val; 16])
    }

    #[test]
    fn seal_open_round_trip() {
        // Use identical salt for tx/rx because DummyAead derives XOR from salt[0]^seq.
        let s = salt(9);
        let mut cc = ChannelCrypto::new_epoch0(
            DummyAead,
            key(1),
            s,
            key(2),
            s,
            NonceManagerConfig::default(),
        );
        let mut buf = b"hello".to_vec();
        let out = cc.seal(b"aad", &mut buf).unwrap();
        assert_eq!(out.seq, 0);
        assert_eq!(cc.tx_state().counter, 1);
        cc.open(0, b"aad", &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn monotonic_sequences_enforced() {
        let s = salt(4);
        let mut cc = ChannelCrypto::new_epoch0(
            DummyAead,
            key(3),
            s,
            key(5),
            s,
            NonceManagerConfig::default(),
        );
        let mut buf = b"x".to_vec();
        cc.seal(b"hdr", &mut buf).unwrap();
        // replay attempt
        let err = cc.open(1, b"hdr", &mut buf).unwrap_err();
        assert!(matches!(err, ChannelCryptoError::Replay { .. }));
    }

    #[test]
    fn soft_hint_propagates() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 4;
        cfg.hard_bytes = 64;
        let s = salt(1);
        let mut cc = ChannelCrypto::new_epoch0(DummyAead, key(9), s, key(8), s, cfg);
        let mut total_hint = 0;
        for _ in 0..5 {
            let mut buf = b"ab".to_vec();
            if cc.seal(b"x", &mut buf).unwrap().soft_rekey_hint {
                total_hint += 1;
            }
        }
        assert_eq!(total_hint, 1);
    }

    #[test]
    fn hard_limit_maps_to_error() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 2;
        cfg.hard_bytes = 3; // allow one frame then block on third attempt
        let s = salt(1);
        let mut cc = ChannelCrypto::new_epoch0(DummyAead, key(1), s, key(2), s, cfg);
        let mut b1 = b"aa".to_vec();
        cc.seal(b"z", &mut b1).unwrap();
        let mut b2 = b"a".to_vec();
        let _ = cc.seal(b"z", &mut b2).unwrap();
        let mut b3 = b"a".to_vec();
        let err = cc.seal(b"z", &mut b3).unwrap_err();
        assert!(matches!(
            err,
            ChannelCryptoError::Nonce(NonceSeqError::RekeyRequired)
        ));
    }
}
