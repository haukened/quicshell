/*
`Control` channel frame type definitions for `qsh` v1 (spec §6.* planned).

This module defines CONTROL channel (channel id 0) frames that coordinate
cryptographic maintenance and future session management operations. All
frames here are CBOR-serializable, deterministic, and carry only public or
non‑secret metadata. They MUST NOT embed key material; rekey operations use
existing per‑channel root secrets expanded via the KDF labels defined in the
spec.

Initial frames implemented:
* `REKEY_REQ` – Initiates a per‑channel, per‑direction rekey after soft or
  hard nonce thresholds. Proposes the next epoch number for the SENDER->RECEIVER
  direction indicated.
* `REKEY_ACK` – Acknowledges a received `REKEY_REQ` and authorizes both peers
  to cut over to the derived epoch keys at the sequence boundary.

Design notes:
* CONTROL channel id is always 0; higher layers MUST route by id before decoding.
* Epoch numbers start at 0 (initial keys) and increment by 1. Gaps are invalid.
* Rekey is direction-specific; each logical direction managed independently to
  minimize blast radius if a single key is compromised.
* Padding (`pad`) is excluded from transcript hashes (consistent with handshake);
  it is optional and may be used for length hiding. Implementations SHOULD strip
  it before logging.

Validation rules enforced here:
* `next_epoch` MUST equal current_epoch + 1 supplied by caller during construction.
  (Enforced by constructor helpers, not by decoding – decoding is kept fallible
  but minimal; semantic validation belongs to higher orchestration layer.)
* `direction` is an enum; unknown discriminants fail CBOR decode.

Future extensions (placeholders not yet implemented):
* WINDOW_UPDATE, TERM_RESIZE, FLOW_CONTROL, CHANNEL_CLOSE, OPEN.
*/

use aead::rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Maximum padding length permitted for control frames (tunable; spec TBD).
///
/// Chosen conservatively to balance memory usage and length-hiding utility.
/// Adjust alongside spec evolution; keep small enough to avoid `DoS` via large
/// allocations while still enabling coarse traffic morphing.
pub const MAX_PAD_LEN: usize = 4096;

/// Direction of traffic for which a rekey is being negotiated.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RekeyDirection {
    /// Client to Server direction (client encrypts / server decrypts)
    C2s,
    /// Server to Client direction (server encrypts / client decrypts)
    S2c,
}

/// Control frame initiating a per‑direction channel rekey.
///
/// The sender proposes transitioning from `current_epoch` to `next_epoch`.
/// The receiver MUST verify `next_epoch == current_epoch + 1` and respond with
/// a matching [`RekeyAck`] if acceptable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyReq {
    /// Traffic direction this request covers.
    pub direction: RekeyDirection,
    /// Epoch the sender currently uses for this direction.
    pub current_epoch: u64,
    /// Proposed next epoch (should be `current_epoch` + 1).
    pub next_epoch: u64,
    /// Optional opaque padding excluded from any transcript digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pad: Vec<u8>,
}

impl RekeyReq {
    /// Construct a new `RekeyReq` ensuring monotonic epoch increment.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::EpochNotNext`] if `next_epoch != current_epoch + 1`.
    pub fn new(
        direction: RekeyDirection,
        current_epoch: u64,
        next_epoch: u64,
    ) -> Result<Self, RekeyFrameError> {
        if next_epoch != current_epoch + 1 {
            return Err(RekeyFrameError::EpochNotNext {
                current: current_epoch,
                proposed: next_epoch,
            });
        }
        Ok(Self {
            direction,
            current_epoch,
            next_epoch,
            pad: Vec::new(),
        })
    }
}

/// Control frame acknowledging a [`RekeyReq`] and authorizing cutover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyAck {
    /// Direction acknowledged.
    pub direction: RekeyDirection,
    /// Epoch prior to cutover (must match request `current_epoch`).
    pub current_epoch: u64,
    /// Epoch authorized for activation (must match request `next_epoch`).
    pub next_epoch: u64,
    /// Optional opaque padding excluded from any transcript digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pad: Vec<u8>,
}

impl RekeyAck {
    /// Construct new `RekeyAck` ensuring it acknowledges the expected transition.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::EpochNotNext`] if `next_epoch != current_epoch + 1`.
    pub fn new(
        direction: RekeyDirection,
        current_epoch: u64,
        next_epoch: u64,
    ) -> Result<Self, RekeyFrameError> {
        if next_epoch != current_epoch + 1 {
            return Err(RekeyFrameError::EpochNotNext {
                current: current_epoch,
                proposed: next_epoch,
            });
        }
        Ok(Self {
            direction,
            current_epoch,
            next_epoch,
            pad: Vec::new(),
        })
    }
}

/// Errors emitted during semantic construction of rekey control frames.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RekeyFrameError {
    /// Proposed epoch does not immediately follow current.
    #[error("proposed epoch {proposed} not equal to current {current} + 1")]
    EpochNotNext { current: u64, proposed: u64 },
    /// Supplied padding exceeds `MAX_PAD_LEN`.
    #[error("padding length {len} exceeds max {max}")]
    PadTooLarge { len: usize, max: usize },
}

impl RekeyReq {
    /// Replace existing padding with provided bytes after length validation.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::PadTooLarge`] if `pad.len() > MAX_PAD_LEN`.
    pub fn set_padding(&mut self, pad: Vec<u8>) -> Result<&mut Self, RekeyFrameError> {
        if pad.len() > MAX_PAD_LEN {
            return Err(RekeyFrameError::PadTooLarge {
                len: pad.len(),
                max: MAX_PAD_LEN,
            });
        }
        self.pad = pad;
        Ok(self)
    }

    /// Clear any existing padding.
    pub fn clear_padding(&mut self) {
        self.pad.clear();
    }

    /// Fill padding with `len` random bytes (uniform) using supplied CSPRNG.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::PadTooLarge`] if `len > MAX_PAD_LEN`.
    pub fn random_padding<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        len: usize,
    ) -> Result<&mut Self, RekeyFrameError> {
        if len > MAX_PAD_LEN {
            return Err(RekeyFrameError::PadTooLarge {
                len,
                max: MAX_PAD_LEN,
            });
        }
        self.pad.resize(len, 0u8);
        rng.fill_bytes(&mut self.pad);
        Ok(self)
    }
}

impl RekeyAck {
    /// Replace existing padding with provided bytes after length validation.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::PadTooLarge`] if `pad.len() > MAX_PAD_LEN`.
    pub fn set_padding(&mut self, pad: Vec<u8>) -> Result<&mut Self, RekeyFrameError> {
        if pad.len() > MAX_PAD_LEN {
            return Err(RekeyFrameError::PadTooLarge {
                len: pad.len(),
                max: MAX_PAD_LEN,
            });
        }
        self.pad = pad;
        Ok(self)
    }

    /// Clear any existing padding.
    pub fn clear_padding(&mut self) {
        self.pad.clear();
    }

    /// Fill padding with `len` random bytes (uniform) using supplied CSPRNG.
    ///
    /// # Errors
    /// * Returns [`RekeyFrameError::PadTooLarge`] if `len > MAX_PAD_LEN`.
    pub fn random_padding<R: CryptoRng + RngCore>(
        &mut self,
        rng: &mut R,
        len: usize,
    ) -> Result<&mut Self, RekeyFrameError> {
        if len > MAX_PAD_LEN {
            return Err(RekeyFrameError::PadTooLarge {
                len,
                max: MAX_PAD_LEN,
            });
        }
        self.pad.resize(len, 0u8);
        rng.fill_bytes(&mut self.pad);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aead::rand_core::OsRng;
    #[test]
    fn rekey_req_new_ok() {
        let r = RekeyReq::new(RekeyDirection::C2s, 0, 1).unwrap();
        assert_eq!(r.current_epoch, 0);
        assert_eq!(r.next_epoch, 1);
    }

    #[test]
    fn rekey_req_new_err() {
        let e = RekeyReq::new(RekeyDirection::S2c, 1, 3).unwrap_err();
        assert!(matches!(e, RekeyFrameError::EpochNotNext { .. }));
    }

    #[test]
    fn rekey_ack_new_ok() {
        let a = RekeyAck::new(RekeyDirection::S2c, 5, 6).unwrap();
        assert_eq!(a.current_epoch, 5);
        assert_eq!(a.next_epoch, 6);
    }

    #[test]
    fn rekey_ack_new_err() {
        let e = RekeyAck::new(RekeyDirection::C2s, 2, 4).unwrap_err();
        assert!(matches!(e, RekeyFrameError::EpochNotNext { .. }));
    }

    #[test]
    fn serde_round_trip_req() {
        let r = RekeyReq::new(RekeyDirection::C2s, 7, 8).unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&r, &mut buf).unwrap();
        let de: RekeyReq = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(r, de);
    }

    #[test]
    fn serde_round_trip_ack() {
        let a = RekeyAck::new(RekeyDirection::S2c, 9, 10).unwrap();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&a, &mut buf).unwrap();
        let de: RekeyAck = ciborium::de::from_reader(buf.as_slice()).unwrap();
        assert_eq!(a, de);
    }

    #[test]
    fn padding_set_and_clear_req() {
        let mut r = RekeyReq::new(RekeyDirection::C2s, 3, 4).unwrap();
        r.set_padding(vec![1u8; 16]).unwrap();
        assert_eq!(r.pad.len(), 16);
        r.clear_padding();
        assert!(r.pad.is_empty());
    }

    #[test]
    fn padding_random_ack() {
        let mut a = RekeyAck::new(RekeyDirection::S2c, 4, 5).unwrap();
        a.random_padding(&mut OsRng, 32).unwrap();
        assert_eq!(a.pad.len(), 32);
    }

    #[test]
    fn padding_too_large() {
        let mut r = RekeyReq::new(RekeyDirection::C2s, 10, 11).unwrap();
        let big = vec![0u8; MAX_PAD_LEN + 1];
        let e = r.set_padding(big).unwrap_err();
        assert!(matches!(e, RekeyFrameError::PadTooLarge { .. }));
    }

    #[test]
    fn padding_too_large_ack() {
        let mut a = RekeyAck::new(RekeyDirection::S2c, 1, 2).unwrap();
        let big = vec![0u8; MAX_PAD_LEN + 1];
        let e = a.set_padding(big).unwrap_err();
        assert!(matches!(e, RekeyFrameError::PadTooLarge { .. }));
    }

    #[test]
    fn random_padding_too_large_req() {
        let mut r = RekeyReq::new(RekeyDirection::C2s, 2, 3).unwrap();
        let err = r.random_padding(&mut OsRng, MAX_PAD_LEN + 1).unwrap_err();
        assert!(matches!(err, RekeyFrameError::PadTooLarge { .. }));
    }

    #[test]
    fn random_padding_too_large_ack() {
        let mut a = RekeyAck::new(RekeyDirection::S2c, 3, 4).unwrap();
        let err = a.random_padding(&mut OsRng, MAX_PAD_LEN + 1).unwrap_err();
        assert!(matches!(err, RekeyFrameError::PadTooLarge { .. }));
    }

    #[test]
    fn clear_padding_ack() {
        let mut a = RekeyAck::new(RekeyDirection::S2c, 5, 6).unwrap();
        a.set_padding(vec![7u8; 8]).unwrap();
        assert_eq!(a.pad.len(), 8);
        a.clear_padding();
        assert!(a.pad.is_empty());
    }

    #[test]
    fn empty_pad_omitted_in_cbor() {
        let a = RekeyAck::new(RekeyDirection::C2s, 7, 8).unwrap();
        let mut buf_empty = Vec::new();
        ciborium::ser::into_writer(&a, &mut buf_empty).unwrap();
        let mut a_padded = a.clone();
        a_padded.set_padding(vec![0xAA; 16]).unwrap();
        let mut buf_padded = Vec::new();
        ciborium::ser::into_writer(&a_padded, &mut buf_padded).unwrap();
        assert!(buf_padded.len() > buf_empty.len());
        let decoded: RekeyAck = ciborium::de::from_reader(buf_empty.as_slice()).unwrap();
        assert!(decoded.pad.is_empty());
    }
}
