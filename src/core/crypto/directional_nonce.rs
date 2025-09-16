//! Directional AEAD nonce manager implementation.
//!
//! Implements `DirectionalNonceManager` port. Maintains per-direction counter,
//! byte accounting, and soft/hard rekey thresholds. Does *not* perform HKDF;
//! caller supplies new `NonceSalt` on rekey.

use crate::ports::crypto::{NonceSalt, Seq};
use crate::ports::nonce_manager::{
    DirectionalNonceManager, NonceAdvance, NonceManagerConfig, NonceSeqError, NonceState,
};
use core::time::Duration;
use std::time::Instant;

/// Directional AEAD nonce manager (production type, real time via `Instant::now()`).
///
/// Responsibilities:
/// - Maintains a strictly monotonic per-direction sequence (`seq`).
/// - Tracks bytes sealed since last rekey to emit policy hints and enforce a hard limit.
/// - Surfaces two independent soft rekey hints: size threshold and elapsed time threshold.
/// - Enforces a hard byte ceiling (`hard_bytes`) beyond which sealing MUST stop until a rekey.
///
/// Hint semantics:
/// - `soft_rekey_hint` (size): Fires **once per epoch** the first time cumulative bytes reach or
///   exceed `soft_bytes`. After a successful rekey (via `install_rekey`) it may fire again.
/// - `time_rekey_hint` (time): Becomes `true` once elapsed wall time since the epoch start reaches
///   or exceeds `soft_time` and remains `true` on all subsequent calls in that epoch (persistence is
///   intentional; higher layers can poll lazily without missing the transition point).
///
/// Hard limit semantics:
/// - A call to `next(bytes)` returns `RekeyRequired` if `bytes_since_rekey >= hard_bytes` *before*
///   allocating the new sequence (pre-check). This guarantees the last successful frame never
///   crosses the policy boundary.
/// - Exactly hitting the boundary (`bytes_since_rekey == hard_bytes`) is permitted for the last
///   successful frame; the subsequent call (even with `bytes=0`) returns `RekeyRequired`.
///
/// Counter exhaustion:
/// - If the internal 64-bit counter reaches `u64::MAX`, `Exhausted` is returned. Proper rekeying
///   should rotate epochs long before this point (practically unreachable in normal operation).
///
/// Invariants (debug asserted):
/// - `soft_bytes <= hard_bytes`.
/// - A single frame size (as reported to `next`) must never exceed `hard_bytes`.
///
/// Concurrency:
/// - This type is **not** thread-safe; it assumes exclusive mutable access on the send path.
///   If future multi-threaded sending is introduced, wrap in a synchronization primitive or refactor
///   to an atomic design.
///
/// Security notes:
/// - Monotonic `(salt, seq)` pairs prevent nonce reuse under the same key material.
/// - Rekey logic (salt/key derivation) is executed externally; this manager only resets state when
///   `install_rekey` is invoked with fresh material.
///
/// Related design record: ADR-0009 (per-channel, per-direction rekeying).
pub struct DirectionalNonceM {
    salt: NonceSalt,
    epoch: u64,
    counter: u64,
    bytes_since_rekey: u64,
    first_instant: Instant,
    cfg: NonceManagerConfig,
    soft_rekey_signalled: bool,
    #[cfg(test)]
    test_clock: Option<TestClockHandle>,
}

impl DirectionalNonceM {
    /// Create a new manager with an initial salt and epoch.
    ///
    /// Initializes sequence and byte counters to zero and captures the starting wall clock instant.
    ///
    /// Invariants:
    /// - `cfg.soft_bytes <= cfg.hard_bytes` (debug asserted).
    /// - `soft_rekey_signalled` starts `false`.
    ///
    /// The time-based hint will remain `false` until elapsed time >= `cfg.soft_time`.
    ///
    /// # Parameters
    /// - `initial_salt`: Fresh 16-byte salt for AEAD nonce prefix.
    /// - `epoch`: Caller-assigned epoch number (monotonic per rekey).
    /// - `cfg`: Policy thresholds for soft/time/hard rekey signaling.
    ///
    /// # Returns
    /// New `DirectionalNonceM` ready for use.
    #[must_use]
    pub fn new(initial_salt: NonceSalt, epoch: u64, cfg: NonceManagerConfig) -> Self {
        debug_assert!(
            cfg.soft_bytes <= cfg.hard_bytes,
            "soft_bytes must not exceed hard_bytes"
        );
        Self {
            salt: initial_salt,
            epoch,
            counter: 0,
            bytes_since_rekey: 0,
            first_instant: Instant::now(),
            cfg,
            soft_rekey_signalled: false,
            #[cfg(test)]
            test_clock: None,
        }
    }

    #[cfg(test)]
    fn with_test_clock(
        initial_salt: NonceSalt,
        epoch: u64,
        cfg: NonceManagerConfig,
        handle: TestClockHandle,
    ) -> Self {
        let now = handle.now();
        Self {
            salt: initial_salt,
            epoch,
            counter: 0,
            bytes_since_rekey: 0,
            first_instant: now,
            cfg,
            soft_rekey_signalled: false,
            test_clock: Some(handle),
        }
    }
    fn elapsed(&self) -> Duration {
        #[cfg(test)]
        {
            if let Some(ref h) = self.test_clock {
                return h.now().saturating_duration_since(self.first_instant);
            }
        }
        Instant::now().saturating_duration_since(self.first_instant)
    }

    #[cfg(test)]
    fn set_counter_for_test(&mut self, v: u64) {
        self.counter = v;
    }
}

impl DirectionalNonceManager for DirectionalNonceM {
    fn next(&mut self, bytes_about_to_seal: usize) -> Result<NonceAdvance, NonceSeqError> {
        debug_assert!(
            bytes_about_to_seal as u64 <= self.cfg.hard_bytes,
            "single frame exceeds hard byte policy"
        );
        // Hard byte limit enforcement BEFORE increment
        if self.bytes_since_rekey >= self.cfg.hard_bytes {
            return Err(NonceSeqError::RekeyRequired);
        }
        // Counter exhaustion check
        if self.counter == u64::MAX {
            return Err(NonceSeqError::Exhausted);
        }

        let seq = Seq(self.counter); // use current value for this frame
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(NonceSeqError::Exhausted)?;
        self.bytes_since_rekey = self
            .bytes_since_rekey
            .saturating_add(bytes_about_to_seal as u64);

        let elapsed = self.elapsed();

        // Soft hints
        let soft_size = !self.soft_rekey_signalled && self.bytes_since_rekey >= self.cfg.soft_bytes;
        let soft_time = elapsed >= self.cfg.soft_time;
        if soft_size {
            self.soft_rekey_signalled = true;
        }

        // Hard post-allocation enforcement (if we crossed exactly now)
        if self.bytes_since_rekey > self.cfg.hard_bytes {
            return Err(NonceSeqError::RekeyRequired);
        }

        Ok(NonceAdvance {
            salt: self.salt,
            seq,
            soft_rekey_hint: soft_size,
            time_rekey_hint: soft_time,
        })
    }

    /// Install freshly derived salt (and implicitly a new AEAD key outside this type) and advance the epoch.
    ///
    /// Resets sequence counter, byte accounting, hint flags, and time origin. Intended to be called
    /// immediately after higher-layer rekey derivation completes.
    ///
    /// # Parameters
    /// - `new_salt`: New nonce salt (must never repeat with prior epochs for the same direction).
    /// - `new_epoch`: Monotonically increasing epoch identifier.
    ///
    /// # Panics
    /// Never panics; debug asserts enforce configuration invariants.
    fn install_rekey(&mut self, new_salt: NonceSalt, new_epoch: u64) {
        debug_assert!(
            self.cfg.soft_bytes <= self.cfg.hard_bytes,
            "soft_bytes must not exceed hard_bytes"
        );
        debug_assert!(
            new_epoch > self.epoch,
            "epoch must strictly increase (old: {}, new: {})",
            self.epoch,
            new_epoch
        );
        debug_assert!(
            new_salt != self.salt,
            "nonce salt must change between epochs"
        );
        self.salt = new_salt;
        self.epoch = new_epoch;
        self.counter = 0;
        self.bytes_since_rekey = 0;
        self.first_instant = {
            #[cfg(test)]
            {
                if let Some(ref h) = self.test_clock {
                    h.now()
                } else {
                    Instant::now()
                }
            }
            #[cfg(not(test))]
            {
                Instant::now()
            }
        };
        self.soft_rekey_signalled = false;
    }

    /// Return a snapshot of the internal state for diagnostics / telemetry.
    ///
    /// `soft_rekey_signalled` indicates whether the size-based hint has already fired this epoch.
    fn state(&self) -> NonceState {
        NonceState {
            epoch: self.epoch,
            counter: self.counter,
            bytes_since_rekey: self.bytes_since_rekey,
            soft_rekey_signalled: self.soft_rekey_signalled,
        }
    }
}

// ---------- Test Support (cfg(test)) ----------
#[cfg(test)]
#[derive(Clone)]
struct TestClockHandle {
    inner: std::sync::Arc<core::cell::Cell<Instant>>,
}
#[cfg(test)]
impl TestClockHandle {
    fn now(&self) -> Instant {
        self.inner.get()
    }
    fn advance(&self, d: Duration) {
        self.inner.set(self.inner.get() + d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::nonce_manager::NonceManagerConfig;

    fn salt() -> NonceSalt {
        NonceSalt([0u8; 16])
    }

    fn test_mgr(cfg: NonceManagerConfig) -> (DirectionalNonceM, super::TestClockHandle) {
        let handle = super::TestClockHandle {
            inner: std::sync::Arc::new(core::cell::Cell::new(Instant::now())),
        };
        (
            DirectionalNonceM::with_test_clock(salt(), 0, cfg, handle.clone()),
            handle,
        )
    }

    #[test]
    fn allocates_monotonic_seq() {
        let cfg = NonceManagerConfig::default();
        let (mut m, _) = test_mgr(cfg);
        for i in 0..10 {
            assert_eq!(m.next(1).unwrap().seq.0, i);
        }
    }

    #[test]
    fn soft_size_hint_once() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 8;
        cfg.hard_bytes = 100;
        let (mut m, _) = test_mgr(cfg);
        let mut hinted = 0;
        for _ in 0..16 {
            if m.next(1).unwrap().soft_rekey_hint {
                hinted += 1;
            }
        }
        assert_eq!(hinted, 1);
    }

    #[test]
    fn soft_time_hint() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_time = Duration::from_millis(50);
        let (mut m, h) = test_mgr(cfg);
        assert!(!m.next(1).unwrap().time_rekey_hint);
        h.advance(Duration::from_millis(60));
        assert!(m.next(1).unwrap().time_rekey_hint);
    }

    #[test]
    fn both_hints_same_call() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 4;
        cfg.soft_time = Duration::from_millis(10);
        cfg.hard_bytes = 100;
        let (mut m, h) = test_mgr(cfg);
        h.advance(Duration::from_millis(15));
        let adv = m.next(4).unwrap();
        assert!(adv.soft_rekey_hint && adv.time_rekey_hint);
    }

    #[test]
    fn hard_byte_limit_enforced() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 2;
        cfg.hard_bytes = 4;
        let (mut m, _) = test_mgr(cfg);
        m.next(2).unwrap();
        m.next(2).unwrap();
        assert!(matches!(
            m.next(1).unwrap_err(),
            NonceSeqError::RekeyRequired
        ));
    }

    #[test]
    fn hard_byte_exact_boundary_allows_last_frame_then_blocks() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 2;
        cfg.hard_bytes = 4;
        let (mut m, _) = test_mgr(cfg);
        m.next(2).unwrap(); // bytes=2
        let _ = m.next(2).unwrap(); // bytes=4 exactly allowed
        assert!(matches!(
            m.next(0).unwrap_err(),
            NonceSeqError::RekeyRequired
        ));
    }

    #[test]
    fn install_rekey_resets_state() {
        let cfg = NonceManagerConfig::default();
        let (mut m, _) = test_mgr(cfg);
        m.next(10).unwrap();
        m.install_rekey(NonceSalt([1u8; 16]), 1);
        let s = m.state();
        assert_eq!(s.epoch, 1);
        assert_eq!(s.counter, 0);
        assert_eq!(s.bytes_since_rekey, 0);
    }

    #[test]
    fn soft_hint_fires_again_after_rekey() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 4;
        cfg.hard_bytes = 100;
        let (mut m, _) = test_mgr(cfg.clone());
        // trigger first soft hint
        m.next(2).unwrap();
        let adv = m.next(2).unwrap();
        assert!(adv.soft_rekey_hint);
        // rekey
        m.install_rekey(NonceSalt([2u8; 16]), 99);
        // trigger again
        m.next(2).unwrap();
        let adv2 = m.next(2).unwrap();
        assert!(adv2.soft_rekey_hint, "soft hint should refire after rekey");
    }

    #[test]
    fn new_constructor_sets_initial_state() {
        let mut cfg = NonceManagerConfig::default();
        cfg.soft_bytes = 32; // arbitrary
        cfg.hard_bytes = 1024; // arbitrary
        let salt_val = NonceSalt([9u8; 16]);
        let mut m = DirectionalNonceM::new(salt_val, 7, cfg.clone());
        let s = m.state();
        assert_eq!(s.epoch, 7);
        assert_eq!(s.counter, 0);
        assert_eq!(s.bytes_since_rekey, 0);
        assert!(!s.soft_rekey_signalled);
        // first next uses seq 0 and updates accounting
        let adv = m.next(4).unwrap();
        assert_eq!(adv.seq.0, 0);
        assert_eq!(adv.salt, salt_val);
        let s2 = m.state();
        assert_eq!(s2.counter, 1);
        assert_eq!(s2.bytes_since_rekey, 4);
    }

    #[test]
    fn counter_exhaustion_path() {
        // Use small loop to avoid huge runtime: set counter to near max.
        let cfg = NonceManagerConfig::default();
        let (mut m, _) = test_mgr(cfg);
        m.set_counter_for_test(u64::MAX - 1);
        let _ = m.next(1).unwrap(); // allocates last valid seq
        assert!(matches!(m.next(1).unwrap_err(), NonceSeqError::Exhausted));
    }
}
