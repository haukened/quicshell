//! Port abstraction for directional AEAD nonce management.
//!
//! Provides an interface that channel/application layers use to obtain
//! monotonically increasing `(salt, seq)` pairs for constructing AEAD nonces
//! (XChaCha20-Poly1305: 16-byte salt/prefix || 8-byte counter = 24 bytes).
//!
//! Responsibilities:
//! * Enforce per-direction counter monotonicity (no reuse)
//! * Signal when soft rekey thresholds (bytes/time) are crossed
//! * Prevent wrap-around within an epoch (hard failure -> must rekey)
//! * Reset internal counters on successful rekey installation
//!
//! This trait deliberately does NOT perform HKDF derivation; callers supply
//! fresh `NonceSalt` values derived from the key schedule at handshake and
//! each rekey event.
//!
//! Clean architecture: This lives in `ports` so that core/infrastructure
//! implementations supply concrete managers while application logic depends
//! only on the abstraction.

use crate::ports::crypto::{NonceSalt, Seq};
use core::time::Duration;

/// Error conditions surfaced by a `DirectionalNonceManager`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NonceSeqError {
    /// Counter would wrap (u64 exhausted) before a rekey was performed.
    #[error("nonce sequence exhausted; rekey required")]
    Exhausted,
    /// Hard size or time threshold exceeded; caller MUST rekey before sending more.
    #[error("rekey required (hard threshold exceeded)")]
    RekeyRequired,
    /// Internal invariant violation (should never occur in correct usage).
    #[error("internal nonce manager invariant violated")]
    InternalInvariant,
}

/// Snapshot of internal state for diagnostics / metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceState {
    pub epoch: u64,
    pub counter: u64,
    pub bytes_since_rekey: u64,
    pub soft_rekey_signalled: bool,
}

/// Outcome flags returned alongside a successful sequence allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceAdvance {
    /// The salt to use (prefix of AEAD nonce).
    pub salt: NonceSalt,
    /// The sequence value (counter BEFORE increment used in AEAD nonce suffix).
    pub seq: Seq,
    /// Hint: soft byte threshold crossed (initiate rekey soon).
    pub soft_rekey_hint: bool,
    /// Hint: soft time threshold crossed (initiate rekey soon).
    pub time_rekey_hint: bool,
}

/// Trait for a per-direction AEAD nonce manager.
///
/// Contract:
/// * `next(bytes)` returns a unique `(salt, seq)` until a hard limit triggers an error.
/// * Caller inspects `soft_*` hints to proactively initiate rekey.
/// * After rekey key schedule finishes, caller invokes `install_rekey` with new salt & epoch.
pub trait DirectionalNonceManager {
    /// Obtain next `(salt, seq)` pair given number of plaintext bytes about to be sealed.
    /// `bytes_about_to_seal` contributes to size-based rekey heuristics.
    ///
    /// # Errors
    /// Returns `NonceSeqError::RekeyRequired` if a hard threshold was exceeded,
    /// `NonceSeqError::Exhausted` if the counter would wrap, or
    /// `NonceSeqError::InternalInvariant` if an internal invariant failed.
    fn next(&mut self, bytes_about_to_seal: usize) -> Result<NonceAdvance, NonceSeqError>;

    /// Install a new salt and reset counters after a successful rekey.
    fn install_rekey(&mut self, new_salt: NonceSalt, new_epoch: u64);

    /// Return a diagnostic snapshot.
    fn state(&self) -> NonceState;
}

/// Configuration parameters for a nonce manager implementation.
#[derive(Debug, Clone, Copy)]
pub struct NonceManagerConfig {
    /// Soft byte threshold (e.g., 1 MiB) after which a rekey should be initiated.
    pub soft_bytes: u64,
    /// Hard byte ceiling (e.g., 64 MiB) which MUST NOT be exceeded without rekey.
    pub hard_bytes: u64,
    /// Soft time threshold (e.g., 30 s) after which rekey should be initiated.
    pub soft_time: Duration,
}

impl Default for NonceManagerConfig {
    fn default() -> Self {
        Self {
            soft_bytes: 1024 * 1024,      // 1 MiB
            hard_bytes: 64 * 1024 * 1024, // 64 MiB cap per epoch
            soft_time: Duration::from_secs(30),
        }
    }
}
