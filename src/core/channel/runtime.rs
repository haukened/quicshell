use std::collections::HashMap;
use std::num::NonZeroU64;

/// Type of a channel (semantic purpose / behavior class).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelType {
    /// Control channel (id = 0, always present, carries control frames)
    Control,
    /// Interactive TTY channel
    Tty,
    /// Future: Exec / non-interactive command channel
    Exec,
}

/// Unique identifier for a channel.
///
/// Parity encodes the opening side (even = client, odd = server) for dynamic channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(u64);

impl ChannelId {
    /// Control channel id constant (0).
    pub const CONTROL: ChannelId = ChannelId(0);

    /// Create a channel id from a raw value.
    ///
    /// # Errors
    /// * Returns `ChannelError::ZeroDynamic` if attempting to construct a dynamic id of 0.
    pub fn new(raw: u64) -> Result<Self, ChannelError> {
        if raw == 0 {
            return Err(ChannelError::ZeroDynamic);
        }
        Ok(Self(raw))
    }

    /// Raw numeric value.
    #[must_use]
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Whether id is control (0).
    #[must_use]
    pub fn is_control(self) -> bool {
        self.0 == 0
    }

    /// Returns true if id parity matches a client-originated dynamic channel (even, >0).
    #[must_use]
    pub fn is_client_dynamic(self) -> bool {
        self.0 > 0 && self.0 % 2 == 0
    }

    /// Returns true if id parity matches a server-originated dynamic channel (odd, >0).
    #[must_use]
    pub fn is_server_dynamic(self) -> bool {
        self.0 > 0 && self.0 % 2 == 1
    }
}

/// Lifecycle state of a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Allocated but not yet opened (awaiting OPEN exchange if dynamic).
    Init,
    /// Open and active for data exchange.
    Open,
    /// Close initiated (locally or remotely) – waiting for finalization / draining.
    Closing,
    /// Fully terminated; resources released.
    Closed,
    /// Entered terminal error; should be torn down.
    Error,
}

impl ChannelState {
    /// Transition helper enforcing allowed state advances.
    ///
    /// Allowed transitions:
    /// * Init -> Open | Error
    /// * Open -> Closing | Error
    /// * Closing -> Closed | Error
    /// * Any -> Error
    ///   Closed/Error are terminal (except Closed -> Error disallowed to avoid late error noise).
    #[must_use]
    pub fn can_transition(self, next: ChannelState) -> bool {
        use ChannelState::{Closed, Closing, Error, Init, Open};
        matches!(
            (self, next),
            (Init, Open | Error) | (Open, Closing | Error) | (Closing, Closed | Error)
        )
    }
}

/// Errors related to channel runtime management.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("channel id 0 is reserved for control")]
    ZeroDynamic,
    #[error("parity mismatch for allocation (expected even=client, odd=server)")]
    ParityMismatch,
    #[error("duplicate channel id")]
    Duplicate,
    #[error("unknown channel id")]
    Unknown,
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: ChannelState,
        to: ChannelState,
    },
    #[error("allocation exhausted (no next id)")]
    AllocationExhausted,
}

/// Supervisor maintains registry and allocation of dynamic channels.
pub struct ChannelSupervisor {
    /// Whether we are client role (determines parity for allocations)
    client_role: bool,
    /// Next dynamic id cursor (always even if client, odd if server). Starts at first valid dynamic id: 2 (client) or 1 (server)
    next_id: NonZeroU64,
    /// Registry of channel states & types.
    registry: HashMap<ChannelId, (ChannelType, ChannelState)>,
}

impl ChannelSupervisor {
    /// Create a new supervisor for given role.
    /// Create a new supervisor for given role.
    ///
    /// # Panics
    /// Panics only if internal `NonZeroU64` construction fails (unreachable for valid start values 1 or 2).
    #[must_use]
    pub fn new(client_role: bool) -> Self {
        let start = if client_role { 2 } else { 1 }; // first dynamic id respecting parity
        Self {
            client_role,
            next_id: NonZeroU64::new(start).unwrap(),
            registry: HashMap::from([(
                ChannelId::CONTROL,
                (ChannelType::Control, ChannelState::Open),
            )]),
        }
    }

    /// Allocate a new dynamic channel id and register it in `Init` state.
    /// Allocate a new dynamic channel id and register it in `Init` state.
    ///
    /// # Errors
    /// * `ChannelError::ParityMismatch` if internal parity drifted.
    /// * `ChannelError::Duplicate` if id already present.
    /// * `ChannelError::AllocationExhausted` if id space wrapped.
    pub fn allocate(&mut self, ty: ChannelType) -> Result<ChannelId, ChannelError> {
        let mut raw = self.next_id.get();
        // Enforce parity (should already align by construction); guard in case of manual tampering.
        if self.client_role && raw % 2 != 0 {
            return Err(ChannelError::ParityMismatch);
        }
        if !self.client_role && raw % 2 != 1 {
            return Err(ChannelError::ParityMismatch);
        }
        let cid = ChannelId(raw);
        if self.registry.contains_key(&cid) {
            return Err(ChannelError::Duplicate);
        }
        self.registry.insert(cid, (ty, ChannelState::Init));
        // Advance cursor, checking for overflow; skip parity by +2 steps.
        raw = raw.saturating_add(2);
        if raw == 0 {
            // wrapped
            return Err(ChannelError::AllocationExhausted);
        }
        self.next_id = NonZeroU64::new(raw).ok_or(ChannelError::AllocationExhausted)?;
        Ok(cid)
    }

    /// Get current state of a channel.
    /// Get current state of a channel.
    ///
    /// # Errors
    /// * `ChannelError::Unknown` if id not registered.
    pub fn state(&self, cid: ChannelId) -> Result<ChannelState, ChannelError> {
        self.registry
            .get(&cid)
            .map(|(_, s)| *s)
            .ok_or(ChannelError::Unknown)
    }

    /// Transition channel to next state if allowed.
    /// Transition channel to next state if permitted.
    ///
    /// # Errors
    /// * `ChannelError::Unknown` if id not registered.
    /// * `ChannelError::InvalidTransition` if disallowed by FSM rules.
    pub fn transition(&mut self, cid: ChannelId, next: ChannelState) -> Result<(), ChannelError> {
        let entry = self.registry.get_mut(&cid).ok_or(ChannelError::Unknown)?;
        let current = entry.1;
        if !current.can_transition(next) {
            return Err(ChannelError::InvalidTransition {
                from: current,
                to: next,
            });
        }
        entry.1 = next;
        Ok(())
    }

    /// Remove closed channels from registry.
    pub fn reap_closed(&mut self) {
        self.registry
            .retain(|_, (_, st)| *st != ChannelState::Closed);
    }

    /// Count channels by predicate.
    #[must_use]
    pub fn count(&self) -> usize {
        self.registry.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_channel_present_open() {
        let sup = ChannelSupervisor::new(true);
        assert_eq!(sup.state(ChannelId::CONTROL).unwrap(), ChannelState::Open);
    }

    #[test]
    fn allocate_parity_client_even() {
        let mut sup = ChannelSupervisor::new(true);
        let cid = sup.allocate(ChannelType::Tty).unwrap();
        assert!(cid.is_client_dynamic());
        assert_eq!(sup.state(cid).unwrap(), ChannelState::Init);
    }

    #[test]
    fn allocate_parity_server_odd() {
        let mut sup = ChannelSupervisor::new(false);
        let cid = sup.allocate(ChannelType::Tty).unwrap();
        assert!(cid.is_server_dynamic());
    }

    #[test]
    fn state_transitions_valid() {
        let mut sup = ChannelSupervisor::new(true);
        let cid = sup.allocate(ChannelType::Tty).unwrap();
        sup.transition(cid, ChannelState::Open).unwrap();
        sup.transition(cid, ChannelState::Closing).unwrap();
        sup.transition(cid, ChannelState::Closed).unwrap();
        // Cannot transition again
        let err = sup.transition(cid, ChannelState::Error).unwrap_err();
        assert!(matches!(err, ChannelError::InvalidTransition { .. }));
    }

    #[test]
    fn invalid_transition_rejected() {
        let mut sup = ChannelSupervisor::new(true);
        let cid = sup.allocate(ChannelType::Tty).unwrap();
        // Init -> Closed not allowed directly
        let err = sup.transition(cid, ChannelState::Closed).unwrap_err();
        assert!(matches!(err, ChannelError::InvalidTransition { .. }));
    }

    #[test]
    fn reap_closed_removes() {
        let mut sup = ChannelSupervisor::new(true);
        let cid = sup.allocate(ChannelType::Tty).unwrap();
        sup.transition(cid, ChannelState::Open).unwrap();
        sup.transition(cid, ChannelState::Closing).unwrap();
        sup.transition(cid, ChannelState::Closed).unwrap();
        sup.reap_closed();
        assert!(matches!(sup.state(cid), Err(ChannelError::Unknown)));
    }

    #[test]
    fn channel_id_zero_dynamic_error() {
        let err = ChannelId::new(0).unwrap_err();
        assert_eq!(err, ChannelError::ZeroDynamic);
    }

    #[test]
    fn channel_id_methods() {
        let cid_client = ChannelId::new(2).unwrap();
        assert_eq!(cid_client.raw(), 2);
        assert!(!cid_client.is_control());
        assert!(cid_client.is_client_dynamic());
        assert!(!cid_client.is_server_dynamic());
        assert!(ChannelId::CONTROL.is_control());
    }

    #[test]
    fn can_transition_negative_cases() {
        assert!(!ChannelState::Init.can_transition(ChannelState::Closed));
        assert!(!ChannelState::Open.can_transition(ChannelState::Closed));
        assert!(!ChannelState::Closed.can_transition(ChannelState::Open));
        assert!(!ChannelState::Error.can_transition(ChannelState::Open));
    }

    #[test]
    fn unknown_state_and_transition_errors() {
        let mut sup = ChannelSupervisor::new(true);
        let bogus = ChannelId(9); // not allocated
        assert!(matches!(sup.state(bogus), Err(ChannelError::Unknown)));
        let err = sup.transition(bogus, ChannelState::Open).unwrap_err();
        assert!(matches!(err, ChannelError::Unknown));
    }

    #[test]
    fn count_reflects_registry_changes() {
        let mut sup = ChannelSupervisor::new(true);
        assert_eq!(sup.count(), 1); // control
        let c1 = sup.allocate(ChannelType::Tty).unwrap();
        let _c2 = sup.allocate(ChannelType::Tty).unwrap();
        assert_eq!(sup.count(), 3);
        sup.transition(c1, ChannelState::Open).unwrap();
        sup.transition(c1, ChannelState::Closing).unwrap();
        sup.transition(c1, ChannelState::Closed).unwrap();
        sup.reap_closed();
        assert_eq!(sup.count(), 2);
    }
}
