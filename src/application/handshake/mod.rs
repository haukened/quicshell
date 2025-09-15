pub mod errors;
pub mod fsm_machine;
#[cfg(test)]
mod fsm_tests;
pub mod fsm_types;
pub mod ports;

pub use errors::*;
pub use fsm_machine::*;
pub use fsm_types::*;
pub use ports::*;

// Unified namespace export so users can choose `handshake::fsm::HandshakeFsm`
// instead of pulling individual symbols at the root. This keeps API flexibility
// while allowing a single import path for all FSM-related items.
pub mod fsm {
    pub use super::errors::*;
    pub use super::fsm_machine::*;
    pub use super::fsm_types::*;
    pub use super::ports::*;
}
