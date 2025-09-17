// Legacy shim: re-export moved handshake port items from `ports::handshake` to
// avoid widespread path churn for existing callers still using
// `application::handshake::...`.
pub use crate::ports::handshake::{HandshakeTranscriptRef, HandshakeWire, WireError};
