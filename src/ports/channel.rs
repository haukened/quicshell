use crate::core::channel::runtime::{
    ChannelError as RuntimeChannelError, ChannelId, ChannelState, ChannelType,
};
use thiserror::Error;

/// Errors surfaced by channel port operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChannelPortError {
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeChannelError),
    #[error("io error")]
    Io,
    #[error("encryption error")]
    Crypto,
    #[error("channel closed")]
    Closed,
    #[error("backpressure: send queue full")]
    Backpressure,
}

/// Sending side of a data-capable channel.
pub trait ChannelTx {
    /// Queue plaintext frame payload for sending (implementation applies crypto and framing later).
    ///
    /// # Errors
    /// * `ChannelPortError::Closed` if already closed.
    /// * `ChannelPortError::Backpressure` if send buffer full.
    fn send(&mut self, data: &[u8]) -> Result<(), ChannelPortError>;
    /// Close intent (half-close semantics for data direction if supported).
    ///
    /// # Errors
    /// * `ChannelPortError::Closed` if already closed.
    fn close(&mut self) -> Result<(), ChannelPortError>;
}

/// Receiving side of a data-capable channel.
pub trait ChannelRx {
    /// Poll for next decrypted data frame; returning `Ok(None)` means no frame currently available.
    ///
    /// # Errors
    /// * `ChannelPortError::Closed` if fully closed and no more data.
    fn poll_recv(&mut self) -> Result<Option<Vec<u8>>, ChannelPortError>;
}

/// Control operations applicable to any channel (query state, type, id).
pub trait ChannelControl {
    /// Channel identifier.
    fn id(&self) -> ChannelId;
    /// Channel type.
    fn ty(&self) -> ChannelType;
    /// Current runtime state.
    fn state(&self) -> ChannelState;
}

/// Multiplexer handles allocation and lookup of channels plus opening semantics.
pub trait Multiplexer {
    /// Open a new channel of given type, returning handle implementing Tx/Rx/Control.
    ///
    /// # Errors
    /// * `ChannelPortError::Runtime` if allocation fails.
    fn open_tty(&mut self) -> Result<Box<dyn ChannelTx + Send>, ChannelPortError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::channel::runtime::{ChannelState, ChannelSupervisor, ChannelType};

    struct MockTtyChannel {
        id: ChannelId,
        buf: Vec<Vec<u8>>,
        closed: bool,
        state: ChannelState,
        ty: ChannelType,
    }
    impl MockTtyChannel {
        fn new(id: ChannelId) -> Self {
            Self {
                id,
                buf: Vec::new(),
                closed: false,
                state: ChannelState::Init,
                ty: ChannelType::Tty,
            }
        }
    }
    impl ChannelTx for MockTtyChannel {
        fn send(&mut self, data: &[u8]) -> Result<(), ChannelPortError> {
            if self.closed {
                return Err(ChannelPortError::Closed);
            }
            self.buf.push(data.to_vec());
            Ok(())
        }
        fn close(&mut self) -> Result<(), ChannelPortError> {
            self.closed = true;
            self.state = ChannelState::Closed;
            Ok(())
        }
    }
    impl ChannelRx for MockTtyChannel {
        fn poll_recv(&mut self) -> Result<Option<Vec<u8>>, ChannelPortError> {
            if self.buf.is_empty() {
                return Ok(None);
            }
            Ok(self.buf.remove(0).into())
        }
    }
    impl ChannelControl for MockTtyChannel {
        fn id(&self) -> ChannelId {
            self.id
        }
        fn ty(&self) -> ChannelType {
            self.ty
        }
        fn state(&self) -> ChannelState {
            self.state
        }
    }

    struct MockMux {
        sup: ChannelSupervisor,
    }
    impl MockMux {
        fn new(client: bool) -> Self {
            Self {
                sup: ChannelSupervisor::new(client),
            }
        }
    }
    impl Multiplexer for MockMux {
        fn open_tty(&mut self) -> Result<Box<dyn ChannelTx + Send>, ChannelPortError> {
            let cid = self.sup.allocate(ChannelType::Tty)?;
            Ok(Box::new(MockTtyChannel::new(cid)))
        }
    }

    #[test]
    fn open_and_send_mock() {
        let mut mux = MockMux::new(true);
        let mut ch = mux.open_tty().unwrap();
        ch.send(b"hello").unwrap();
        ch.close().unwrap();
        let err = ch.send(b"again").unwrap_err();
        assert!(matches!(err, ChannelPortError::Closed));
    }
}
