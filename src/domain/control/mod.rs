//! Control channel domain models.
//!
//! This module now delegates specific frame groups to submodules:
//! * `rekey` – per‑direction rekey request/acknowledgement logic.
//! * `channel` – (planned) channel open/close lifecycle frames.
//! * `window` – (planned) PTY/window size management frames.
//!
//! Each submodule provides pure data structures plus semantic constructors and
//! validation errors. Protocol encoding/decoding lives in the protocol layer.

pub mod channel;
pub mod rekey;
// pub mod window;  // forthcoming

pub use channel::{ChannelFrameError, ChannelKind, Close, CloseReasonCode, Open, WinSize};
pub use rekey::{MAX_PAD_LEN, RekeyAck, RekeyDirection, RekeyFrameError, RekeyReq};
