use serde::{Deserialize, Serialize};

use super::rekey::MAX_PAD_LEN;

/// Maximum command length for `exec` OPEN frames (UTF-8 bytes, NFC expected externally).
pub const MAX_CMD_LEN: usize = 256;
/// Maximum environment variable count allowed in an OPEN frame.
pub const MAX_ENV_VARS: usize = 64;
/// Maximum single environment variable name length.
pub const MAX_ENV_NAME: usize = 64;
/// Maximum single environment variable value length.
pub const MAX_ENV_VALUE: usize = 256;

/// Channel kind requested in an `Open` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    /// Interactive TTY session (pty-backed shell)
    Tty,
    /// Single exec command (non-interactive)
    Exec,
}

/// Reason codes for a graceful channel close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReasonCode {
    /// Normal application completion (e.g. EOF or command exit)
    Normal,
    /// Aborted locally by user (e.g. cancellation)
    Canceled,
    /// Protocol violation detected (channel scoped)
    ProtocolError,
    /// Resource exhaustion (e.g. memory/limits)
    Resource,
}

/// Window size hint for `tty` channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinSize {
    /// Columns (1..=10000)
    pub cols: u32,
    /// Rows (1..=10000)
    pub rows: u32,
}

impl WinSize {
    /// Construct a validated `WinSize`.
    ///
    /// # Errors
    /// * Returns [`ChannelFrameError::InvalidWindow`] if outside 1..=10000.
    pub fn new(cols: u32, rows: u32) -> Result<Self, ChannelFrameError> {
        if !(1..=10000).contains(&cols) || !(1..=10000).contains(&rows) {
            return Err(ChannelFrameError::InvalidWindow { cols, rows });
        }
        Ok(Self { cols, rows })
    }
}

/// OPEN frame for requesting a new logical channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
    /// Proposed channel id (parity = initiator identity responsibility of caller).
    pub id: u64,
    /// Kind of channel requested.
    pub kind: ChannelKind,
    /// Command for `exec` kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    /// Optional environment variables (already validated; map semantics left to higher layer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<(String, String)>>,
    /// Optional window size (only valid for `tty`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub winsize: Option<WinSize>,
    /// Optional padding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pad: Vec<u8>,
}

impl Open {
    /// Build a new `Open` frame performing semantic validation.
    ///
    /// # Errors
    /// * [`ChannelFrameError::CmdRequired`] if kind is `Exec` and cmd missing.
    /// * [`ChannelFrameError::CmdProhibited`] if kind is `Tty` and cmd provided.
    /// * [`ChannelFrameError::CmdTooLong`] if `cmd` exceeds `MAX_CMD_LEN` bytes.
    /// * [`ChannelFrameError::EnvTooMany`] if env var count exceeds `MAX_ENV_VARS`.
    /// * [`ChannelFrameError::EnvNameInvalid`] / `EnvValueInvalid` for size violations.
    /// * [`ChannelFrameError::WinsizeProhibited`] if winsize for non-tty.
    /// * [`ChannelFrameError::WinsizeInvalid`] if winsize out of bounds.
    pub fn new(
        id: u64,
        kind: ChannelKind,
        cmd: Option<String>,
        env: Option<Vec<(String, String)>>,
        winsize: Option<WinSize>,
    ) -> Result<Self, ChannelFrameError> {
        match kind {
            ChannelKind::Exec => {
                let c = cmd.as_ref().ok_or(ChannelFrameError::CmdRequired)?;
                if c.len() > MAX_CMD_LEN {
                    return Err(ChannelFrameError::CmdTooLong { len: c.len() });
                }
                if winsize.is_some() {
                    return Err(ChannelFrameError::WinsizeProhibited);
                }
            }
            ChannelKind::Tty => {
                if cmd.is_some() {
                    return Err(ChannelFrameError::CmdProhibited);
                }
            }
        }

        if let Some(ref ws) = winsize
            && (!(1..=10000).contains(&ws.cols) || !(1..=10000).contains(&ws.rows))
        {
            return Err(ChannelFrameError::WinsizeInvalid {
                cols: ws.cols,
                rows: ws.rows,
            });
        }

        if let Some(ref vars) = env {
            if vars.len() > MAX_ENV_VARS {
                return Err(ChannelFrameError::EnvTooMany { count: vars.len() });
            }
            for (name, value) in vars {
                if name.is_empty() || name.len() > MAX_ENV_NAME {
                    return Err(ChannelFrameError::EnvNameInvalid { len: name.len() });
                }
                if value.len() > MAX_ENV_VALUE {
                    return Err(ChannelFrameError::EnvValueInvalid { len: value.len() });
                }
            }
        }

        Ok(Self {
            id,
            kind,
            cmd,
            env,
            winsize,
            pad: Vec::new(),
        })
    }

    /// Set deterministic padding bytes.
    ///
    /// # Errors
    /// * Returns [`ChannelFrameError::PadTooLarge`] if `pad.len() > MAX_PAD_LEN`.
    pub fn set_padding(&mut self, pad: Vec<u8>) -> Result<&mut Self, ChannelFrameError> {
        if pad.len() > MAX_PAD_LEN {
            return Err(ChannelFrameError::PadTooLarge { len: pad.len() });
        }
        self.pad = pad;
        Ok(self)
    }

    /// Clear existing padding.
    pub fn clear_padding(&mut self) {
        self.pad.clear();
    }
}

/// CLOSE frame for terminating a logical channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Close {
    /// Channel id being closed.
    pub id: u64,
    /// Reason code (advisory).
    pub code: CloseReasonCode,
    /// Optional human-readable reason (UTF-8, truncated by builders if needed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional padding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pad: Vec<u8>,
}

impl Close {
    /// Construct a new `Close`.
    ///
    /// # Errors
    /// * [`ChannelFrameError::ReasonTooLong`] if reason > 256 bytes.
    pub fn new(
        id: u64,
        code: CloseReasonCode,
        reason: Option<String>,
    ) -> Result<Self, ChannelFrameError> {
        if let Some(ref r) = reason
            && r.len() > 256
        {
            return Err(ChannelFrameError::ReasonTooLong { len: r.len() });
        }
        Ok(Self {
            id,
            code,
            reason,
            pad: Vec::new(),
        })
    }

    /// Set deterministic padding.
    ///
    /// # Errors
    /// * Returns [`ChannelFrameError::PadTooLarge`] if `pad.len() > MAX_PAD_LEN`.
    pub fn set_padding(&mut self, pad: Vec<u8>) -> Result<&mut Self, ChannelFrameError> {
        if pad.len() > MAX_PAD_LEN {
            return Err(ChannelFrameError::PadTooLarge { len: pad.len() });
        }
        self.pad = pad;
        Ok(self)
    }

    /// Clear padding.
    pub fn clear_padding(&mut self) {
        self.pad.clear();
    }
}

/// Errors for channel frame semantic validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelFrameError {
    #[error("cmd required for exec kind")]
    CmdRequired,
    #[error("cmd prohibited for tty kind")]
    CmdProhibited,
    #[error("command length {len} exceeds {MAX_CMD_LEN}")]
    CmdTooLong { len: usize },
    #[error("too many environment variables: {count} > {MAX_ENV_VARS}")]
    EnvTooMany { count: usize },
    #[error("environment variable name length {len} invalid (1..={MAX_ENV_NAME})")]
    EnvNameInvalid { len: usize },
    #[error("environment variable value length {len} exceeds {MAX_ENV_VALUE}")]
    EnvValueInvalid { len: usize },
    #[error("window size invalid cols={cols} rows={rows} (1..=10000)")]
    InvalidWindow { cols: u32, rows: u32 },
    #[error("winsize field only valid for tty channels")]
    WinsizeProhibited,
    #[error("winsize invalid bounds cols={cols} rows={rows}")]
    WinsizeInvalid { cols: u32, rows: u32 },
    #[error("padding length {len} exceeds MAX_PAD_LEN {MAX_PAD_LEN}")]
    PadTooLarge { len: usize },
    #[error("close reason length {len} exceeds 256")]
    ReasonTooLong { len: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_exec_ok() {
        let o = Open::new(2, ChannelKind::Exec, Some("ls".into()), None, None).unwrap();
        assert_eq!(o.kind, ChannelKind::Exec);
        assert_eq!(o.cmd.as_deref(), Some("ls"));
    }

    #[test]
    fn open_exec_missing_cmd() {
        let e = Open::new(2, ChannelKind::Exec, None, None, None).unwrap_err();
        assert!(matches!(e, ChannelFrameError::CmdRequired));
    }

    #[test]
    fn open_tty_cmd_prohibited() {
        let e = Open::new(4, ChannelKind::Tty, Some("bash".into()), None, None).unwrap_err();
        assert!(matches!(e, ChannelFrameError::CmdProhibited));
    }

    #[test]
    fn open_tty_with_winsize() {
        let ws = WinSize::new(80, 24).unwrap();
        let o = Open::new(4, ChannelKind::Tty, None, None, Some(ws.clone())).unwrap();
        assert_eq!(o.winsize, Some(ws));
    }

    #[test]
    fn open_exec_with_winsize_prohibited() {
        let ws = WinSize::new(80, 24).unwrap();
        let e = Open::new(2, ChannelKind::Exec, Some("ls".into()), None, Some(ws)).unwrap_err();
        assert!(matches!(e, ChannelFrameError::WinsizeProhibited));
    }

    #[test]
    fn env_validation() {
        let env = vec![("HOME".into(), "/home/user".into())];
        let o = Open::new(6, ChannelKind::Exec, Some("id".into()), Some(env), None).unwrap();
        assert_eq!(o.id, 6);
    }

    #[test]
    fn env_name_too_long() {
        let name = "X".repeat(MAX_ENV_NAME + 1);
        let env = vec![(name, "v".into())];
        let e = Open::new(6, ChannelKind::Exec, Some("id".into()), Some(env), None).unwrap_err();
        assert!(matches!(e, ChannelFrameError::EnvNameInvalid { .. }));
    }

    #[test]
    fn env_value_too_long() {
        let value = "V".repeat(MAX_ENV_VALUE + 1);
        let env = vec![("N".into(), value)];
        let e = Open::new(6, ChannelKind::Exec, Some("id".into()), Some(env), None).unwrap_err();
        assert!(matches!(e, ChannelFrameError::EnvValueInvalid { .. }));
    }

    #[test]
    fn close_reason_ok() {
        let c = Close::new(2, CloseReasonCode::Normal, Some("done".into())).unwrap();
        assert_eq!(c.reason.as_deref(), Some("done"));
    }

    #[test]
    fn close_reason_too_long() {
        let r = "r".repeat(257);
        let e = Close::new(2, CloseReasonCode::Canceled, Some(r)).unwrap_err();
        assert!(matches!(e, ChannelFrameError::ReasonTooLong { .. }));
    }

    #[test]
    fn winsize_new_invalid() {
        let err = WinSize::new(0, 24).unwrap_err();
        assert!(matches!(err, ChannelFrameError::InvalidWindow { .. }));
    }

    #[test]
    fn open_with_invalid_winsize_struct() {
        // Bypass constructor validation by constructing an invalid Winsize directly
        let invalid = WinSize { cols: 0, rows: 50 }; // 0 invalid
        let err = Open::new(8, ChannelKind::Tty, None, None, Some(invalid)).unwrap_err();
        assert!(matches!(err, ChannelFrameError::WinsizeInvalid { .. }));
    }

    #[test]
    fn open_command_too_long() {
        let long_cmd = "a".repeat(MAX_CMD_LEN + 1);
        let err = Open::new(2, ChannelKind::Exec, Some(long_cmd), None, None).unwrap_err();
        assert!(matches!(err, ChannelFrameError::CmdTooLong { .. }));
    }

    #[test]
    fn open_env_too_many() {
        let mut env = Vec::new();
        for i in 0..=MAX_ENV_VARS {
            // one more than allowed
            env.push((format!("K{i}"), "V".into()));
        }
        let err =
            Open::new(10, ChannelKind::Exec, Some("echo".into()), Some(env), None).unwrap_err();
        assert!(matches!(err, ChannelFrameError::EnvTooMany { .. }));
    }

    #[test]
    fn open_padding_set_and_clear() {
        let mut o = Open::new(12, ChannelKind::Exec, Some("id".into()), None, None).unwrap();
        o.set_padding(vec![0u8; 8]).unwrap();
        assert_eq!(o.pad.len(), 8);
        o.clear_padding();
        assert!(o.pad.is_empty());
    }

    #[test]
    fn open_padding_too_large() {
        let mut o = Open::new(14, ChannelKind::Exec, Some("true".into()), None, None).unwrap();
        let big = vec![0u8; MAX_PAD_LEN + 1];
        let err = o.set_padding(big).unwrap_err();
        assert!(matches!(err, ChannelFrameError::PadTooLarge { .. }));
    }

    #[test]
    fn close_padding_set_and_clear() {
        let mut c = Close::new(16, CloseReasonCode::Normal, None).unwrap();
        c.set_padding(vec![1u8; 4]).unwrap();
        assert_eq!(c.pad.len(), 4);
        c.clear_padding();
        assert!(c.pad.is_empty());
    }

    #[test]
    fn close_padding_too_large() {
        let mut c = Close::new(18, CloseReasonCode::Canceled, None).unwrap();
        let big = vec![0u8; MAX_PAD_LEN + 1];
        let err = c.set_padding(big).unwrap_err();
        assert!(matches!(err, ChannelFrameError::PadTooLarge { .. }));
    }
}
