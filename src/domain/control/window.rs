use serde::{Deserialize, Serialize};

use super::rekey::MAX_PAD_LEN;

/// Bounds for terminal window dimensions (inclusive).
pub const MIN_DIM: u32 = 1;
pub const MAX_DIM: u32 = 10000;

/// Frame indicating a PTY size change for a `tty` channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermResize {
    /// Target channel id (must reference an existing `tty` channel; higher layer validates kind).
    pub id: u64,
    /// Columns (1..=10000).
    pub cols: u32,
    /// Rows (1..=10000).
    pub rows: u32,
    /// Optional padding (length hiding; excluded from transcript style hashes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pad: Vec<u8>,
}

impl TermResize {
    /// Construct a new `TermResize` after bounds validation.
    ///
    /// # Errors
    /// * [`WindowFrameError::InvalidDims`] if `cols` or `rows` outside `MIN_DIM..=MAX_DIM`.
    pub fn new(id: u64, cols: u32, rows: u32) -> Result<Self, WindowFrameError> {
        if !(MIN_DIM..=MAX_DIM).contains(&cols) || !(MIN_DIM..=MAX_DIM).contains(&rows) {
            return Err(WindowFrameError::InvalidDims { cols, rows });
        }
        Ok(Self {
            id,
            cols,
            rows,
            pad: Vec::new(),
        })
    }

    /// Set deterministic padding bytes.
    ///
    /// # Errors
    /// * [`WindowFrameError::PadTooLarge`] if `pad.len() > MAX_PAD_LEN`.
    pub fn set_padding(&mut self, pad: Vec<u8>) -> Result<&mut Self, WindowFrameError> {
        if pad.len() > MAX_PAD_LEN {
            return Err(WindowFrameError::PadTooLarge { len: pad.len() });
        }
        self.pad = pad;
        Ok(self)
    }

    /// Clear padding.
    pub fn clear_padding(&mut self) {
        self.pad.clear();
    }
}

/// Errors for terminal window management frames.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WindowFrameError {
    #[error("terminal resize dimensions invalid cols={cols} rows={rows} (1..=10000)")]
    InvalidDims { cols: u32, rows: u32 },
    #[error("padding length {len} exceeds MAX_PAD_LEN {MAX_PAD_LEN}")]
    PadTooLarge { len: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resize_ok() {
        let r = TermResize::new(4, 120, 40).unwrap();
        assert_eq!(r.cols, 120);
        assert_eq!(r.rows, 40);
    }

    #[test]
    fn resize_invalid_cols() {
        let e = TermResize::new(4, 0, 40).unwrap_err();
        assert!(matches!(e, WindowFrameError::InvalidDims { .. }));
    }

    #[test]
    fn resize_invalid_rows() {
        let e = TermResize::new(4, 80, 0).unwrap_err();
        assert!(matches!(e, WindowFrameError::InvalidDims { .. }));
    }

    #[test]
    fn resize_padding_set_and_clear() {
        let mut r = TermResize::new(6, 80, 25).unwrap();
        r.set_padding(vec![0u8; 16]).unwrap();
        assert_eq!(r.pad.len(), 16);
        r.clear_padding();
        assert!(r.pad.is_empty());
    }

    #[test]
    fn resize_padding_too_large() {
        let mut r = TermResize::new(6, 80, 25).unwrap();
        let big = vec![0u8; MAX_PAD_LEN + 1];
        let e = r.set_padding(big).unwrap_err();
        assert!(matches!(e, WindowFrameError::PadTooLarge { .. }));
    }
}
