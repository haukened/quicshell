// ---- Helper validation functions ----
use crate::domain::handshake::params::CAP_TOKEN_MAX;

/// Checks if a string is a valid ASCII uppercase token.
pub(crate) fn is_ascii_upper_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= CAP_TOKEN_MAX
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(!is_ascii_upper_token(""));
    }
    #[test]
    fn rejects_too_long() {
        assert!(!is_ascii_upper_token(&"X".repeat(CAP_TOKEN_MAX + 1)));
    }
    #[test]
    fn rejects_invalid_char() {
        assert!(!is_ascii_upper_token("AB-"));
    }
    #[test]
    fn accepts_simple_valid() {
        assert!(is_ascii_upper_token("EXEC"));
    }
    #[test]
    fn accepts_max_len() {
        assert!(is_ascii_upper_token(&"A".repeat(CAP_TOKEN_MAX)));
    }
}
