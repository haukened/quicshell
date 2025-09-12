use crate::domain::handshake::helpers::is_ascii_upper_token;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Capability token (validated UPPERCASE ASCII, length 1..=`CAP_TOKEN_MAX`).
///
/// Why a newtype over `String` (not an enum): the capability space is intentionally
/// open/extensible; peers must forward & accept unknown advisory tokens without a
/// code / deploy cycle. A closed enum would either:
/// * reject future tokens (version skew) OR
/// * require an `Unknown(String)` variant that callers then still have to treat like a free string.
///
/// This newtype centralizes validation while preserving forward compatibility. If the
/// set ever freezes, an enum can replace it in a breaking revision. Ordering derives `Ord`
/// so a `Vec<Capability>` can be validated for strict lexicographic ordering (no duplicates)
/// with a simple window check.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(String);
impl Capability {
    /// Access the inner string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Parse and validate a capability token from a `&str`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input string violates length or character constraints:
    /// - Not ASCII uppercase (A-Z, 0-9, or `_`).
    /// - Length is zero or exceeds `CAP_TOKEN_MAX`.
    pub fn parse(s: &str) -> Result<Self, &'static str> {
        if is_ascii_upper_token(s) {
            Ok(Capability(s.to_string()))
        } else {
            Err("invalid capability token")
        }
    }
}
impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Capability({})", self.0)
    }
}
impl From<Capability> for String {
    fn from(c: Capability) -> Self {
        c.0
    }
}
impl Serialize for Capability {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use std::borrow::Cow;
        // Accept either a borrowed or owned string from the deserializer.
        let s: Cow<'de, str> = Cow::deserialize(d)?;
        let s_ref = s.as_ref();
        if !is_ascii_upper_token(s_ref) {
            return Err(serde::de::Error::custom("invalid capability token"));
        }
        Ok(Capability(s.into_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::params::CAP_TOKEN_MAX;
    use crate::test_support::mk_cap;

    #[test]
    fn parse_accepts_valid_tokens() {
        for tok in ["EXEC", "TTY", "A_B", "FOO1"] {
            assert!(Capability::parse(tok).is_ok(), "token {tok}");
        }
        let long = "X".repeat(CAP_TOKEN_MAX);
        assert!(Capability::parse(&long).is_ok());
    }
    #[test]
    fn parse_rejects_invalid_tokens() {
        for tok in ["exec", "A-B", "", "FOO!"] {
            assert!(Capability::parse(tok).is_err(), "token {tok}");
        }
        let long = "X".repeat(CAP_TOKEN_MAX + 1);
        assert!(Capability::parse(&long).is_err());
    }
    #[test]
    fn into_string_and_debug() {
        let c = mk_cap("EXEC");
        let s: String = c.clone().into();
        assert_eq!(s, "EXEC");
        assert!(format!("{c:?}").contains("Capability(EXEC)"));
    }
}
