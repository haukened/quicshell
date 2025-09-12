use crate::domain::handshake::errors::HandshakeError;
use crate::domain::handshake::params::{CAP_COUNT_MAX, PAD_MAX};
use crate::domain::handshake::{Capability, KemClientEphemeral, Nonce32};
use serde::{Deserialize, Serialize};

/// # Example (constructing a minimal `Hello`)
/// ```ignore
/// use quicshell::core::protocol::handshake::types::{
///         Hello, KemClientEphemeral, X25519Pub, Mlkem768Pub, Nonce32, Capability
/// };
/// // Dummy zeroed values for illustration ONLY – real code must use cryptographically
/// // secure randomness / proper key generation.
/// let kem = KemClientEphemeral { x25519_pub: X25519Pub([0;32]), mlkem_pub: Mlkem768Pub([0;1184]) };
/// let nonce = Nonce32([0;32]);
/// let caps = vec![Capability::parse("EXEC").unwrap(), Capability::parse("TTY").unwrap()];
/// // Calling the `new` constructor validates the message immediately.
/// let h_res = Hello::new(kem, nonce, caps, None);
/// match h_res {
///         Ok(h) => println!("Constructed valid Hello: {:?}", h),
///         Err(e) => eprintln!("Failed to construct Hello: {}", e),
/// }
/// ```
/// Client `HELLO` handshake message (spec §5.1).
///
/// Contains the client's ephemeral hybrid KEM public keys, a fresh nonce,
/// and advisory capability tokens (must include baseline `EXEC` and `TTY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Protocol version (must be 1)
    pub v: u8,
    /// Client's ephemeral KEM public keys
    pub kem_client_ephemeral: KemClientEphemeral,
    /// Randomly generated client nonce (length == 32)
    pub client_nonce: Nonce32,
    /// Advisory capability tokens (validated, must include baseline EXEC & TTY, strictly increasing)
    pub capabilities: Vec<Capability>,
    /// Optional padding (excluded from transcript hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<Vec<u8>>,
}

impl Hello {
    /// Validate semantic invariants (version, capabilities, pad size).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following invariants are violated:
    /// - `v` is not 1
    /// - Baseline capabilities `EXEC` or `TTY` missing
    /// - Capabilities not strictly increasing or exceed `CAP_COUNT_MAX`
    /// - Padding exceeds `PAD_MAX`
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.v != 1 {
            return Err(HandshakeError::HelloBadVersion);
        }
        // Baseline capabilities must be present
        if !(self.capabilities.iter().any(|c| c.as_str() == "EXEC")
            && self.capabilities.iter().any(|c| c.as_str() == "TTY"))
        {
            return Err(HandshakeError::HelloBadCapsFormat); // reuse variant per decision
        }
        // Enforce count + strict lexicographic increasing (no duplicates)
        if self.capabilities.len() > CAP_COUNT_MAX
            || self.capabilities.windows(2).any(|w| w[0] >= w[1])
        {
            return Err(HandshakeError::HelloBadCapsOrder);
        }
        if let Some(p) = &self.pad
            && p.len() > PAD_MAX
        {
            return Err(HandshakeError::HelloPadTooLarge);
        }
        Ok(())
    }

    /// Construct a `Hello` and immediately validate it.
    ///
    /// # Errors
    ///
    /// Returns `Err` if semantic validation fails (see [`Hello::validate`]).
    /// Prefer this over manual struct literal when constructing external-facing values.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        kem_client_ephemeral: KemClientEphemeral,
        client_nonce: Nonce32,
        capabilities: Vec<Capability>,
        pad: Option<Vec<u8>>,
    ) -> Result<Self, HandshakeError> {
        let h = Hello {
            v: 1,
            kem_client_ephemeral,
            client_nonce,
            capabilities,
            pad,
        };
        h.validate()?;
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::errors::HandshakeError;
    use crate::domain::handshake::params::{CAP_COUNT_MAX, PAD_MAX};
    use crate::test_support::{mk_cap, mk_kem, mk_nonce};
    use ciborium::{de::from_reader, ser::into_writer};
    use std::io::Cursor;

    #[test]
    fn version_must_be_1() {
        let (kem_c, _, _) = mk_kem();
        let h = Hello {
            v: 2,
            kem_client_ephemeral: kem_c,
            client_nonce: mk_nonce(),
            capabilities: vec![mk_cap("EXEC"), mk_cap("TTY")],
            pad: None,
        };
        assert!(matches!(h.validate(), Err(HandshakeError::HelloBadVersion)));
    }
    #[test]
    fn missing_baseline_caps_errors() {
        let (kem_c, _, _) = mk_kem();
        let nonce = mk_nonce();
        assert!(matches!(
            Hello::new(kem_c.clone(), nonce.clone(), vec![mk_cap("EXEC")], None),
            Err(HandshakeError::HelloBadCapsFormat)
        ));
        assert!(matches!(
            Hello::new(kem_c, nonce, vec![mk_cap("TTY")], None),
            Err(HandshakeError::HelloBadCapsFormat)
        ));
    }
    #[test]
    fn caps_unsorted_or_duplicate_errors() {
        let (kem_c, _, _) = mk_kem();
        let nonce = mk_nonce();
        let caps = vec![mk_cap("TTY"), mk_cap("EXEC")];
        assert!(matches!(
            Hello::new(kem_c.clone(), nonce.clone(), caps, None),
            Err(HandshakeError::HelloBadCapsOrder)
        ));
        let caps = vec![mk_cap("EXEC"), mk_cap("EXEC"), mk_cap("TTY")];
        assert!(matches!(
            Hello::new(kem_c.clone(), nonce.clone(), caps, None),
            Err(HandshakeError::HelloBadCapsOrder)
        ));
        let mut caps = vec![mk_cap("EXEC"), mk_cap("TTY")];
        for i in 0..CAP_COUNT_MAX - 1 {
            caps.push(mk_cap(&format!("Z{i:02}")));
        }
        caps.sort();
        assert_eq!(caps.len(), CAP_COUNT_MAX + 1);
        assert!(matches!(
            Hello::new(kem_c, nonce, caps, None),
            Err(HandshakeError::HelloBadCapsOrder)
        ));
    }
    #[test]
    fn pad_over_max_errors() {
        let (kem_c, _, _) = mk_kem();
        let pad = Some(vec![0u8; PAD_MAX + 1]);
        assert!(matches!(
            Hello::new(kem_c, mk_nonce(), vec![mk_cap("EXEC"), mk_cap("TTY")], pad),
            Err(HandshakeError::HelloPadTooLarge)
        ));
    }
    #[test]
    fn pad_at_max_ok() {
        let (kem_c, _, _) = mk_kem();
        let pad = Some(vec![0u8; PAD_MAX]);
        let h = Hello::new(kem_c, mk_nonce(), vec![mk_cap("EXEC"), mk_cap("TTY")], pad).unwrap();
        assert!(h.pad.is_some());
    }
    #[test]
    fn serialize_round_trip_caps_are_sorted_unique() {
        let mut caps = vec![mk_cap("TTY"), mk_cap("EXEC"), mk_cap("FOO1")];
        caps.sort();
        let (kem_c, _, _) = mk_kem();
        let hello = Hello::new(kem_c, mk_nonce(), caps.clone(), None).unwrap();
        let mut buf = Vec::new();
        into_writer(&hello, &mut buf).unwrap();
        let de: Hello = from_reader(Cursor::new(&buf)).unwrap();
        let got: Vec<String> = de
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        let mut want: Vec<String> = caps.into_iter().map(|c| c.as_str().to_string()).collect();
        want.sort();
        want.dedup();
        assert_eq!(got, want);
        assert!(de.capabilities.windows(2).all(|w| w[0] < w[1]));
    }
    #[derive(serde::Serialize)]
    struct HelloExtra {
        #[serde(flatten)]
        base: Hello,
        xtra: u8,
    }
    #[test]
    fn deny_unknown_fields_rejected() {
        let (kem_c, _, _) = mk_kem();
        let hello =
            Hello::new(kem_c, mk_nonce(), vec![mk_cap("EXEC"), mk_cap("TTY")], None).unwrap();
        let mut buf = Vec::new();
        into_writer(
            &HelloExtra {
                base: hello,
                xtra: 1,
            },
            &mut buf,
        )
        .unwrap();
        assert!(from_reader::<Hello, _>(Cursor::new(&buf)).is_err());
    }
}
