use crate::domain::handshake::params::{CERT_MAX, PAD_MAX};
use crate::domain::handshake::{HandshakeError, KemServerEphemeral, Nonce32};
use serde::{Deserialize, Serialize};

/// Server ACCEPT handshake message (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    pub kem_server_ephemeral: KemServerEphemeral,
    pub host_cert_chain: Vec<Vec<u8>>, // array even if length 1
    pub server_nonce: Nonce32,         // length == 32
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticket_params: Option<TicketParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_policy: Option<String>, // advisory; ignore if unknown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<Vec<u8>>,
}

impl Accept {
    /// Validate semantic invariants (non-empty cert chain, size limits, ticket params, pad size).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following invariants are violated:
    /// - Certificate chain is empty or contains an oversized certificate
    /// - Ticket lifetime is zero or max uses is not 1
    /// - Padding exceeds `PAD_MAX`
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.host_cert_chain.is_empty() {
            return Err(HandshakeError::AcceptEmptyCertChain);
        }
        if self.host_cert_chain.iter().any(|c| c.len() > CERT_MAX) {
            return Err(HandshakeError::AcceptCertTooLarge);
        }
        if let Some(tp) = &self.ticket_params {
            if tp.lifetime_s == 0 {
                return Err(HandshakeError::AcceptTicketLifetimeZero);
            }
            if tp.max_uses != 1 {
                return Err(HandshakeError::AcceptTicketMaxUsesInvalid);
            }
        }
        if let Some(p) = &self.pad
            && p.len() > PAD_MAX
        {
            return Err(HandshakeError::AcceptPadTooLarge);
        }
        Ok(())
    }

    /// Construct and validate an `Accept` message.
    ///
    /// # Errors
    ///
    /// Returns `Err` if semantic validation fails (see [`Accept::validate`]).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        kem_server_ephemeral: KemServerEphemeral,
        host_cert_chain: Vec<Vec<u8>>,
        server_nonce: Nonce32,
        ticket_params: Option<TicketParams>,
        revocation_policy: Option<String>,
        pad: Option<Vec<u8>>,
    ) -> Result<Self, HandshakeError> {
        let a = Accept {
            kem_server_ephemeral,
            host_cert_chain,
            server_nonce,
            ticket_params,
            revocation_policy,
            pad,
        };
        a.validate()?;
        Ok(a)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketParams {
    /// Lifetime of the ticket in seconds (must be > 0 in v1).
    pub lifetime_s: u64,
    /// Maximum permitted uses (must be 1 in v1 for strict replay semantics).
    pub max_uses: u8, // v1 expects 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::errors::HandshakeError;
    use crate::domain::handshake::params::{CERT_MAX, PAD_MAX};
    use crate::test_support::{mk_kem, mk_nonce};
    use ciborium::{de::from_reader, ser::into_writer};
    use std::io::Cursor;

    #[test]
    fn requires_non_empty_cert_chain() {
        let (_, kem_s, _) = mk_kem();
        assert!(matches!(
            Accept::new(kem_s, vec![], mk_nonce(), None, None, None),
            Err(HandshakeError::AcceptEmptyCertChain)
        ));
    }
    #[test]
    fn rejects_oversize_cert() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![vec![0u8; CERT_MAX + 1]];
        assert!(matches!(
            Accept::new(kem_s, chain, mk_nonce(), None, None, None),
            Err(HandshakeError::AcceptCertTooLarge)
        ));
    }
    #[test]
    fn ticket_param_checks() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![vec![1u8; 1]];
        let tp_zero = TicketParams {
            lifetime_s: 0,
            max_uses: 1,
        };
        assert!(matches!(
            Accept::new(
                kem_s.clone(),
                chain.clone(),
                mk_nonce(),
                Some(tp_zero),
                None,
                None
            ),
            Err(HandshakeError::AcceptTicketLifetimeZero)
        ));
        let tp_bad = TicketParams {
            lifetime_s: 10,
            max_uses: 2,
        };
        assert!(matches!(
            Accept::new(kem_s, chain, mk_nonce(), Some(tp_bad), None, None),
            Err(HandshakeError::AcceptTicketMaxUsesInvalid)
        ));
    }
    #[test]
    fn pad_over_max_errors() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![vec![1u8; 1]];
        let pad = Some(vec![0u8; PAD_MAX + 1]);
        assert!(matches!(
            Accept::new(kem_s, chain, mk_nonce(), None, None, pad),
            Err(HandshakeError::AcceptPadTooLarge)
        ));
    }
    #[test]
    fn ticket_and_boundary_pad_ok() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![vec![7u8; 42]];
        let tp = TicketParams {
            lifetime_s: 60,
            max_uses: 1,
        };
        let a = Accept::new(
            kem_s,
            chain,
            mk_nonce(),
            Some(tp),
            Some("OCSP_MUST_STAPLE".to_string()),
            Some(vec![1u8; PAD_MAX]),
        )
        .unwrap();
        assert_eq!(a.pad.unwrap().len(), PAD_MAX);
    }
    #[test]
    fn ticket_params_validity_ok() {
        let (_, kem_s, _) = mk_kem();
        let a = Accept::new(
            kem_s,
            vec![vec![1u8; 1]],
            mk_nonce(),
            Some(TicketParams {
                lifetime_s: 1,
                max_uses: 1,
            }),
            None,
            None,
        )
        .unwrap();
        assert!(a.ticket_params.is_some());
    }
    #[derive(serde::Serialize)]
    struct AcceptExtra {
        #[serde(flatten)]
        base: Accept,
        xtra: u8,
    }
    #[test]
    fn deny_unknown_fields_rejected() {
        let (_, kem_s, _) = mk_kem();
        let accept = Accept::new(kem_s, vec![vec![0u8; 1]], mk_nonce(), None, None, None).unwrap();
        let mut buf = Vec::new();
        into_writer(
            &AcceptExtra {
                base: accept,
                xtra: 1,
            },
            &mut buf,
        )
        .unwrap();
        assert!(from_reader::<Accept, _>(Cursor::new(&buf)).is_err());
    }
}
