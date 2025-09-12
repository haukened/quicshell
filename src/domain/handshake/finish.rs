use crate::domain::handshake::params::{AEAD_TAG_LEN, CERT_MAX, PAD_MAX};
use crate::domain::handshake::{HandshakeError, KemCiphertexts, UserAuth};
use serde::{Deserialize, Serialize};

/// Client `FINISH_CLIENT` handshake message (spec §5.1).
///
/// Carries hybrid KEM ciphertexts plus one of two user authentication forms:
/// raw public keys (with signatures) or a certificate chain (with signatures),
/// and an AEAD confirmation tag binding transcript and key schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishClient {
    /// Hybrid KEM ciphertext set (currently just ML-KEM-768).
    pub kem_ciphertexts: KemCiphertexts,
    /// Exactly one authentication form (`RawKeys` or `CertChain`).
    pub user_auth: UserAuth, // exactly one arm present
    /// AEAD confirmation tag verifying key schedule & transcript binding.
    /// AEAD confirmation tag (`AEAD_TAG_LEN` bytes) binding transcript & key schedule.
    pub client_confirm: Vec<u8>, // AEAD tag (length validated)
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional padding (random opaque bytes) excluded from transcript hash.
    pub pad: Option<Vec<u8>>,
}

impl FinishClient {
    /// Validate semantic invariants (cert chain content when present, AEAD tag length, pad size).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following invariants are violated:
    /// - Certificate chain is empty or contains an oversized certificate
    /// - AEAD confirmation tag length mismatch
    /// - Padding exceeds `PAD_MAX`
    pub fn validate(&self) -> Result<(), HandshakeError> {
        match &self.user_auth {
            UserAuth::RawKeys { raw_keys, sig } => {
                let _ = (raw_keys, sig); // lengths enforced by types
            }
            UserAuth::CertChain {
                user_cert_chain,
                sig,
            } => {
                if user_cert_chain.is_empty() {
                    return Err(HandshakeError::FinishClientCertChainEmpty);
                }
                if user_cert_chain.iter().any(|c| c.len() > CERT_MAX) {
                    return Err(HandshakeError::FinishClientCertTooLarge);
                }
                let _ = sig; // enforced by types
            }
        }
        if self.client_confirm.len() != AEAD_TAG_LEN {
            return Err(HandshakeError::LengthMismatch {
                field: "FINISH_CLIENT.client_confirm",
                expected: AEAD_TAG_LEN,
                actual: self.client_confirm.len(),
            });
        }
        if let Some(p) = &self.pad
            && p.len() > PAD_MAX
        {
            return Err(HandshakeError::FinishClientPadTooLarge);
        }

        Ok(())
    }

    /// Construct and validate a `FinishClient` message.
    ///
    /// # Errors
    ///
    /// Returns `Err` if semantic validation fails (see [`FinishClient::validate`]).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        kem_ciphertexts: KemCiphertexts,
        user_auth: UserAuth,
        client_confirm: Vec<u8>,
        pad: Option<Vec<u8>>,
    ) -> Result<Self, HandshakeError> {
        let fc = FinishClient {
            kem_ciphertexts,
            user_auth,
            client_confirm,
            pad,
        };
        fc.validate()?;
        Ok(fc)
    }
}

/// Server `FINISH_SERVER` handshake message (spec §5.1).
///
/// Contains the server AEAD confirmation tag and optionally a resumption ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishServer {
    /// Server AEAD confirmation tag (same length semantics as `client_confirm`).
    /// Server AEAD confirmation tag (`AEAD_TAG_LEN` bytes) mirroring the client tag semantics.
    pub server_confirm: Vec<u8>, // AEAD tag (length validated)
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional resumption ticket (opaque to client) enabling fast reconnect.
    pub resumption_ticket: Option<Vec<u8>>, // Stage 3 optional
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional padding (random opaque bytes) excluded from transcript hash.
    pub pad: Option<Vec<u8>>,
}

impl FinishServer {
    /// Validate semantic invariants (AEAD tag length, ticket non-empty, pad size).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following invariants are violated:
    /// - AEAD confirmation tag length mismatch
    /// - Resumption ticket is present but empty
    /// - Padding exceeds `PAD_MAX`
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.server_confirm.len() != AEAD_TAG_LEN {
            return Err(HandshakeError::LengthMismatch {
                field: "FINISH_SERVER.server_confirm",
                expected: AEAD_TAG_LEN,
                actual: self.server_confirm.len(),
            });
        }
        if let Some(t) = &self.resumption_ticket
            && t.is_empty()
        {
            return Err(HandshakeError::FinishServerTicketEmpty);
        }
        if let Some(p) = &self.pad
            && p.len() > PAD_MAX
        {
            return Err(HandshakeError::FinishServerPadTooLarge);
        }
        Ok(())
    }

    /// Construct and validate a `FinishServer` message.
    ///
    /// # Errors
    ///
    /// Returns `Err` if semantic validation fails (see [`FinishServer::validate`]).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        server_confirm: Vec<u8>,
        resumption_ticket: Option<Vec<u8>>,
        pad: Option<Vec<u8>>,
    ) -> Result<Self, HandshakeError> {
        let fs = FinishServer {
            server_confirm,
            resumption_ticket,
            pad,
        };
        fs.validate()?;
        Ok(fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::handshake::errors::HandshakeError;
    use crate::domain::handshake::params::{AEAD_TAG_LEN, CERT_MAX, PAD_MAX};
    use crate::test_support::mk_kem;
    use crate::test_support::mk_keys;
    use ciborium::{de::from_reader, ser::into_writer};
    use std::io::Cursor;

    // FinishClient tests
    #[test]
    fn cert_chain_error_cases() {
        let (_, _, kem_ct) = mk_kem();
        let (_, sig) = mk_keys();
        let confirm = vec![0u8; AEAD_TAG_LEN];
        let ua_empty = UserAuth::CertChain {
            user_cert_chain: vec![],
            sig: sig.clone(),
        };
        assert!(matches!(
            FinishClient::new(kem_ct.clone(), ua_empty, confirm.clone(), None),
            Err(HandshakeError::FinishClientCertChainEmpty)
        ));
        let ua_big = UserAuth::CertChain {
            user_cert_chain: vec![vec![0u8; CERT_MAX + 1]],
            sig,
        };
        assert!(matches!(
            FinishClient::new(kem_ct, ua_big, confirm, None),
            Err(HandshakeError::FinishClientCertTooLarge)
        ));
    }
    #[test]
    fn aead_tag_length_checks_client() {
        let (_, _, kem_ct) = mk_kem();
        let (raw_keys, sig) = mk_keys();
        let ua = UserAuth::RawKeys { raw_keys, sig };
        assert!(matches!(
            FinishClient::new(
                kem_ct.clone(),
                ua.clone(),
                vec![0u8; AEAD_TAG_LEN - 1],
                None
            ),
            Err(HandshakeError::LengthMismatch { .. })
        ));
        assert!(FinishClient::new(kem_ct, ua, vec![0u8; AEAD_TAG_LEN], None).is_ok());
    }
    #[test]
    fn pad_over_max_errors_client() {
        let (_, _, kem_ct) = mk_kem();
        let (raw_keys, sig) = mk_keys();
        let ua = UserAuth::RawKeys { raw_keys, sig };
        let pad = Some(vec![0u8; PAD_MAX + 1]);
        assert!(matches!(
            FinishClient::new(kem_ct, ua, vec![0u8; AEAD_TAG_LEN], pad),
            Err(HandshakeError::FinishClientPadTooLarge)
        ));
    }
    #[test]
    fn cert_chain_success_with_pad_boundary_client() {
        let (_, _, kem_ct) = mk_kem();
        let (_, sig) = mk_keys();
        let ua = UserAuth::CertChain {
            user_cert_chain: vec![vec![3u8; 10]],
            sig,
        };
        let fc = FinishClient::new(
            kem_ct,
            ua,
            vec![0u8; AEAD_TAG_LEN],
            Some(vec![9u8; PAD_MAX]),
        )
        .unwrap();
        assert_eq!(fc.client_confirm.len(), AEAD_TAG_LEN);
        assert_eq!(fc.pad.unwrap().len(), PAD_MAX);
    }

    // FinishServer tests
    #[test]
    fn aead_tag_length_checks_server() {
        assert!(matches!(
            FinishServer::new(vec![0u8; AEAD_TAG_LEN - 1], None, None),
            Err(HandshakeError::LengthMismatch { .. })
        ));
        assert!(FinishServer::new(vec![0u8; AEAD_TAG_LEN], None, None).is_ok());
    }
    #[test]
    fn ticket_non_empty_when_present_server() {
        assert!(matches!(
            FinishServer::new(vec![0u8; AEAD_TAG_LEN], Some(vec![]), None),
            Err(HandshakeError::FinishServerTicketEmpty)
        ));
    }
    #[test]
    fn pad_over_max_errors_server() {
        assert!(matches!(
            FinishServer::new(vec![0u8; AEAD_TAG_LEN], None, Some(vec![0u8; PAD_MAX + 1])),
            Err(HandshakeError::FinishServerPadTooLarge)
        ));
    }
    #[test]
    fn success_with_ticket_and_boundary_pad_server() {
        let ticket = vec![5u8; 8];
        let fs = FinishServer::new(
            vec![0u8; AEAD_TAG_LEN],
            Some(ticket.clone()),
            Some(vec![6u8; PAD_MAX]),
        )
        .unwrap();
        assert_eq!(fs.server_confirm.len(), AEAD_TAG_LEN);
        assert_eq!(fs.resumption_ticket.unwrap(), ticket);
    }
    #[derive(serde::Serialize)]
    struct FinishClientExtra {
        #[serde(flatten)]
        base: FinishClient,
        xtra: u8,
    }
    #[derive(serde::Serialize)]
    struct FinishServerExtra {
        #[serde(flatten)]
        base: FinishServer,
        xtra: u8,
    }
    #[test]
    fn deny_unknown_fields_rejected_finish_messages() {
        let (_, _, kem_ct) = mk_kem();
        let (raw_keys, sig) = mk_keys();
        let fc = FinishClient::new(
            kem_ct,
            UserAuth::RawKeys { raw_keys, sig },
            vec![0u8; AEAD_TAG_LEN],
            None,
        )
        .unwrap();
        let mut buf = Vec::new();
        into_writer(&FinishClientExtra { base: fc, xtra: 1 }, &mut buf).unwrap();
        assert!(from_reader::<FinishClient, _>(Cursor::new(&buf)).is_err());
        let fs = FinishServer::new(vec![0u8; AEAD_TAG_LEN], None, None).unwrap();
        let mut buf2 = Vec::new();
        into_writer(&FinishServerExtra { base: fs, xtra: 1 }, &mut buf2).unwrap();
        assert!(from_reader::<FinishServer, _>(Cursor::new(&buf2)).is_err());
    }
}
