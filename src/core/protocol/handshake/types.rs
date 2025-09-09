use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---- Spec-bound size constants (v1 parameter set) ----
const NONCE_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;
const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const MLKEM768_PK_LEN: usize = 1184;   // Kyber/ML-KEM-768 public key size
const MLKEM768_CT_LEN: usize = 1088;   // Kyber/ML-KEM-768 ciphertext size
const MLDSA44_PK_LEN: usize = 1312;    // Dilithium/ML-DSA-44 public key size
const MLDSA44_SIG_LEN: usize = 2420;   // Dilithium/ML-DSA-44 signature size

const PAD_MAX: usize = 1024;           // defensive bound for pad
const CERT_MAX: usize = 16 * 1024;     // defensive bound per certificate blob
const CAP_TOKEN_MAX: usize = 16;       // max capability token length
const CAP_COUNT_MAX: usize = 16;       // max number of capability tokens

// ---- Domain error type (idiomatic, typed) ----
#[derive(Debug, Error)]
pub enum HandshakeError {
    // HELLO
    #[error("HELLO.v must be 1")]
    HelloBadVersion,
    #[error("HELLO.client_nonce must be {expected} bytes, got {actual}")]
    HelloBadNonce { expected: usize, actual: usize },
    #[error("HELLO.kem_client_ephemeral.x25519_pub must be 32 bytes")]
    HelloBadX25519,
    #[error("HELLO.kem_client_ephemeral.mlkem_pub must be 1184 bytes (ML-KEM-768)")]
    HelloBadMlkemPub,
    #[error("HELLO.capabilities must be UPPERCASE ASCII tokens (A-Z, 0-9, _) ≤16 bytes")]
    HelloBadCapsFormat,
    #[error("HELLO.capabilities must be lexicographic, strictly increasing (no duplicates) and ≤16 entries")]
    HelloBadCapsOrder,
    #[error("HELLO.pad too large")]
    HelloPadTooLarge,

    // ACCEPT
    #[error("ACCEPT.server_nonce must be 32 bytes")]
    AcceptBadNonce,
    #[error("ACCEPT.kem_server_ephemeral.x25519_pub must be 32 bytes")]
    AcceptBadX25519,
    #[error("ACCEPT.kem_server_ephemeral.mlkem_pub must be 1184 bytes (ML-KEM-768)")]
    AcceptBadMlkemPub,
    #[error("ACCEPT.host_cert_chain must contain at least one element")]
    AcceptEmptyCertChain,
    #[error("ACCEPT.host_cert_chain element too large")]
    AcceptCertTooLarge,
    #[error("ACCEPT.ticket_params.lifetime_s must be > 0")]
    AcceptTicketLifetimeZero,
    #[error("ACCEPT.ticket_params.max_uses must be 1 in v1")]
    AcceptTicketMaxUsesInvalid,
    #[error("ACCEPT.pad too large")]
    AcceptPadTooLarge,

    // FINISH_CLIENT
    #[error("FINISH_CLIENT.kem_ciphertexts.mlkem_ct must be 1088 bytes (ML-KEM-768)")]
    FinishClientBadMlkemCt,
    #[error("FINISH_CLIENT.ed25519_pub must be 32 bytes")]
    FinishClientRawEd25519PubLen,
    #[error("FINISH_CLIENT.mldsa44_pub must be 1312 bytes")]
    FinishClientRawMldsaPubLen,
    #[error("FINISH_CLIENT.sig.ed25519 must be 64 bytes")]
    FinishClientSigEd25519Len,
    #[error("FINISH_CLIENT.sig.mldsa44 must be 2420 bytes")]
    FinishClientSigMldsaLen,
    #[error("FINISH_CLIENT.user_cert_chain must have ≥1 cert")]
    FinishClientCertChainEmpty,
    #[error("FINISH_CLIENT.user_cert_chain element too large")]
    FinishClientCertTooLarge,
    #[error("FINISH_CLIENT.hybrid signature lengths invalid")]
    FinishClientHybridSigLens,
    #[error("FINISH_CLIENT.client_confirm (AEAD tag) must not be empty")]
    FinishClientConfirmEmpty,
    #[error("FINISH_CLIENT.pad too large")]
    FinishClientPadTooLarge,

    // FINISH_SERVER
    #[error("FINISH_SERVER.server_confirm (AEAD tag) must not be empty")]
    FinishServerConfirmEmpty,
    #[error("FINISH_SERVER.resumption_ticket must not be empty when present")]
    FinishServerTicketEmpty,
    #[error("FINISH_SERVER.pad too large")]
    FinishServerPadTooLarge,
}

// ---- Helper validation functions ----

/// Checks if a string is a valid ASCII uppercase token.
fn is_ascii_upper_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= CAP_TOKEN_MAX
        && s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

/// Checks if a vector of strings is lexicographically ordered without duplicates and within count limit.
fn is_lexicographic_no_dups(v: &[String]) -> bool {
    if v.len() > CAP_COUNT_MAX { return false; }
    v.windows(2).all(|w| w[0] < w[1]) // strict increasing ⇒ sorted & no dups
}

// Handshake messages for qsh v1 (spec §5.1).
//
// **Lifecycle:**
// HELLO (client→server) → ACCEPT (server→client) → FINISH_CLIENT (client→server) → FINISH_SERVER (server→client).
// The FINISH_* pair completes the **handshake** (mutual auth + key confirmation). The **session** starts *after* FINISH_SERVER is verified.
// Channels and rekeys operate within the established session; they do **not** re‑authenticate the user.

/// 32-byte nonce (validated by length checks).
pub type Nonce32 = Vec<u8>;

/// Hybrid signature bytes (Ed25519 + ML-DSA-44)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSig {
    pub ed25519: Vec<u8>,
    pub mldsa44: Vec<u8>,
}

/// Ephemeral hybrid KEM public keys sent by client in HELLO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemClientEphemeral {
    pub x25519_pub: Vec<u8>,
    pub mlkem_pub: Vec<u8>,
}

/// Client HELLO handshake message (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version (must be 1)
    pub v: u8,
    /// Client's ephemeral KEM public keys
    pub kem_client_ephemeral: KemClientEphemeral,
    /// Randomly generated client nonce (length == 32)
    pub client_nonce: Nonce32,
    /// Advisory capability tokens (ASCII UPPERCASE, lexicographic)
    pub capabilities: Vec<String>,
    /// Optional padding (excluded from transcript hash)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<Vec<u8>>,
}

impl Hello {
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.v != 1 { return Err(HandshakeError::HelloBadVersion); }
        if self.client_nonce.len() != NONCE_LEN {
            return Err(HandshakeError::HelloBadNonce { expected: NONCE_LEN, actual: self.client_nonce.len() });
        }
        if self.kem_client_ephemeral.x25519_pub.len() != X25519_PK_LEN {
            return Err(HandshakeError::HelloBadX25519);
        }
        if self.kem_client_ephemeral.mlkem_pub.len() != MLKEM768_PK_LEN {
            return Err(HandshakeError::HelloBadMlkemPub);
        }
        if self.capabilities.is_empty() || !self.capabilities.iter().all(|c| is_ascii_upper_token(c)) {
            return Err(HandshakeError::HelloBadCapsFormat);
        }
        if !is_lexicographic_no_dups(&self.capabilities) {
            return Err(HandshakeError::HelloBadCapsOrder);
        }
        if let Some(p) = &self.pad { if p.len() > PAD_MAX { return Err(HandshakeError::HelloPadTooLarge); } }
        Ok(())
    }
}

/// Ephemeral hybrid KEM public keys sent by server in ACCEPT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemServerEphemeral {
    pub x25519_pub: Vec<u8>,
    pub mlkem_pub: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketParams {
    pub lifetime_s: u64,
    pub max_uses: u8, // v1 expects 1
}

/// Server ACCEPT handshake message (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.server_nonce.len() != NONCE_LEN { return Err(HandshakeError::AcceptBadNonce); }
        if self.kem_server_ephemeral.x25519_pub.len() != X25519_PK_LEN {
            return Err(HandshakeError::AcceptBadX25519);
        }
        if self.kem_server_ephemeral.mlkem_pub.len() != MLKEM768_PK_LEN {
            return Err(HandshakeError::AcceptBadMlkemPub);
        }
        if self.host_cert_chain.is_empty() { return Err(HandshakeError::AcceptEmptyCertChain); }
        if self.host_cert_chain.iter().any(|c| c.len() > CERT_MAX) { return Err(HandshakeError::AcceptCertTooLarge); }
        if let Some(tp) = &self.ticket_params {
            if tp.lifetime_s == 0 { return Err(HandshakeError::AcceptTicketLifetimeZero); }
            if tp.max_uses != 1 { return Err(HandshakeError::AcceptTicketMaxUsesInvalid); }
        }
        if let Some(p) = &self.pad { if p.len() > PAD_MAX { return Err(HandshakeError::AcceptPadTooLarge); } }
        Ok(())
    }
}

/// Hybrid KEM ciphertexts sent by client in FINISH_CLIENT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemCiphertexts {
    pub mlkem_ct: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawKeys {
    pub ed25519_pub: Vec<u8>,
    pub mldsa44_pub: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserAuth {
    // { raw_keys: {ed25519_pub, mldsa44_pub}, sig: {ed25519, mldsa44} }
    #[serde(rename_all = "snake_case")]
    RawKeys { raw_keys: RawKeys, sig: HybridSig },
    // { user_cert_chain: [bstr,...], sig: {ed25519, mldsa44} }
    #[serde(rename_all = "snake_case")]
    CertChain { user_cert_chain: Vec<Vec<u8>>, sig: HybridSig },
}

/// Client FINISH_CLIENT handshake message (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishClient {
    pub kem_ciphertexts: KemCiphertexts,
    pub user_auth: UserAuth,     // exactly one arm present
    pub client_confirm: Vec<u8>, // AEAD tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<Vec<u8>>,
}

impl FinishClient {
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.kem_ciphertexts.mlkem_ct.len() != MLKEM768_CT_LEN {
            return Err(HandshakeError::FinishClientBadMlkemCt);
        }
        match &self.user_auth {
            UserAuth::RawKeys { raw_keys, sig } => {
                if raw_keys.ed25519_pub.len() != ED25519_PK_LEN { return Err(HandshakeError::FinishClientRawEd25519PubLen); }
                if raw_keys.mldsa44_pub.len() != MLDSA44_PK_LEN { return Err(HandshakeError::FinishClientRawMldsaPubLen); }
                if sig.ed25519.len() != ED25519_SIG_LEN { return Err(HandshakeError::FinishClientSigEd25519Len); }
                if sig.mldsa44.len() != MLDSA44_SIG_LEN { return Err(HandshakeError::FinishClientSigMldsaLen); }
            }
            UserAuth::CertChain { user_cert_chain, sig } => {
                if user_cert_chain.is_empty() { return Err(HandshakeError::FinishClientCertChainEmpty); }
                if user_cert_chain.iter().any(|c| c.len() > CERT_MAX) { return Err(HandshakeError::FinishClientCertTooLarge); }
                if sig.ed25519.len() != ED25519_SIG_LEN || sig.mldsa44.len() != MLDSA44_SIG_LEN {
                    return Err(HandshakeError::FinishClientHybridSigLens);
                }
            }
        }
        if self.client_confirm.is_empty() { return Err(HandshakeError::FinishClientConfirmEmpty); }
        if let Some(p) = &self.pad { if p.len() > PAD_MAX { return Err(HandshakeError::FinishClientPadTooLarge); } }
        Ok(())
    }
}

/// Server FINISH_SERVER handshake message (spec §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishServer {
    pub server_confirm: Vec<u8>, // AEAD tag
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resumption_ticket: Option<Vec<u8>>, // Stage 3 optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pad: Option<Vec<u8>>,
}

impl FinishServer {
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.server_confirm.is_empty() { return Err(HandshakeError::FinishServerConfirmEmpty); }
        if let Some(t) = &self.resumption_ticket { if t.is_empty() { return Err(HandshakeError::FinishServerTicketEmpty); } }
        if let Some(p) = &self.pad { if p.len() > PAD_MAX { return Err(HandshakeError::FinishServerPadTooLarge); } }
        Ok(())
    }
}
