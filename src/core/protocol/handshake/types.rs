//! Handshake message type definitions for qsh v1 (spec §5.1).
//!
//! This module defines the CBOR-serializable structures exchanged during the
//! four‑message handshake:
//! `HELLO -> ACCEPT -> FINISH_CLIENT -> FINISH_SERVER`.
//!
//! Goals:
//! * Enforce wire‑format length invariants at the type level where practical (fixed-size
//!   newtypes for nonces, public keys, ciphertexts, signatures).
//! * Provide explicit, typed validation errors via `HandshakeError` for semantic checks
//!   not encoded in the Rust type system (capability ordering, certificate list bounds, etc.).
//! * Keep defensive size limits private constants while documenting their intent.
//!
//! Notes:
//! * Padding fields (`pad`) are excluded from any future transcript hash (per spec rationale).
//! * Baseline capabilities `EXEC` and `TTY` are mandatory and validated.
//! * AEAD confirmation tags (`client_confirm`, `server_confirm`) are fixed to `AEAD_TAG_LEN` (=16) bytes.
//! * No private / secret key material is represented here; zeroization is not required.
//! * `UserAuth` is currently an untagged enum and will gain a custom deserializer to reject
//!   ambiguous inputs (see backlog Phase 5).
//!
//! Future (backlog):
//! * Generic length error consolidation.
//! * Capability newtype and manual `UserAuth` deserialization.
//! * Additional ergonomic constructors and examples.
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ---- Spec-bound size constants (v1 parameter set) ----
/// Fixed sizes derived from the qsh v1 handshake parameter set. These are
/// enforced either by newtypes (preferred) or by validation logic until all
/// fields are migrated.
const NONCE_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;
const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const MLKEM768_PK_LEN: usize = 1184; // Kyber/ML-KEM-768 public key size
const MLKEM768_CT_LEN: usize = 1088; // Kyber/ML-KEM-768 ciphertext size
const MLDSA44_PK_LEN: usize = 1312; // Dilithium/ML-DSA-44 public key size
const MLDSA44_SIG_LEN: usize = 2420; // Dilithium/ML-DSA-44 signature size
const AEAD_TAG_LEN: usize = 16; // AES-GCM and ChaCha20-Poly1305 tag size
const PAD_MAX: usize = 1024; // defensive bound for pad
const CERT_MAX: usize = 16 * 1024; // defensive bound per certificate blob
const CAP_TOKEN_MAX: usize = 16; // max capability token length
const CAP_COUNT_MAX: usize = 16; // max number of capability tokens

/// ---- Domain error type (idiomatic, typed) ----
/// Captures semantic validation failures discovered post-deserialization.
/// Many length checks will disappear once all variable `Vec<u8>` fields are
/// replaced by fixed-size newtypes.
#[derive(Debug, Error)]
pub enum HandshakeError {
    // HELLO
    /// Protocol version field in `HELLO` was not `1`.
    #[error("HELLO.v must be 1")]
    HelloBadVersion,
    /// Client nonce length mismatch (should be enforced by type; legacy path).
    #[error("HELLO.client_nonce must be {expected} bytes, got {actual}")]
    HelloBadNonce { expected: usize, actual: usize },
    /// X25519 ephemeral public key wrong length (will be removed after newtype rollout).
    #[error("HELLO.kem_client_ephemeral.x25519_pub must be 32 bytes")]
    HelloBadX25519,
    /// ML-KEM-768 ephemeral public key wrong length (will be removed after newtype rollout).
    #[error("HELLO.kem_client_ephemeral.mlkem_pub must be 1184 bytes (ML-KEM-768)")]
    HelloBadMlkemPub,
    /// Capability token formatting invalid OR mandatory baseline missing.
    #[error("HELLO.capabilities must be UPPERCASE ASCII tokens (A-Z, 0-9, _) ≤16 bytes")]
    HelloBadCapsFormat,
    /// Capability list not strictly lexicographic or exceeds count limit.
    #[error("HELLO.capabilities must be lexicographic, strictly increasing (no duplicates) and ≤16 entries")]
    HelloBadCapsOrder,
    /// Padding exceeded defensive size bound.
    #[error("HELLO.pad too large")]
    HelloPadTooLarge,

    // ACCEPT
    /// Server nonce length mismatch (legacy, retained until full newtype adoption in all code paths).
    #[error("ACCEPT.server_nonce must be 32 bytes")]
    AcceptBadNonce,
    /// Server ephemeral X25519 public key wrong length.
    #[error("ACCEPT.kem_server_ephemeral.x25519_pub must be 32 bytes")]
    AcceptBadX25519,
    /// Server ephemeral ML-KEM-768 public key wrong length.
    #[error("ACCEPT.kem_server_ephemeral.mlkem_pub must be 1184 bytes (ML-KEM-768)")]
    AcceptBadMlkemPub,
    /// Empty server certificate chain.
    #[error("ACCEPT.host_cert_chain must contain at least one element")]
    AcceptEmptyCertChain,
    /// A server certificate exceeded the defensive size bound.
    #[error("ACCEPT.host_cert_chain element too large")]
    AcceptCertTooLarge,
    /// Ticket lifetime was zero.
    #[error("ACCEPT.ticket_params.lifetime_s must be > 0")]
    AcceptTicketLifetimeZero,
    /// Ticket max uses was not 1 (v1 restriction).
    #[error("ACCEPT.ticket_params.max_uses must be 1 in v1")]
    AcceptTicketMaxUsesInvalid,
    /// ACCEPT padding exceeded defensive size bound.
    #[error("ACCEPT.pad too large")]
    AcceptPadTooLarge,

    // FINISH_CLIENT
    /// Hybrid KEM ML-KEM-768 ciphertext wrong length.
    #[error("FINISH_CLIENT.kem_ciphertexts.mlkem_ct must be 1088 bytes (ML-KEM-768)")]
    FinishClientBadMlkemCt,
    /// Ed25519 public key length invalid (raw key auth path).
    #[error("FINISH_CLIENT.ed25519_pub must be 32 bytes")]
    FinishClientRawEd25519PubLen,
    /// ML-DSA-44 public key length invalid (raw key auth path).
    #[error("FINISH_CLIENT.mldsa44_pub must be 1312 bytes")]
    FinishClientRawMldsaPubLen,
    /// Ed25519 signature length invalid.
    #[error("FINISH_CLIENT.sig.ed25519 must be 64 bytes")]
    FinishClientSigEd25519Len,
    /// ML-DSA-44 signature length invalid.
    #[error("FINISH_CLIENT.sig.mldsa44 must be 2420 bytes")]
    FinishClientSigMldsaLen,
    /// User certificate chain was empty.
    #[error("FINISH_CLIENT.user_cert_chain must have ≥1 cert")]
    FinishClientCertChainEmpty,
    /// A user certificate exceeded defensive size bound.
    #[error("FINISH_CLIENT.user_cert_chain element too large")]
    FinishClientCertTooLarge,
    /// One or both hybrid signature component lengths invalid.
    #[error("FINISH_CLIENT.hybrid signature lengths invalid")]
    FinishClientHybridSigLens,
    /// AEAD confirmation tag length mismatch.
    #[error("FINISH_CLIENT.client_confirm (AEAD tag) wrong length (expected 16)")]
    FinishClientConfirmLen,
    /// FINISH_CLIENT padding exceeded defensive size bound.
    #[error("FINISH_CLIENT.pad too large")]
    FinishClientPadTooLarge,

    // FINISH_SERVER
    /// Server AEAD confirmation tag length invalid.
    #[error("FINISH_SERVER.server_confirm (AEAD tag) must not be empty")]
    FinishServerConfirmLen,
    /// Present resumption ticket was empty.
    #[error("FINISH_SERVER.resumption_ticket must not be empty when present")]
    FinishServerTicketEmpty,
    /// FINISH_SERVER padding exceeded defensive size bound.
    #[error("FINISH_SERVER.pad too large")]
    FinishServerPadTooLarge,
    // Generic / future use
    /// Ambiguous user auth object contained both raw keys and certificate chain.
    #[error("USER_AUTH object contains both raw_keys and user_cert_chain (ambiguous)")]
    UserAuthAmbiguous,
}

// ---- Helper validation functions ----

/// Checks if a string is a valid ASCII uppercase token.
fn is_ascii_upper_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= CAP_TOKEN_MAX
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

/// Capability token (validated UPPERCASE ASCII, length 1..=CAP_TOKEN_MAX).
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
    pub fn as_str(&self) -> &str { &self.0 }
}
impl fmt::Debug for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Capability({})", self.0) }
}
impl From<Capability> for String { fn from(c: Capability) -> Self { c.0 } }
impl Serialize for Capability {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&self.0) }
}
impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(d)?;
        if !is_ascii_upper_token(s) { return Err(serde::de::Error::custom("invalid capability token")); }
        Ok(Capability(s.to_string()))
    }
}

/// Checks if a vector of strings is lexicographically ordered without duplicates and within count limit.
fn is_lexicographic_no_dups(v: &[String]) -> bool {
    if v.len() > CAP_COUNT_MAX {
        return false;
    }
    v.windows(2).all(|w| w[0] < w[1]) // strict increasing ⇒ sorted & no dups
}

// Handshake messages for qsh v1 (spec §5.1).
//
// **Lifecycle:**
// HELLO (client→server) → ACCEPT (server→client) → FINISH_CLIENT (client→server) → FINISH_SERVER (server→client).
// The FINISH_* pair completes the **handshake** (mutual auth + key confirmation). The **session** starts *after* FINISH_SERVER is verified.
// Channels and rekeys operate within the established session; they do **not** re‑authenticate the user.


/// 32-byte nonce used in `HELLO.client_nonce` and `ACCEPT.server_nonce`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nonce32(pub [u8; NONCE_LEN]);
impl fmt::Debug for Nonce32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce32(..)")
    }
}
impl Nonce32 {
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// X25519 public key (fixed 32 bytes) used in hybrid KEM ephemeral key pairs.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct X25519Pub(pub [u8; X25519_PK_LEN]);
impl fmt::Debug for X25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519Pub(..)")
    }
}
impl X25519Pub {
    pub fn as_bytes(&self) -> &[u8; X25519_PK_LEN] {
        &self.0
    }
}

/// ML-KEM-768 public key (1184 bytes) used in hybrid KEM ephemeral key pairs.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mlkem768Pub(pub [u8; MLKEM768_PK_LEN]);
impl fmt::Debug for Mlkem768Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Pub(..)")
    }
}
impl Mlkem768Pub {
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PK_LEN] {
        &self.0
    }
}

/// ML-KEM-768 ciphertext (1088 bytes) produced by encapsulation in FINISH_CLIENT.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mlkem768Ciphertext(pub [u8; MLKEM768_CT_LEN]);
impl fmt::Debug for Mlkem768Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Ciphertext(..)")
    }
}
impl Mlkem768Ciphertext {
    pub fn as_bytes(&self) -> &[u8; MLKEM768_CT_LEN] {
        &self.0
    }
}

/// Ed25519 public key (32 bytes) for user authentication (raw key path).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519Pub(pub [u8; ED25519_PK_LEN]);
impl fmt::Debug for Ed25519Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Pub(..)")
    }
}
impl Ed25519Pub {
    pub fn as_bytes(&self) -> &[u8; ED25519_PK_LEN] {
        &self.0
    }
}

/// ML-DSA-44 (Dilithium level 2) public key (1312 bytes) for user authentication.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mldsa44Pub(pub [u8; MLDSA44_PK_LEN]);
impl fmt::Debug for Mldsa44Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Pub(..)")
    }
}
impl Mldsa44Pub {
    pub fn as_bytes(&self) -> &[u8; MLDSA44_PK_LEN] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ed25519Sig(pub [u8; ED25519_SIG_LEN]);
impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Sig(..)")
    }
}
impl Ed25519Sig {
    pub fn as_bytes(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.0
    }
}

/// ML-DSA-44 signature (2420 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Mldsa44Sig(pub [u8; MLDSA44_SIG_LEN]);
impl fmt::Debug for Mldsa44Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Sig(..)")
    }
}
impl Mldsa44Sig {
    pub fn as_bytes(&self) -> &[u8; MLDSA44_SIG_LEN] {
        &self.0
    }
}

/// Hybrid user authentication signature bundle (Ed25519 + ML-DSA-44).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSig {
    pub ed25519: Ed25519Sig,
    pub mldsa44: Mldsa44Sig,
}

/// Ephemeral hybrid KEM public keys sent by client in `HELLO`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemClientEphemeral {
    pub x25519_pub: X25519Pub,
    pub mlkem_pub: Mlkem768Pub,
}

/// Client `HELLO` handshake message (spec §5.1).
///
/// Contains the client's ephemeral hybrid KEM public keys, a fresh nonce,
/// and advisory capability tokens (must include baseline `EXEC` and `TTY`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.v != 1 {
            return Err(HandshakeError::HelloBadVersion);
        }
        // Baseline capabilities must be present
        if !(self.capabilities.iter().any(|c| c.as_str() == "EXEC")
            && self.capabilities.iter().any(|c| c.as_str() == "TTY")) {
            return Err(HandshakeError::HelloBadCapsFormat); // reuse variant per decision
        }
        // Enforce count + strict lexicographic increasing (no duplicates)
        if self.capabilities.len() > CAP_COUNT_MAX
            || self
                .capabilities
                .windows(2)
                .any(|w| !(w[0] < w[1]))
        {
            return Err(HandshakeError::HelloBadCapsOrder);
        }
        if let Some(p) = &self.pad {
            if p.len() > PAD_MAX {
                return Err(HandshakeError::HelloPadTooLarge);
            }
        }
        Ok(())
    }
}

/// Ephemeral hybrid KEM public keys sent by server in `ACCEPT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemServerEphemeral {
    pub x25519_pub: X25519Pub,
    pub mlkem_pub: Mlkem768Pub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketParams {
    /// Lifetime of the ticket in seconds (must be > 0 in v1).
    pub lifetime_s: u64,
    /// Maximum permitted uses (must be 1 in v1 for strict replay semantics).
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
        if let Some(p) = &self.pad {
            if p.len() > PAD_MAX {
                return Err(HandshakeError::AcceptPadTooLarge);
            }
        }
        Ok(())
    }
}

/// Hybrid KEM ciphertexts sent by client in `FINISH_CLIENT`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemCiphertexts {
    /// Hybrid KEM ML-KEM-768 ciphertext encapsulating shared secret material.
    pub mlkem_ct: Mlkem768Ciphertext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawKeys {
    /// User Ed25519 public key.
    pub ed25519_pub: Ed25519Pub,
    /// User ML-DSA-44 public key.
    pub mldsa44_pub: Mldsa44Pub,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserAuth {
    // { raw_keys: {ed25519_pub, mldsa44_pub}, sig: {ed25519, mldsa44} }
    #[serde(rename_all = "snake_case")]
    /// Direct raw key authentication: the client supplies public keys plus a hybrid signature.
    RawKeys { raw_keys: RawKeys, sig: HybridSig },
    // { user_cert_chain: [bstr,...], sig: {ed25519, mldsa44} }
    #[serde(rename_all = "snake_case")]
    /// Certificate chain based authentication (≥1 certificate) plus a hybrid signature.
    CertChain {
        /// Ordered chain (leaf first). Each element length bounded defensively.
        user_cert_chain: Vec<Vec<u8>>,
        /// Hybrid signature over transcript using keys in leaf cert.
        sig: HybridSig,
    },
}

/// Client `FINISH_CLIENT` handshake message (spec §5.1).
///
/// Carries hybrid KEM ciphertexts plus one of two user authentication forms:
/// raw public keys (with signatures) or a certificate chain (with signatures),
/// and an AEAD confirmation tag binding transcript and key schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishClient {
    /// Hybrid KEM ciphertext set (currently just ML-KEM-768).
    pub kem_ciphertexts: KemCiphertexts,
    /// Exactly one authentication form (`RawKeys` or `CertChain`).
    pub user_auth: UserAuth, // exactly one arm present
    /// AEAD confirmation tag verifying key schedule & transcript binding.
    pub client_confirm: Vec<u8>, // AEAD tag
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional padding (random opaque bytes) excluded from transcript hash.
    pub pad: Option<Vec<u8>>,
}

impl FinishClient {
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
            return Err(HandshakeError::FinishClientConfirmLen);
        }
        if let Some(p) = &self.pad {
            if p.len() > PAD_MAX {
                return Err(HandshakeError::FinishClientPadTooLarge);
            }
        }
        Ok(())
    }
}

/// Server `FINISH_SERVER` handshake message (spec §5.1).
///
/// Contains the server AEAD confirmation tag and optionally a resumption ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishServer {
    /// Server AEAD confirmation tag (same length semantics as client_confirm).
    pub server_confirm: Vec<u8>, // AEAD tag
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional resumption ticket (opaque to client) enabling fast reconnect.
    pub resumption_ticket: Option<Vec<u8>>, // Stage 3 optional
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional padding (random opaque bytes) excluded from transcript hash.
    pub pad: Option<Vec<u8>>,
}

impl FinishServer {
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.server_confirm.len() != AEAD_TAG_LEN {
            return Err(HandshakeError::FinishServerConfirmLen);
        }
        if let Some(t) = &self.resumption_ticket {
            if t.is_empty() {
                return Err(HandshakeError::FinishServerTicketEmpty);
            }
        }
        if let Some(p) = &self.pad {
            if p.len() > PAD_MAX {
                return Err(HandshakeError::FinishServerPadTooLarge);
            }
        }
        Ok(())
    }
}
