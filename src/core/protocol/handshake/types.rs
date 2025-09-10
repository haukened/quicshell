/*!
`Handshake` message type definitions for `qsh` v1 (spec §5.1).

This module is the single source of truth for the wire schema of the
four‑message handshake.
It intentionally keeps **all secret material out** (only public keys,
signatures, ciphertexts, nonces, and advisory metadata) so zeroization is
not required for the types themselves.

This module defines the CBOR-serializable structures exchanged during the
four‑message handshake:
`HELLO -> ACCEPT -> FINISH_CLIENT -> FINISH_SERVER`.

Goals:
* Enforce wire‑format length invariants at the type level where practical (fixed-size newtypes for nonces, public keys, ciphertexts, signatures).
* Provide explicit, typed validation errors via [`HandshakeError`] for semantic checks not encoded in the Rust type system (capability ordering, certificate list bounds, etc.).
* Keep defensive size limits private constants while documenting their intent.

Notes:
* Padding fields ([`pad`]) are excluded from any future transcript hash (per spec rationale).
* Baseline capabilities [`EXEC`] and [`TTY`] are mandatory and validated.
* AEAD confirmation tags ([`client_confirm`], [`server_confirm`]) are fixed to [`AEAD_TAG_LEN`] (=16) bytes.
* No private / secret key material is represented here; zeroization is not required.
* [`UserAuth`] uses a custom deserializer to reject ambiguous inputs containing both [`raw_keys`] and [`user_cert_chain`] (emits [`HandshakeError::UserAuthAmbiguous`]).

Future (backlog):
* Generic length error consolidation. (Partially complete: [`LengthMismatch`].)
* Additional ergonomic constructors and examples (selected constructors added).

# Example (constructing a minimal [`Hello`])
```ignore
use quicshell::core::protocol::handshake::types::{
        Hello, KemClientEphemeral, X25519Pub, Mlkem768Pub, Nonce32, Capability
};
// Dummy zeroed values for illustration ONLY – real code must use cryptographically
// secure randomness / proper key generation.
let kem = KemClientEphemeral { x25519_pub: X25519Pub([0;32]), mlkem_pub: Mlkem768Pub([0;1184]) };
let nonce = Nonce32([0;32]);
let caps = vec![Capability::parse("EXEC").unwrap(), Capability::parse("TTY").unwrap()];
// Calling the [`new`] constructor validates the message immediately.
let h_res = Hello::new(kem, nonce, caps, None);
match h_res {
        Ok(h) => println!("Constructed valid Hello: {:?}", h),
        Err(e) => eprintln!("Failed to construct Hello: {}", e),
}
```
*/

use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ---- Spec-bound size & defensive constants (v1 parameter set) ----
/// Fixed sizes derived from the qsh v1 parameter set. Enforced at the type level
/// (preferred) via newtypes. Defensive maxima (`*_MAX`) are NOT wire commitments;
/// they bound resource usage and may change in a subsequent major version.
///
/// Baseline capabilities (`EXEC`, `TTY`) are validated at runtime; AEAD tag
/// length is fixed (`AEAD_TAG_LEN`) and enforced with `LengthMismatch`.
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

// Manual serde needed for arrays > 32 bytes (serde derives only auto-impl up to 32 for generic T arrays).
// Provide a helper macro to reduce repetition across large fixed-size byte newtypes.
macro_rules! impl_large_array_newtype_serde {
    ($name:ident, $len_const:ident) => {
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                // Serialize as a CBOR / Serde bytes string, not a sequence of u8.
                s.serialize_bytes(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V<const N: usize>;
                impl<'de, const N: usize> serde::de::Visitor<'de> for V<N> {
                    type Value = [u8; N];
                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(f, "byte string of length {}", N)
                    }
                    fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                        if v.len() != N {
                            return Err(E::invalid_length(v.len(), &self));
                        }
                        let mut a = [0u8; N];
                        a.copy_from_slice(v);
                        Ok(a)
                    }
                    fn visit_seq<A: serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: A,
                    ) -> Result<Self::Value, A::Error> {
                        let mut a = [0u8; N];
                        let mut i = 0;
                        while let Some(byte) = seq.next_element::<u8>()? {
                            if i >= N {
                                return Err(serde::de::Error::invalid_length(i, &self));
                            }
                            a[i] = byte;
                            i += 1;
                        }
                        if i != N {
                            return Err(serde::de::Error::invalid_length(i, &self));
                        }
                        Ok(a)
                    }
                }
                let arr = d.deserialize_bytes(V::<{ $len_const }>)?;
                Ok($name(arr))
            }
        }
    };
}

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
    /// User certificate chain was empty.
    #[error("FINISH_CLIENT.user_cert_chain must have ≥1 cert")]
    FinishClientCertChainEmpty,
    /// A user certificate exceeded defensive size bound.
    #[error("FINISH_CLIENT.user_cert_chain element too large")]
    FinishClientCertTooLarge,
    /// `FINISH_CLIENT` padding exceeded defensive size bound.
    #[error("FINISH_CLIENT.pad too large")]
    FinishClientPadTooLarge,

    // FINISH_SERVER
    /// Present resumption ticket was empty.
    #[error("FINISH_SERVER.resumption_ticket must not be empty when present")]
    FinishServerTicketEmpty,
    /// `FINISH_SERVER` padding exceeded defensive size bound.
    #[error("FINISH_SERVER.pad too large")]
    FinishServerPadTooLarge,
    // Generic / future use
    /// Ambiguous user auth object contained both raw keys and certificate chain.
    #[error("USER_AUTH object contains both raw_keys and user_cert_chain (ambiguous)")]
    UserAuthAmbiguous,
    /// Generic field length mismatch (unifies prior specific length variants).
    #[error("{field} length mismatch: expected {expected}, got {actual}")]
    LengthMismatch {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

// ---- Helper validation functions ----

/// Checks if a string is a valid ASCII uppercase token.
fn is_ascii_upper_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= CAP_TOKEN_MAX
        && s.bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

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
        let s = <&str>::deserialize(d)?;
        if !is_ascii_upper_token(s) {
            return Err(serde::de::Error::custom("invalid capability token"));
        }
        Ok(Capability(s.to_string()))
    }
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
    /// Access the inner byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Create a `Nonce32` from a byte slice, validating length.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the input slice length does not match `NONCE_LEN`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, HandshakeError> {
        if b.len() != NONCE_LEN {
            return Err(HandshakeError::LengthMismatch {
                field: "Nonce32",
                expected: NONCE_LEN,
                actual: b.len(),
            });
        }
        let mut arr = [0u8; NONCE_LEN];
        arr.copy_from_slice(b);
        Ok(Nonce32(arr))
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
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; X25519_PK_LEN] {
        &self.0
    }
}

/// ML-KEM-768 public key (1184 bytes) used in hybrid KEM ephemeral key pairs.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mlkem768Pub(pub [u8; MLKEM768_PK_LEN]);
impl fmt::Debug for Mlkem768Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Pub(..)")
    }
}
impl Mlkem768Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLKEM768_PK_LEN] {
        &self.0
    }
}

/// ML-KEM-768 ciphertext (1088 bytes) produced by encapsulation in `FINISH_CLIENT`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mlkem768Ciphertext(pub [u8; MLKEM768_CT_LEN]);
impl fmt::Debug for Mlkem768Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mlkem768Ciphertext(..)")
    }
}
impl Mlkem768Ciphertext {
    #[must_use]
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
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PK_LEN] {
        &self.0
    }
}

/// ML-DSA-44 (Dilithium level 2) public key (1312 bytes) for user authentication.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mldsa44Pub(pub [u8; MLDSA44_PK_LEN]);
impl fmt::Debug for Mldsa44Pub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Pub(..)")
    }
}
impl Mldsa44Pub {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA44_PK_LEN] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Ed25519Sig(pub [u8; ED25519_SIG_LEN]);
impl fmt::Debug for Ed25519Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Sig(..)")
    }
}
impl Ed25519Sig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.0
    }
}

/// ML-DSA-44 signature (2420 bytes) over the transcript (hybrid user auth path).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Mldsa44Sig(pub [u8; MLDSA44_SIG_LEN]);
impl fmt::Debug for Mldsa44Sig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mldsa44Sig(..)")
    }
}
impl Mldsa44Sig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA44_SIG_LEN] {
        &self.0
    }
}

// Apply manual serde impl macro for large arrays (>32 bytes; serde derive covers up to 32 only).
impl_large_array_newtype_serde!(Mlkem768Pub, MLKEM768_PK_LEN);
impl_large_array_newtype_serde!(Mlkem768Ciphertext, MLKEM768_CT_LEN);
impl_large_array_newtype_serde!(Mldsa44Pub, MLDSA44_PK_LEN);
impl_large_array_newtype_serde!(Ed25519Sig, ED25519_SIG_LEN);
impl_large_array_newtype_serde!(Mldsa44Sig, MLDSA44_SIG_LEN);

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UserAuth {
    /// Direct raw key authentication: the client supplies public keys plus a hybrid signature.
    RawKeys {
        raw_keys: Box<RawKeys>,
        sig: Box<HybridSig>,
    },
    /// Certificate chain based authentication (≥1 certificate) plus a hybrid signature.
    CertChain {
        user_cert_chain: Vec<Vec<u8>>,
        sig: Box<HybridSig>,
    },
}

impl<'de> Deserialize<'de> for UserAuth {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use serde::de::{Error as DeError, MapAccess, Visitor};

        struct UAuthVisitor(PhantomData<()>);
        impl<'de> Visitor<'de> for UAuthVisitor {
            type Value = UserAuth;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "user_auth object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut raw_keys: Option<RawKeys> = None;
                let mut user_cert_chain: Option<Vec<Vec<u8>>> = None;
                let mut sig: Option<HybridSig> = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "raw_keys" => {
                            if raw_keys.is_some() {
                                return Err(A::Error::custom("duplicate raw_keys"));
                            }
                            let inner: RawKeys = map.next_value()?;
                            raw_keys = Some(inner);
                        }
                        "user_cert_chain" => {
                            if user_cert_chain.is_some() {
                                return Err(A::Error::custom("duplicate user_cert_chain"));
                            }
                            let chain: Vec<Vec<u8>> = map.next_value()?;
                            user_cert_chain = Some(chain);
                        }
                        "sig" => {
                            if sig.is_some() {
                                return Err(A::Error::custom("duplicate sig"));
                            }
                            sig = Some(map.next_value()?);
                        }
                        // Ignore unknown keys for forward compatibility
                        _ => {
                            let _ignored: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                if raw_keys.is_some() && user_cert_chain.is_some() {
                    return Err(A::Error::custom(
                        "USER_AUTH object contains both raw_keys and user_cert_chain (ambiguous)",
                    ));
                }
                let sig = sig.ok_or_else(|| A::Error::custom("missing sig"))?;
                if let Some(rk) = raw_keys {
                    return Ok(UserAuth::RawKeys {
                        raw_keys: Box::new(rk),
                        sig: Box::new(sig),
                    });
                }
                if let Some(chain) = user_cert_chain {
                    return Ok(UserAuth::CertChain {
                        user_cert_chain: chain,
                        sig: Box::new(sig),
                    });
                }
                Err(A::Error::custom(
                    "user_auth must contain either raw_keys or user_cert_chain",
                ))
            }
        }
        d.deserialize_map(UAuthVisitor(PhantomData))
    }
}

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
    use serde::Serialize;
    use serde_cbor::{from_slice, to_vec};

    fn bytes_of(n: u8, len: usize) -> Vec<u8> {
        vec![n; len]
    }

    fn mk_cap(s: &str) -> Capability {
        Capability::parse(s).unwrap()
    }

    fn mk_keys() -> (RawKeys, HybridSig) {
        (
            RawKeys {
                ed25519_pub: Ed25519Pub([0; ED25519_PK_LEN]),
                mldsa44_pub: Mldsa44Pub([0; MLDSA44_PK_LEN]),
            },
            HybridSig {
                ed25519: Ed25519Sig([0; ED25519_SIG_LEN]),
                mldsa44: Mldsa44Sig([0; MLDSA44_SIG_LEN]),
            },
        )
    }

    fn mk_kem() -> (KemClientEphemeral, KemServerEphemeral, KemCiphertexts) {
        let x = X25519Pub([0; X25519_PK_LEN]);
        let m = Mlkem768Pub([0; MLKEM768_PK_LEN]);
        let ct = Mlkem768Ciphertext([0; MLKEM768_CT_LEN]);
        (
            KemClientEphemeral {
                x25519_pub: x.clone(),
                mlkem_pub: m.clone(),
            },
            KemServerEphemeral {
                x25519_pub: x,
                mlkem_pub: m,
            },
            KemCiphertexts { mlkem_ct: ct },
        )
    }

    fn mk_nonce() -> Nonce32 {
        Nonce32([0; NONCE_LEN])
    }

    #[test]
    fn capability_parse_accepts_valid_tokens() {
        for tok in ["EXEC", "TTY", "A_B", "FOO1"] {
            assert!(Capability::parse(tok).is_ok(), "token {}", tok);
        }
        let long = "X".repeat(CAP_TOKEN_MAX);
        assert!(Capability::parse(&long).is_ok());
    }

    #[test]
    fn capability_parse_rejects_invalid_tokens() {
        for tok in ["exec", "A-B", "", "FOO!"] {
            assert!(Capability::parse(tok).is_err(), "token {}", tok);
        }
        let long = "X".repeat(CAP_TOKEN_MAX + 1);
        assert!(Capability::parse(&long).is_err());
    }

    #[test]
    fn hello_requires_version_1() {
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
    fn hello_requires_baseline_caps() {
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
    fn hello_caps_must_be_sorted_and_unique() {
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
            caps.push(mk_cap(&format!("Z{:02}", i)));
        }
        caps.sort();
        assert_eq!(caps.len(), CAP_COUNT_MAX + 1);
        assert!(matches!(
            Hello::new(kem_c, nonce, caps, None),
            Err(HandshakeError::HelloBadCapsOrder)
        ));
    }

    #[test]
    fn hello_pad_bound() {
        let (kem_c, _, _) = mk_kem();
        let pad = Some(bytes_of(0, PAD_MAX + 1));
        assert!(matches!(
            Hello::new(kem_c, mk_nonce(), vec![mk_cap("EXEC"), mk_cap("TTY")], pad),
            Err(HandshakeError::HelloPadTooLarge)
        ));
    }

    #[test]
    fn accept_requires_non_empty_cert_chain() {
        let (_, kem_s, _) = mk_kem();
        assert!(matches!(
            Accept::new(kem_s, vec![], mk_nonce(), None, None, None),
            Err(HandshakeError::AcceptEmptyCertChain)
        ));
    }

    #[test]
    fn accept_rejects_oversize_cert() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![bytes_of(0, CERT_MAX + 1)];
        assert!(matches!(
            Accept::new(kem_s, chain, mk_nonce(), None, None, None),
            Err(HandshakeError::AcceptCertTooLarge)
        ));
    }

    #[test]
    fn accept_ticket_param_checks() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![bytes_of(1, 1)];
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
    fn accept_pad_bound() {
        let (_, kem_s, _) = mk_kem();
        let chain = vec![bytes_of(1, 1)];
        let pad = Some(bytes_of(0, PAD_MAX + 1));
        assert!(matches!(
            Accept::new(kem_s, chain, mk_nonce(), None, None, pad),
            Err(HandshakeError::AcceptPadTooLarge)
        ));
    }

    #[test]
    fn finish_client_cert_chain_rules() {
        let (_, _, kem_ct) = mk_kem();
        let (_, sig) = mk_keys();
        let confirm = bytes_of(0, AEAD_TAG_LEN);
        let ua = UserAuth::CertChain {
            user_cert_chain: vec![],
            sig: Box::new(sig.clone()),
        };
        assert!(matches!(
            FinishClient::new(kem_ct.clone(), ua, confirm.clone(), None),
            Err(HandshakeError::FinishClientCertChainEmpty)
        ));
        let ua = UserAuth::CertChain {
            user_cert_chain: vec![bytes_of(0, CERT_MAX + 1)],
            sig: Box::new(sig),
        };
        assert!(matches!(
            FinishClient::new(kem_ct, ua, confirm, None),
            Err(HandshakeError::FinishClientCertTooLarge)
        ));
    }

    #[test]
    fn finish_client_aead_tag_len() {
        let (_, _, kem_ct) = mk_kem();
        let (raw_keys, sig) = mk_keys();
        let ua = UserAuth::RawKeys {
            raw_keys: Box::new(raw_keys),
            sig: Box::new(sig),
        };
        assert!(matches!(
            FinishClient::new(kem_ct.clone(), ua.clone(), bytes_of(0, AEAD_TAG_LEN - 1), None),
            Err(HandshakeError::LengthMismatch { .. })
        ));
        assert!(FinishClient::new(kem_ct, ua, bytes_of(0, AEAD_TAG_LEN), None).is_ok());
    }

    #[test]
    fn finish_client_pad_bound() {
        let (_, _, kem_ct) = mk_kem();
        let (raw_keys, sig) = mk_keys();
        let ua = UserAuth::RawKeys {
            raw_keys: Box::new(raw_keys),
            sig: Box::new(sig),
        };
        let pad = Some(bytes_of(0, PAD_MAX + 1));
        assert!(matches!(
            FinishClient::new(kem_ct, ua, bytes_of(0, AEAD_TAG_LEN), pad),
            Err(HandshakeError::FinishClientPadTooLarge)
        ));
    }

    #[test]
    fn finish_server_aead_tag_len() {
        assert!(matches!(
            FinishServer::new(bytes_of(0, AEAD_TAG_LEN - 1), None, None),
            Err(HandshakeError::LengthMismatch { .. })
        ));
        assert!(FinishServer::new(bytes_of(0, AEAD_TAG_LEN), None, None).is_ok());
    }

    #[test]
    fn finish_server_ticket_non_empty_when_present() {
        assert!(matches!(
            FinishServer::new(bytes_of(0, AEAD_TAG_LEN), Some(vec![]), None),
            Err(HandshakeError::FinishServerTicketEmpty)
        ));
    }

    #[test]
    fn finish_server_pad_bound() {
        assert!(matches!(
            FinishServer::new(
                bytes_of(0, AEAD_TAG_LEN),
                None,
                Some(bytes_of(0, PAD_MAX + 1))
            ),
            Err(HandshakeError::FinishServerPadTooLarge)
        ));
    }

    #[derive(Serialize)]
    struct RawKeysInput<'a> {
        raw_keys: &'a RawKeys,
        sig: &'a HybridSig,
    }

    #[derive(Serialize)]
    struct CertChainInput<'a> {
        user_cert_chain: Vec<Vec<u8>>,
        sig: &'a HybridSig,
    }

    #[derive(Serialize)]
    struct BothInput<'a> {
        raw_keys: &'a RawKeys,
        user_cert_chain: Vec<Vec<u8>>,
        sig: &'a HybridSig,
    }

    #[derive(Serialize)]
    struct ExtraInput<'a> {
        raw_keys: &'a RawKeys,
        sig: &'a HybridSig,
        extra: u8,
    }

    #[test]
    fn user_auth_deser_raw_keys_ok() {
        let (raw_keys, sig) = mk_keys();
        let inp = RawKeysInput {
            raw_keys: &raw_keys,
            sig: &sig,
        };
        let buf = to_vec(&inp).unwrap();
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::RawKeys { .. }
        ));
    }

    #[test]
    fn user_auth_deser_cert_chain_ok() {
        let (_, sig) = mk_keys();
        let inp = CertChainInput {
            user_cert_chain: vec![bytes_of(0, 1)],
            sig: &sig,
        };
        let buf = to_vec(&inp).unwrap();
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::CertChain { .. }
        ));
    }

    #[test]
    fn user_auth_deser_requires_sig() {
        let (raw_keys, _) = mk_keys();
        #[derive(Serialize)]
        struct NoSig<'a> {
            raw_keys: &'a RawKeys,
        }
        let buf = to_vec(&NoSig { raw_keys: &raw_keys }).unwrap();
        assert!(from_slice::<UserAuth>(&buf).is_err());
    }

    #[test]
    fn user_auth_deser_rejects_both_arms() {
        let (raw_keys, sig) = mk_keys();
        let inp = BothInput {
            raw_keys: &raw_keys,
            user_cert_chain: vec![bytes_of(0, 1)],
            sig: &sig,
        };
        let buf = to_vec(&inp).unwrap();
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }

    #[test]
    fn user_auth_deser_ignores_unknown_fields() {
        let (raw_keys, sig) = mk_keys();
        let inp = ExtraInput {
            raw_keys: &raw_keys,
            sig: &sig,
            extra: 7,
        };
        let buf = to_vec(&inp).unwrap();
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::RawKeys { .. }
        ));
    }

    #[derive(Serialize)]
    struct HelloExtra {
        #[serde(flatten)]
        base: Hello,
        xtra: u8,
    }

    #[derive(Serialize)]
    struct AcceptExtra {
        #[serde(flatten)]
        base: Accept,
        xtra: u8,
    }

    #[derive(Serialize)]
    struct FinishClientExtra {
        #[serde(flatten)]
        base: FinishClient,
        xtra: u8,
    }

    #[derive(Serialize)]
    struct FinishServerExtra {
        #[serde(flatten)]
        base: FinishServer,
        xtra: u8,
    }

    #[test]
    fn top_level_deny_unknown_fields() {
        let (kem_c, kem_s, kem_ct) = mk_kem();
        let hello = Hello::new(
            kem_c,
            mk_nonce(),
            vec![mk_cap("EXEC"), mk_cap("TTY")],
            None,
        )
        .unwrap();
        let buf = to_vec(&HelloExtra { base: hello, xtra: 1 }).unwrap();
        assert!(from_slice::<Hello>(&buf).is_err());

        let accept = Accept::new(
            kem_s,
            vec![bytes_of(0, 1)],
            mk_nonce(),
            None,
            None,
            None,
        )
        .unwrap();
        let buf = to_vec(&AcceptExtra { base: accept, xtra: 1 }).unwrap();
        assert!(from_slice::<Accept>(&buf).is_err());

        let (raw_keys, sig) = mk_keys();
        let fc = FinishClient::new(
            kem_ct,
            UserAuth::RawKeys {
                raw_keys: Box::new(raw_keys),
                sig: Box::new(sig),
            },
            bytes_of(0, AEAD_TAG_LEN),
            None,
        )
        .unwrap();
        let buf = to_vec(&FinishClientExtra { base: fc, xtra: 1 }).unwrap();
        assert!(from_slice::<FinishClient>(&buf).is_err());

        let fs = FinishServer::new(bytes_of(0, AEAD_TAG_LEN), None, None).unwrap();
        let buf = to_vec(&FinishServerExtra { base: fs, xtra: 1 }).unwrap();
        assert!(from_slice::<FinishServer>(&buf).is_err());
    }

    #[test]
    fn capability_debug_and_into_string() {
        let cap = mk_cap("EXEC");
        assert_eq!(format!("{:?}", cap), "Capability(EXEC)");
        let cap2 = mk_cap("FOO1");
        assert_eq!(String::from(cap2), "FOO1".to_string());
    }

    #[test]
    fn capability_deser_invalid_token() {
        let buf = to_vec(&"exec").unwrap();
        assert!(from_slice::<Capability>(&buf).is_err());
        let buf = to_vec(&mk_cap("TTY")).unwrap();
        let cap: Capability = from_slice(&buf).unwrap();
        assert_eq!(cap, mk_cap("TTY"));
    }

    #[test]
    fn nonce32_from_bytes_and_debug() {
        let n = Nonce32::from_bytes(&[1u8; NONCE_LEN]).unwrap();
        assert_eq!(n.as_bytes(), &[1u8; NONCE_LEN]);
        assert_eq!(format!("{:?}", n), "Nonce32(..)");
        assert!(matches!(
            Nonce32::from_bytes(&[0u8; NONCE_LEN - 1]),
            Err(HandshakeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn newtypes_debug_and_getters() {
        let x = X25519Pub([2; X25519_PK_LEN]);
        assert_eq!(x.as_bytes()[0], 2);
        assert_eq!(format!("{:?}", x), "X25519Pub(..)");

        let m = Mlkem768Pub([3; MLKEM768_PK_LEN]);
        assert_eq!(m.as_bytes()[0], 3);
        assert_eq!(format!("{:?}", m), "Mlkem768Pub(..)");

        let ct = Mlkem768Ciphertext([4; MLKEM768_CT_LEN]);
        assert_eq!(ct.as_bytes()[0], 4);
        assert_eq!(format!("{:?}", ct), "Mlkem768Ciphertext(..)");

        let ep = Ed25519Pub([5; ED25519_PK_LEN]);
        assert_eq!(ep.as_bytes()[0], 5);
        assert_eq!(format!("{:?}", ep), "Ed25519Pub(..)");

        let mp = Mldsa44Pub([6; MLDSA44_PK_LEN]);
        assert_eq!(mp.as_bytes()[0], 6);
        assert_eq!(format!("{:?}", mp), "Mldsa44Pub(..)");

        let es = Ed25519Sig([7; ED25519_SIG_LEN]);
        assert_eq!(es.as_bytes()[0], 7);
        assert_eq!(format!("{:?}", es), "Ed25519Sig(..)");

        let ms = Mldsa44Sig([8; MLDSA44_SIG_LEN]);
        assert_eq!(ms.as_bytes()[0], 8);
        assert_eq!(format!("{:?}", ms), "Mldsa44Sig(..)");
    }

    #[test]
    fn large_array_newtype_serde_paths() {
        use serde_cbor::value::Value;

        let pk = Mlkem768Pub([9; MLKEM768_PK_LEN]);
        let buf = to_vec(&pk).unwrap();
        assert_eq!(from_slice::<Mlkem768Pub>(&buf).unwrap(), pk);

        let buf = to_vec(&bytes_of(0, MLKEM768_PK_LEN - 1)).unwrap();
        assert!(from_slice::<Mlkem768Pub>(&buf).is_err());

        let seq = Value::Array(vec![Value::Integer(0); MLKEM768_CT_LEN]);
        let buf = to_vec(&seq).unwrap();
        let ct: Mlkem768Ciphertext = from_slice(&buf).unwrap();
        assert_eq!(ct.as_bytes(), &[0u8; MLKEM768_CT_LEN]);

        let seq_short = Value::Array(vec![Value::Integer(0); MLKEM768_CT_LEN - 1]);
        let buf = to_vec(&seq_short).unwrap();
        assert!(from_slice::<Mlkem768Ciphertext>(&buf).is_err());

        let seq_long = Value::Array(vec![Value::Integer(0); MLKEM768_CT_LEN + 1]);
        let buf = to_vec(&seq_long).unwrap();
        assert!(from_slice::<Mlkem768Ciphertext>(&buf).is_err());
    }

    #[test]
    fn user_auth_deser_non_map_triggers_expectation() {
        let buf = to_vec(&42u8).unwrap();
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("user_auth object"));
    }

    #[test]
    fn user_auth_deser_duplicate_raw_keys() {
        use serde::ser::{SerializeMap, Serializer as _};
        use serde_cbor::ser::Serializer;
        let (raw_keys, sig) = mk_keys();
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::new(&mut buf);
            let mut map = ser.serialize_map(Some(3)).unwrap();
            map.serialize_entry("raw_keys", &raw_keys).unwrap();
            map.serialize_entry("raw_keys", &raw_keys).unwrap();
            map.serialize_entry("sig", &sig).unwrap();
            map.end().unwrap();
        }
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("duplicate raw_keys"));
    }

    #[test]
    fn user_auth_deser_duplicate_user_cert_chain() {
        use serde::ser::{SerializeMap, Serializer as _};
        use serde_cbor::ser::Serializer;
        let (_, sig) = mk_keys();
        let chain = vec![bytes_of(0, 1)];
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::new(&mut buf);
            let mut map = ser.serialize_map(Some(3)).unwrap();
            map.serialize_entry("user_cert_chain", &chain).unwrap();
            map.serialize_entry("user_cert_chain", &chain).unwrap();
            map.serialize_entry("sig", &sig).unwrap();
            map.end().unwrap();
        }
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("duplicate user_cert_chain"));
    }

    #[test]
    fn user_auth_deser_duplicate_sig() {
        use serde::ser::{SerializeMap, Serializer as _};
        use serde_cbor::ser::Serializer;
        let (raw_keys, sig) = mk_keys();
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::new(&mut buf);
            let mut map = ser.serialize_map(Some(3)).unwrap();
            map.serialize_entry("sig", &sig).unwrap();
            map.serialize_entry("sig", &sig).unwrap();
            map.serialize_entry("raw_keys", &raw_keys).unwrap();
            map.end().unwrap();
        }
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("duplicate sig"));
    }

    #[test]
    fn user_auth_deser_missing_auth_arm() {
        use serde::ser::{SerializeMap, Serializer as _};
        use serde_cbor::ser::Serializer;
        let (_, sig) = mk_keys();
        let mut buf = Vec::new();
        {
            let mut ser = Serializer::new(&mut buf);
            let mut map = ser.serialize_map(Some(1)).unwrap();
            map.serialize_entry("sig", &sig).unwrap();
            map.end().unwrap();
        }
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err
            .to_string()
            .contains("user_auth must contain either raw_keys or user_cert_chain"));
    }

    #[test]
    fn finish_client_cert_chain_validates() {
        let (_, _, kem_ct) = mk_kem();
        let (_, sig) = mk_keys();
        let ua = UserAuth::CertChain {
            user_cert_chain: vec![bytes_of(0, 1)],
            sig: Box::new(sig),
        };
        let fc = FinishClient::new(kem_ct, ua, bytes_of(0, AEAD_TAG_LEN), None).unwrap();
        assert!(fc.validate().is_ok());
    }
}

