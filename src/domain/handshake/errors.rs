use thiserror::Error;

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
    #[error(
        "HELLO.capabilities must be lexicographic, strictly increasing (no duplicates) and ≤16 entries"
    )]
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
