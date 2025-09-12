/// ---- Spec-bound size & defensive constants (v1 parameter set) ----
/// Fixed sizes derived from the qsh v1 parameter set. Enforced at the type level
/// (preferred) via newtypes. Defensive maxima (`*_MAX`) are NOT wire commitments;
/// they bound resource usage and may change in a subsequent major version.
///
/// Baseline capabilities (`EXEC`, `TTY`) are validated at runtime; AEAD tag
/// length is fixed (`AEAD_TAG_LEN`) and enforced with `LengthMismatch`.
pub(crate) const NONCE_LEN: usize = 32;
pub(crate) const X25519_PK_LEN: usize = 32;
pub(crate) const ED25519_PK_LEN: usize = 32;
pub(crate) const ED25519_SIG_LEN: usize = 64;
pub(crate) const MLKEM768_PK_LEN: usize = 1184; // Kyber/ML-KEM-768 public key size
pub(crate) const MLKEM768_CT_LEN: usize = 1088; // Kyber/ML-KEM-768 ciphertext size
pub(crate) const MLDSA44_PK_LEN: usize = 1312; // Dilithium/ML-DSA-44 public key size
pub(crate) const MLDSA44_SIG_LEN: usize = 2420; // Dilithium/ML-DSA-44 signature size
pub(crate) const AEAD_TAG_LEN: usize = 16; // AES-GCM and ChaCha20-Poly1305 tag size
pub(crate) const PAD_MAX: usize = 1024; // defensive bound for pad
pub(crate) const CERT_MAX: usize = 16 * 1024; // defensive bound per certificate blob
pub(crate) const CAP_TOKEN_MAX: usize = 16; // max capability token length
pub(crate) const CAP_COUNT_MAX: usize = 16; // max number of capability tokens
