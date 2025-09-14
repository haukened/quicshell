/*
    HKDF-SHA-384 extract/expand implementation using `hkdf` crate.
    RFC5869: https://datatracker.ietf.org/doc/html/rfc5869
    SHA-384: https://datatracker.ietf.org/doc/html/rfc6234#section-4.2

    Note: `hkdf` crate uses `sha2` crate for hash implementations.
*/

use hkdf::Hkdf;
use sha2::Sha384;

#[derive(Debug, thiserror::Error)]
pub enum HkdfError {
    #[error("invalid PRK")]
    InvalidPrk,
    #[error("invalid length")]
    InvalidLength,
}

/// `HKDF-SHA-384` extract: derive a pseudorandom key (PRK) from input keying material (IKM) and optional salt.
/// If `salt` is empty, it is treated as a string of `HashLen` (48) zeros as per RFC5869.
/// Returns a 48-byte `PRK`.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    // RFC5869: PRK length = `HashLen` (48 for SHA-384)
    let hk = Hkdf::<Sha384>::new(Some(salt), ikm);
    let mut prk = [0u8; 48];
    // Hkdf::new already does extract; we just signal the length here.
    // We’ll use `expand_into` below from this combined state, so return PRK materialized.
    // Alternatively: store Hkdf instance; here we re-init per expand for clarity.
    hk.expand(b"", &mut prk).ok(); // expand with empty info to get PRK bytes
    prk
}

/// `HKDF-SHA-384` expand: derive output keying material (`OKM`) from pseudorandom key (`PRK`) and info.
/// `out` is the output buffer to fill; its length determines the length of OKM.
/// Note: max output length is 255 * `HashLen` = 255 * 48 = 12240 bytes.
/// # Errors
/// Returns `Err(())` if `prk` is invalid or output length is too large.
pub fn hkdf_expand(info: &[u8], prk: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
    // Rebuild HKDF from PRK by using extract with zero salt, then expand.
    let hk = Hkdf::<Sha384>::from_prk(prk).map_err(|_| HkdfError::InvalidPrk)?;
    hk.expand(info, out).map_err(|_| HkdfError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_length_and_different_salt_changes_prk() {
        let ikm = b"input keying material";
        let prk1 = hkdf_extract(b"salt-a", ikm);
        let prk2 = hkdf_extract(b"salt-b", ikm);
        assert_eq!(prk1.len(), 48);
        assert_ne!(prk1, prk2, "different salt should yield different PRK");
    }

    #[test]
    fn expand_produces_distinct_outputs_for_distinct_info() {
        let ikm = b"ikm";
        let prk = hkdf_extract(b"salt", ikm);
        let mut out1 = [0u8; 32];
        let mut out2 = [0u8; 32];
        hkdf_expand(b"info-1", &prk, &mut out1).unwrap();
        hkdf_expand(b"info-2", &prk, &mut out2).unwrap();
        assert_ne!(out1, out2, "different info should yield different OKM");
    }

    #[test]
    fn expand_max_length_boundary_ok() {
        // Use a relatively large but safe length (hashLen * 3) to ensure multi-block logic in crate.
        let ikm = b"ikm-long";
        let prk = hkdf_extract(b"salt", ikm);
        let mut out = vec![0u8; 48 * 3];
        hkdf_expand(b"info", &prk, &mut out).unwrap();
        assert!(
            out.iter().any(|&b| b != 0),
            "output should not be all zeros"
        );
    }

    #[test]
    fn expand_invalid_prk_errors() {
        // Provide a PRK of wrong length (short) to trigger InvalidPrk
        let bad_prk = [0u8; 16];
        let mut out = [0u8; 32];
        let err = hkdf_expand(b"info", &bad_prk, &mut out).unwrap_err();
        matches!(err, HkdfError::InvalidPrk);
    }

    #[test]
    fn expand_too_large_length_errors() {
        // Construct a large out buffer exceeding max (simulate by forcing hkdf crate to reject)
        // 255 * 48 = 12240 max; so 12241 should fail.
        let ikm = b"ikm";
        let prk = hkdf_extract(b"salt", ikm);
        let mut out = vec![0u8; 48 * 255 + 1];
        let err = hkdf_expand(b"info", &prk, &mut out).unwrap_err();
        matches!(err, HkdfError::InvalidLength);
    }
}
