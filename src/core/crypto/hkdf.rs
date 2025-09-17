/*
    HKDF-SHA-384 helpers for qsh.

    - RFC5869: https://datatracker.ietf.org/doc/html/rfc5869
    - SHA-384: https://datatracker.ietf.org/doc/html/rfc6234#section-4.2

    Provides:
    - Raw `hkdf_extract` / `hkdf_expand` helpers
    - Channel-specific derivations per docs/spec.md §5.2 & §6.3
      * ch_root(app_secret, channel_id)
      * directional key from ch_root (c2s / s2c)
      * nonce salt from ch_root + direction + epoch
      * chained rekey from previous directional key

    Note: `hkdf` crate uses `sha2` for hash implementations.
*/

use crate::ports::crypto::{AeadKey, NonceSalt};
use hmac::{Hmac, Mac};
use sha2::Sha384;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
pub enum HkdfError {
    #[error("invalid PRK")]
    InvalidPrk,
    #[error("invalid length")]
    InvalidLength,
}

/// `HKDF-SHA-384` extract (RFC5869 §2.2): derive a pseudorandom key (PRK) from input keying material (IKM) and optional salt.
/// If `salt` is empty, it is treated as a string of `HashLen` (48) zeros.
/// Returns a 48-byte `PRK`.
///
/// # Panics
/// This function does not panic in practice. `HMAC-SHA-384` accepts keys of any length,
/// so key initialization cannot fail under normal circumstances.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    type H = Hmac<Sha384>;
    const HASH_LEN: usize = 48;
    let mut prk = [0u8; HASH_LEN];
    // Per RFC5869, if salt is not provided, use HashLen zeros
    let mut mac = if salt.is_empty() {
        H::new_from_slice(&[0u8; HASH_LEN]).expect("HMAC accepts fixed zero key")
    } else {
        H::new_from_slice(salt).expect("HMAC accepts arbitrary key lengths")
    };
    mac.update(ikm);
    let t = mac.finalize().into_bytes();
    prk.copy_from_slice(&t);
    prk
}

/// `HKDF-SHA-384` expand (RFC5869 §2.3): derive output keying material (`OKM`) from a key (`prk`) and `info`.
/// Accepts any-length key (either a true PRK from `hkdf_extract` or a 32-byte seed like `app_secret`).
/// `out` is the output buffer to fill; its length determines the length of OKM.
/// Note: max output length is 255 * `HashLen` = 255 * 48 = 12240 bytes.
///
/// # Errors
/// Returns `HkdfError::InvalidLength` if `out.len()` exceeds the HKDF limit
/// or `HkdfError::InvalidPrk` if the HMAC key initialization fails.
///
/// # Panics
/// Does not panic in practice. The `expect` on the block counter is unreachable because
/// the HKDF block count is bounded by 255 for SHA-384 and we compute `n` accordingly.
pub fn hkdf_expand(info: &[u8], prk: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
    type H = Hmac<Sha384>;
    const HASH_LEN: usize = 48;
    if out.len() > 255 * HASH_LEN {
        return Err(HkdfError::InvalidLength);
    }
    let mut t_prev: [u8; HASH_LEN] = [0u8; HASH_LEN];
    let mut t_len = 0usize;
    let mut written = 0usize;
    let n = out.len().div_ceil(HASH_LEN);
    for i in 1..=n {
        let mut mac = H::new_from_slice(prk).map_err(|_| HkdfError::InvalidPrk)?;
        if t_len != 0 {
            mac.update(&t_prev[..t_len]);
        }
        mac.update(info);
        let ctr = u8::try_from(i).expect("counter <= 255 by construction");
        mac.update(&[ctr]);
        let t = mac.finalize().into_bytes();
        t_prev.copy_from_slice(&t);
        t_len = HASH_LEN;
        let take = core::cmp::min(HASH_LEN, out.len() - written);
        out[written..written + take].copy_from_slice(&t_prev[..take]);
        written += take;
    }
    // Clear sensitive temporary
    t_prev.zeroize();
    Ok(())
}

// ---------- Channel-specific helpers (spec-aligned) ----------

const L_CH_ROOT: &[u8] = b"qsh v1 ch root"; // + varint(channel_id)
const L_CH_KEY_C2S: &[u8] = b"qsh v1 ch key c2s";
const L_CH_KEY_S2C: &[u8] = b"qsh v1 ch key s2c";
const L_CH_NONCE: &[u8] = b"qsh v1 ch nonce"; // + dir(1) + uint64_be(epoch)
const L_CH_REKEY: &[u8] = b"qsh v1 ch rekey"; // + uint64_be(counter)

/// Encode a QUIC variable-length integer (RFC 9000) into a temporary buffer and return it.
/// Supports full 62-bit range but typical `channel_id`s are small.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]
fn encode_quic_varint(v: u64) -> Vec<u8> {
    if v <= 0x3f {
        // 1 byte, 00xxxxxx
        return vec![v as u8 & 0x3f];
    }
    if v <= 0x3fff {
        // 2 bytes, 01xxxxxx
        let x = 0x40_00 | (v as u16);
        return x.to_be_bytes().to_vec();
    }
    if v <= 0x3fff_ffff {
        // 4 bytes, 10xxxxxx
        let x = 0x80_00_00_00 | (v as u32);
        return x.to_be_bytes().to_vec();
    }
    // 8 bytes, 11xxxxxx
    let x = 0xC0_00_00_00_00_00_00_00u64 | v;
    x.to_be_bytes().to_vec()
}

/// Derive per-channel root from `app_secret` and `channel_id` (QUIC varint encoded).
/// # Errors
/// Returns an error if HKDF expansion fails.
#[must_use]
pub fn derive_ch_root(app_secret: &[u8; 32], channel_id: u64) -> [u8; 32] {
    // Treat `app_secret` like a PRK input; use HKDF-Expand directly as spec indicates.
    let mut info = Vec::with_capacity(L_CH_ROOT.len() + 8);
    info.extend_from_slice(L_CH_ROOT);
    info.extend_from_slice(&encode_quic_varint(channel_id));
    let mut out = [0u8; 32];
    // hkdf_expand_any_prk only errors on invalid PRK length (not possible here) or oversize output.
    let _ = hkdf_expand(&info, app_secret, &mut out);
    out
}

/// Direction byte for labels: 0x00 = client→server, 0x01 = server→client.
#[derive(Debug, Clone, Copy)]
pub enum Dir {
    C2S,
    S2C,
}

fn dir_byte(d: Dir) -> u8 {
    match d {
        Dir::C2S => 0x00,
        Dir::S2C => 0x01,
    }
}

/// Derive initial directional traffic key (epoch 0) from `ch_root`.
#[must_use]
pub fn derive_directional_key(ch_root: &[u8; 32], dir: Dir) -> AeadKey {
    let label = match dir {
        Dir::C2S => L_CH_KEY_C2S,
        Dir::S2C => L_CH_KEY_S2C,
    };
    let mut key = [0u8; 32];
    let _ = hkdf_expand(label, ch_root, &mut key);
    AeadKey(key)
}

/// Derive nonce salt for a given `ch_root`, `dir`, and `epoch`.
#[must_use]
pub fn derive_nonce_salt(ch_root: &[u8; 32], dir: Dir, epoch: u64) -> NonceSalt {
    let mut info = [0u8; L_CH_NONCE.len() + 1 + 8];
    info[..L_CH_NONCE.len()].copy_from_slice(L_CH_NONCE);
    info[L_CH_NONCE.len()] = dir_byte(dir);
    info[L_CH_NONCE.len() + 1..].copy_from_slice(&epoch.to_be_bytes());
    let mut salt = [0u8; 16];
    let _ = hkdf_expand(&info, ch_root, &mut salt);
    NonceSalt(salt)
}

/// Chain a directional key using the rekey counter (big-endian in the label).
#[must_use]
pub fn chain_rekey(curr_key: &AeadKey, counter: u64) -> AeadKey {
    let mut info = [0u8; L_CH_REKEY.len() + 8];
    info[..L_CH_REKEY.len()].copy_from_slice(L_CH_REKEY);
    info[L_CH_REKEY.len()..].copy_from_slice(&counter.to_be_bytes());
    let mut next = [0u8; 32];
    let _ = hkdf_expand(&info, &curr_key.0, &mut next);
    AeadKey(next)
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
    fn expand_accepts_any_length_key() {
        // Use a 32-byte seed (not a strict 48-byte PRK) and verify expansion works.
        let seed = [0x11u8; 32];
        let mut out = [0u8; 32];
        hkdf_expand(b"info", &seed, &mut out).unwrap();
        assert!(out.iter().any(|&b| b != 0));
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

    // --- Channel helper tests ---
    fn app_secret() -> [u8; 32] {
        [0xA5; 32]
    }

    #[test]
    fn varint_encoding_matches_ranges() {
        assert_eq!(encode_quic_varint(0x3f), vec![0x3f]);
        assert_eq!(encode_quic_varint(0x40), vec![0x40, 0x40]); // 0x4040 => 01|000000 01000000
        assert_eq!(encode_quic_varint(0x3fff), vec![0x7f, 0xff]);
        assert_eq!(encode_quic_varint(0x4000), vec![0x80, 0x00, 0x40, 0x00]);
        assert_eq!(
            encode_quic_varint(0x3fff_ffff),
            vec![0xbf, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            encode_quic_varint(0x4000_0000),
            vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn ch_root_is_deterministic_and_channel_scoped() {
        let a = derive_ch_root(&app_secret(), 1);
        let b = derive_ch_root(&app_secret(), 1);
        assert_eq!(a, b);
        let c = derive_ch_root(&app_secret(), 2);
        assert_ne!(a, c);
    }

    #[test]
    fn directional_keys_separate_and_deterministic() {
        let root = derive_ch_root(&app_secret(), 7);
        let c2s = derive_directional_key(&root, Dir::C2S);
        let s2c = derive_directional_key(&root, Dir::S2C);
        assert_ne!(c2s.0, s2c.0);
        let c2s_again = derive_directional_key(&root, Dir::C2S);
        assert_eq!(c2s.0, c2s_again.0);
    }

    #[test]
    fn nonce_salt_varies_by_dir_and_epoch() {
        let root = derive_ch_root(&app_secret(), 3);
        let s0 = derive_nonce_salt(&root, Dir::C2S, 0);
        let s1 = derive_nonce_salt(&root, Dir::C2S, 1);
        let s0_rev = derive_nonce_salt(&root, Dir::S2C, 0);
        assert_ne!(s0.0, s1.0);
        assert_ne!(s0.0, s0_rev.0);
    }

    #[test]
    fn rekey_chaining_changes_key_monotonically() {
        let root = derive_ch_root(&app_secret(), 9);
        let k = derive_directional_key(&root, Dir::C2S);
        let k1 = chain_rekey(&k, 0);
        let k2 = chain_rekey(&k1, 1);
        assert_ne!(k.0, k1.0);
        assert_ne!(k1.0, k2.0);
    }
}
