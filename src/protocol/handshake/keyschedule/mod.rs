use crate::core::crypto::hkdf::{HkdfError, hkdf_expand};
use crate::ports::crypto::{AeadKey, NonceSalt};

pub const KEY_LEN: usize = 32; // XChaCha20-Poly1305
pub const SALT_LEN: usize = 16; // our 16B salt + 8B seq => 24B nonce

// Label helpers (canonical CBOR is already in transcript; labels are ASCII)
const L_CLIENT_KEY: &[u8] = b"qsh v1 client write key";
const L_CLIENT_SALT: &[u8] = b"qsh v1 client write salt16";
const L_SERVER_KEY: &[u8] = b"qsh v1 server write key";
const L_SERVER_SALT: &[u8] = b"qsh v1 server write salt16";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectionKeys {
    pub key: AeadKey,
    pub salt: NonceSalt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteKeys {
    pub client: DirectionKeys,
    pub server: DirectionKeys,
}

/// Derive per-direction write keys & salts.
///
/// Inputs:
/// - `_th`: transcript hash (currently unused, reserved for integrating salt in Extract step)
/// - `prk`: already-derived HKDF PRK (48 bytes)
///
/// Returns a `WriteKeys` struct with client/server direction material.
///
/// # Errors
/// Propagates `HkdfError` if HKDF expansion somehow fails (should not with fixed small lengths).
pub fn derive_keys(_th: &[u8; 48], prk: &[u8; 48]) -> Result<WriteKeys, HkdfError> {
    // Current signature assumes PRK already computed from FSM.

    // Client write
    let mut ck = [0u8; KEY_LEN];
    hkdf_expand(L_CLIENT_KEY, prk, &mut ck)?;
    let mut cs = [0u8; SALT_LEN];
    hkdf_expand(L_CLIENT_SALT, prk, &mut cs)?;

    // Server write
    let mut sk = [0u8; KEY_LEN];
    hkdf_expand(L_SERVER_KEY, prk, &mut sk)?;
    let mut ss = [0u8; SALT_LEN];
    hkdf_expand(L_SERVER_SALT, prk, &mut ss)?;

    Ok(WriteKeys {
        client: DirectionKeys {
            key: AeadKey(ck),
            salt: NonceSalt(cs),
        },
        server: DirectionKeys {
            key: AeadKey(sk),
            salt: NonceSalt(ss),
        },
    })
}

/// Convenience to compute PRK directly here (alternate API)
#[must_use]
pub fn prk_from(th: &[u8; 48], shared: &[u8]) -> [u8; 48] {
    // hkdf::Hkdf::new(Some(salt), ikm) already performs Extract.
    use hkdf::Hkdf;
    use sha2::Sha384;
    let hk = Hkdf::<Sha384>::new(Some(th), shared);
    // Pull out the PRK bytes in a stable form (48 bytes)
    let mut prk = [0u8; 48];
    hk.expand(b"", &mut prk).ok();
    prk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_th(label: u8) -> [u8; 48] {
        let mut th = [0u8; 48];
        for (i, b) in th.iter_mut().enumerate() {
            *b = label.wrapping_add(i as u8);
        }
        th
    }

    #[test]
    fn derive_is_deterministic_for_same_inputs() {
        let th = dummy_th(7);
        let shared = b"shared-secret-material";
        let prk = prk_from(&th, shared);
        let a = derive_keys(&th, &prk).unwrap();
        let b = derive_keys(&th, &prk).unwrap();
        assert_eq!(a.client.key.0, b.client.key.0);
        assert_eq!(a.server.key.0, b.server.key.0);
        assert_eq!(a.client.salt.0, b.client.salt.0);
    }

    #[test]
    fn different_prk_changes_outputs() {
        let th = dummy_th(1);
        let shared1 = b"shared-1";
        let shared2 = b"shared-2";
        let prk1 = prk_from(&th, shared1);
        let prk2 = prk_from(&th, shared2);
        assert_ne!(prk1, prk2);
        let k1 = derive_keys(&th, &prk1).unwrap();
        let k2 = derive_keys(&th, &prk2).unwrap();
        assert_ne!(k1.client.key.0, k2.client.key.0);
        assert_ne!(k1.server.key.0, k2.server.key.0);
    }

    #[test]
    fn client_and_server_material_differ() {
        let th = dummy_th(3);
        let shared = b"hybrid-kex-output";
        let prk = prk_from(&th, shared);
        let ks = derive_keys(&th, &prk).unwrap();
        assert_ne!(ks.client.key.0, ks.server.key.0);
        assert_ne!(ks.client.salt.0, ks.server.salt.0);
    }

    #[test]
    fn transcript_hash_changes_prk_and_keys() {
        let th1 = dummy_th(10);
        let th2 = dummy_th(11);
        let shared = b"S";
        let prk1 = prk_from(&th1, shared);
        let prk2 = prk_from(&th2, shared);
        assert_ne!(prk1, prk2);
        let k1 = derive_keys(&th1, &prk1).unwrap();
        let k2 = derive_keys(&th2, &prk2).unwrap();
        assert_ne!(k1.client.key.0, k2.client.key.0);
    }
}
