use crate::domain::handshake::{HybridSig, RawKeys};
use core::fmt;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as DeError, MapAccess, Visitor},
};

/// Authentication data supplied by the client (raw keys or certificate chain + hybrid signature).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
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

// Field identifiers used during manual map deserialization.
#[derive(Debug, Clone, Copy)]
enum Field {
    RawKeys,
    UserCertChain,
    Sig,
    Ignore,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct FieldVisitor;
        impl Visitor<'_> for FieldVisitor {
            type Value = Field;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "field identifier")
            }
            fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
                Ok(match v {
                    "raw_keys" => Field::RawKeys,
                    "user_cert_chain" => Field::UserCertChain,
                    "sig" => Field::Sig,
                    _ => Field::Ignore,
                })
            }
        }
        d.deserialize_identifier(FieldVisitor)
    }
}

fn build_user_auth<E: DeError>(
    raw_keys: Option<RawKeys>,
    chain: Option<Vec<Vec<u8>>>,
    sig: Option<HybridSig>,
) -> Result<UserAuth, E> {
    if raw_keys.is_some() && chain.is_some() {
        return Err(E::custom(
            "USER_AUTH object contains both raw_keys and user_cert_chain (ambiguous)",
        ));
    }
    let sig = sig.ok_or_else(|| E::custom("missing sig"))?;
    if let Some(rk) = raw_keys {
        return Ok(UserAuth::RawKeys {
            raw_keys: Box::new(rk),
            sig: Box::new(sig),
        });
    }
    if let Some(chain) = chain {
        return Ok(UserAuth::CertChain {
            user_cert_chain: chain,
            sig: Box::new(sig),
        });
    }
    Err(E::custom(
        "user_auth must contain either raw_keys or user_cert_chain",
    ))
}

struct UserAuthVisitor;
impl<'de> Visitor<'de> for UserAuthVisitor {
    type Value = UserAuth;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "user_auth object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut raw_keys: Option<RawKeys> = None;
        let mut chain: Option<Vec<Vec<u8>>> = None;
        let mut sig: Option<HybridSig> = None;
        while let Some(field) = map.next_key::<Field>()? {
            match field {
                Field::RawKeys => {
                    if raw_keys.replace(map.next_value()?).is_some() {
                        return Err(A::Error::custom("duplicate raw_keys"));
                    }
                }
                Field::UserCertChain => {
                    if chain.replace(map.next_value()?).is_some() {
                        return Err(A::Error::custom("duplicate user_cert_chain"));
                    }
                }
                Field::Sig => {
                    if sig.replace(map.next_value()?).is_some() {
                        return Err(A::Error::custom("duplicate sig"));
                    }
                }
                Field::Ignore => {
                    let _ignored: serde::de::IgnoredAny = map.next_value()?;
                }
            }
        }
        build_user_auth(raw_keys, chain, sig)
    }
}

impl<'de> Deserialize<'de> for UserAuth {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_map(UserAuthVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::mk_keys;
    use ciborium::{de::from_reader, ser::into_writer};
    use serde::Serialize;
    use std::io::Cursor;

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
    #[derive(Serialize)]
    struct NoSig<'a> {
        raw_keys: &'a RawKeys,
    }

    fn to_vec<T: Serialize>(v: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        into_writer(v, &mut buf).unwrap();
        buf
    }
    fn from_slice<T: for<'de> serde::Deserialize<'de>>(
        b: &[u8],
    ) -> Result<T, ciborium::de::Error<std::io::Error>> {
        from_reader(Cursor::new(b))
    }

    #[test]
    fn deser_raw_keys_ok() {
        let (raw_keys, sig) = mk_keys();
        let buf = to_vec(&RawKeysInput {
            raw_keys: &raw_keys,
            sig: &sig,
        });
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::RawKeys { .. }
        ));
    }
    #[test]
    fn deser_cert_chain_ok() {
        let (_, sig) = mk_keys();
        let buf = to_vec(&CertChainInput {
            user_cert_chain: vec![vec![0u8; 1]],
            sig: &sig,
        });
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::CertChain { .. }
        ));
    }
    #[test]
    fn deser_requires_sig() {
        let (raw_keys, _) = mk_keys();
        let buf = to_vec(&NoSig {
            raw_keys: &raw_keys,
        });
        assert!(from_slice::<UserAuth>(&buf).is_err());
    }
    #[test]
    fn deser_rejects_both_arms() {
        let (raw_keys, sig) = mk_keys();
        let buf = to_vec(&BothInput {
            raw_keys: &raw_keys,
            user_cert_chain: vec![vec![0u8; 1]],
            sig: &sig,
        });
        let err = from_slice::<UserAuth>(&buf).unwrap_err();
        assert!(err.to_string().contains("ambiguous"));
    }
    #[test]
    fn deser_ignores_unknown_fields() {
        let (raw_keys, sig) = mk_keys();
        let buf = to_vec(&ExtraInput {
            raw_keys: &raw_keys,
            sig: &sig,
            extra: 7,
        });
        assert!(matches!(
            from_slice::<UserAuth>(&buf).unwrap(),
            UserAuth::RawKeys { .. }
        ));
    }

    #[test]
    fn duplicate_raw_keys_field_errors() {
        let (raw_keys, sig) = mk_keys();
        // Manually craft CBOR map with duplicate key by serializing a sequence of key/value pairs.
        // Simpler: encode two maps and splice (quick approach) - instead directly build bytes.
        let mut base = Vec::new();
        // Map of 3 entries: raw_keys, raw_keys (duplicate), sig
        // Major type 5 (map), additional 3 -> 0xA3
        base.push(0xA3);
        // First key: raw_keys (text length 8) -> 0x68 then bytes
        base.push(0x68);
        base.extend_from_slice(b"raw_keys");
        into_writer(&raw_keys, &mut base).unwrap();
        // Duplicate key
        base.push(0x68);
        base.extend_from_slice(b"raw_keys");
        into_writer(&raw_keys, &mut base).unwrap();
        // sig key
        base.push(0x63);
        base.extend_from_slice(b"sig");
        into_writer(&sig, &mut base).unwrap();
        let err = from_reader::<UserAuth, _>(Cursor::new(&base)).unwrap_err();
        assert!(err.to_string().contains("duplicate raw_keys"));
    }

    #[test]
    fn duplicate_sig_field_errors() {
        let (raw_keys, sig) = mk_keys();
        // Map with raw_keys, sig, sig
        let mut base = Vec::new();
        base.push(0xA3); // 3 entries
        base.push(0x68);
        base.extend_from_slice(b"raw_keys");
        into_writer(&raw_keys, &mut base).unwrap();
        base.push(0x63);
        base.extend_from_slice(b"sig");
        into_writer(&sig, &mut base).unwrap();
        base.push(0x63);
        base.extend_from_slice(b"sig");
        into_writer(&sig, &mut base).unwrap();
        let err = from_reader::<UserAuth, _>(Cursor::new(&base)).unwrap_err();
        assert!(err.to_string().contains("duplicate sig"));
    }

    #[test]
    fn duplicate_user_cert_chain_field_errors() {
        let (_, sig) = mk_keys();
        let chain = vec![vec![0u8; 1]];
        let mut base = Vec::new();
        base.push(0xA3); // 3 entries
        base.push(0x6F);
        base.extend_from_slice(b"user_cert_chain");
        into_writer(&chain, &mut base).unwrap();
        base.push(0x6F);
        base.extend_from_slice(b"user_cert_chain");
        into_writer(&chain, &mut base).unwrap();
        base.push(0x63);
        base.extend_from_slice(b"sig");
        into_writer(&sig, &mut base).unwrap();
        let err = from_reader::<UserAuth, _>(Cursor::new(&base)).unwrap_err();
        assert!(err.to_string().contains("duplicate user_cert_chain"));
    }

    #[test]
    fn debug_format_variants() {
        let (raw_keys, sig) = mk_keys();
        // Reuse existing constructors through serde round-trip to ensure we exercise Debug without
        // relying on direct construction specifics.
        #[derive(Serialize)]
        struct RK<'a> {
            raw_keys: &'a RawKeys,
            sig: &'a HybridSig,
        }
        #[derive(Serialize)]
        struct CC<'a> {
            user_cert_chain: Vec<Vec<u8>>,
            sig: &'a HybridSig,
        }
        let (rk, s) = (raw_keys, sig);
        let mut buf = Vec::new();
        into_writer(
            &RK {
                raw_keys: &rk,
                sig: &s,
            },
            &mut buf,
        )
        .unwrap();
        let ua1: UserAuth = from_reader(Cursor::new(&buf)).unwrap();
        buf.clear();
        into_writer(
            &CC {
                user_cert_chain: vec![vec![1u8; 1]],
                sig: &s,
            },
            &mut buf,
        )
        .unwrap();
        let ua2: UserAuth = from_reader(Cursor::new(&buf)).unwrap();
        let d1 = format!("{:?}", ua1);
        let d2 = format!("{:?}", ua2);
        assert!(d1.contains("RawKeys"));
        assert!(d2.contains("CertChain"));
    }
}
