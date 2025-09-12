// Manual serde needed for arrays > 32 bytes (serde derives only auto-impl up to 32 for generic T arrays).
// Provide a helper macro to reduce repetition across large fixed-size byte newtypes.
#[macro_export]
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

#[cfg(test)]
mod tests {
    use ciborium::{de::from_reader, ser::into_writer};
    use core::fmt;
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;

    const TEST_LEN: usize = 48; // >32 to ensure macro path used
    #[derive(Clone, PartialEq, Eq)]
    struct TestArr(pub [u8; TEST_LEN]);
    // Provide Debug manually (avoid pulling other macros)
    impl fmt::Debug for TestArr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "TestArr(..)")
        }
    }
    impl_large_array_newtype_serde!(TestArr, TEST_LEN);

    #[test]
    fn round_trip_bytes_representation() {
        let mut v = [0u8; TEST_LEN];
        for (i, b) in v.iter_mut().enumerate() {
            *b = i as u8;
        }
        let t = TestArr(v);
        let mut buf = Vec::new();
        into_writer(&t, &mut buf).unwrap();
        let de: TestArr = from_reader(Cursor::new(&buf)).unwrap();
        assert_eq!(t.0, de.0);
    }

    #[test]
    fn visit_bytes_length_mismatch() {
        // serialize shorter slice – should fail on deserialize
        let short = vec![1u8; TEST_LEN - 1];
        let mut buf = Vec::new();
        into_writer(&short, &mut buf).unwrap();
        let err = from_reader::<TestArr, _>(Cursor::new(&buf)).unwrap_err();
        assert!(err.to_string().contains("invalid length"));
    }

    #[test]
    fn visit_seq_paths_too_short_and_ok() {
        // Force sequence path by serializing Vec<u8>
        let seq = (0..TEST_LEN as u8).collect::<Vec<u8>>();
        let mut buf = Vec::new();
        into_writer(&seq, &mut buf).unwrap();
        let de: TestArr = from_reader(Cursor::new(&buf)).unwrap();
        assert_eq!(&de.0[..], &seq[..]);
        let too_short = vec![9u8; TEST_LEN - 2];
        let mut buf2 = Vec::new();
        into_writer(&too_short, &mut buf2).unwrap();
        let err = from_reader::<TestArr, _>(Cursor::new(&buf2)).unwrap_err();
        assert!(err.to_string().contains("invalid length"));
    }
}
