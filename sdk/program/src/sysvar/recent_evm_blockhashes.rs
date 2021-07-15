use crate::{declare_sysvar_id, hash::Hash, sysvar::Sysvar};

use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple,
    Deserializer, Serializer,
};
use std::fmt;
use std::marker::PhantomData;

pub const MAX_ENTRIES: usize = 256;

declare_sysvar_id!(
    "SysvarRecentEVMB1ockHashes11111111111111111",
    RecentBlockhashes
);

#[repr(C)]
#[derive(Serialize, Deserialize, Clone)]
pub struct RecentBlockhashes(#[serde(with = "RecentBlockhashes")] pub [Hash; MAX_ENTRIES]);

impl Default for RecentBlockhashes {
    fn default() -> Self {
        Self([Hash::new_from_array([0; 32]); MAX_ENTRIES])
    }
}

impl RecentBlockhashes {
    fn deserialize<'de, D>(deserializer: D) -> Result<[Hash; MAX_ENTRIES], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T> {
            element: PhantomData<T>,
        }
        use serde::de::Deserialize;
        impl<'de, T> Visitor<'de> for ArrayVisitor<T>
        where
            T: Default + Copy + Deserialize<'de>,
        {
            type Value = [T; MAX_ENTRIES];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 256))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[T; MAX_ENTRIES], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [T::default(); MAX_ENTRIES];
                for (i, item) in arr.iter_mut().enumerate() {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(MAX_ENTRIES, visitor)
    }

    fn serialize<S>(data: &[Hash; MAX_ENTRIES], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(data.len())?;
        for elem in &data[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl Sysvar for RecentBlockhashes {
    fn size_of() -> usize {
        MAX_ENTRIES * 32
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_seriazize_evm_blockhashes() {
        let blockhashes = RecentBlockhashes::default();
        assert_eq!(
            bincode::serialize(&blockhashes).unwrap().len(),
            MAX_ENTRIES * 32
        )
    }
}
