use serde::{Serialize, Serializer, Deserializer, Deserialize, de};
use std::fmt::{self, LowerHex};
use std::marker::PhantomData;
use std::str::FromStr;

#[derive(Debug, Hash, Clone, Eq, PartialEq)]
pub struct Hex<T>(pub T);
#[derive(Debug, Clone)]
pub struct Bytes(pub Vec<u8>);

impl<T: LowerHex> Serialize for Hex<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let value = format!("0x{:x}", self.0);
        if &value == "0x" {
            serializer.serialize_str("0x0")
        } else {
            serializer.serialize_str(&value)
        }
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

struct HexVisitor<T> {
    _marker: PhantomData<T>,
}

impl<'de, T: FromStr> de::Visitor<'de> for HexVisitor<T> {
    type Value = Hex<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Must be a valid hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        match T::from_str(s) {
            Ok(s) => Ok(Hex(s)),
            Err(_) => Err(de::Error::invalid_value(de::Unexpected::Str(s), &self)),
        }
    }
}

struct BytesVisitor;

impl<'de> de::Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Must be a valid hex string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        match hex::decode(s) {
            Ok(s) => Ok(Bytes(s)),
            Err(_) => Err(de::Error::invalid_value(de::Unexpected::Str(s), &self)),
        }
    }
}

impl<'de, T: FromStr> Deserialize<'de> for Hex<T> {
    fn deserialize<D>(deserializer: D) -> Result<Hex<T>, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_str(HexVisitor {
            _marker: PhantomData
        })
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_str(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitive_types::U256;
    use serde_json;

    //TODO: WTF? Is Ethereum hex remove in-byte zero? Why it expect 0x1 not 0x01?
    #[test]
    fn hex_single_digit() {
        assert_eq!("\"0x1\"", serde_json::to_string(&Hex(U256::one())).unwrap());
    }

    #[test]
    fn hex_zero() {
        assert_eq!("\"0x0\"", serde_json::to_string(&Hex(U256::zero())).unwrap());
    }

    #[test]
    fn bytes_single_digit() {
        assert_eq!("\"0x01\"", serde_json::to_string(&Bytes(vec![1])).unwrap());
    }
}
