use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaybeValue<V> {
    /// Value exist, and was changed.
    Value(V),
    /// Value was removed.
    Removed,
}

use MaybeValue::*;

impl<V> MaybeValue<V> {
    pub fn by_ref(&self) -> MaybeValue<&V> {
        match self {
            Value(ref v) => Value(v),
            Removed => Removed,
        }
    }
}

impl<T> From<T> for MaybeValue<T> {
    fn from(value: T) -> Self {
        Value(value)
    }
}

impl<T> From<Option<T>> for MaybeValue<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            Some(value) => Value(value),
            None => Removed,
        }
    }
}

impl<T> From<MaybeValue<T>> for Option<T> {
    fn from(mb_value: MaybeValue<T>) -> Option<T> {
        match mb_value {
            Value(value) => Some(value),
            Removed => None,
        }
    }
}
