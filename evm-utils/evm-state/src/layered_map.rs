use serde::{de::DeserializeOwned, Serialize};

use super::storage::{AsBytePrefix, PersistentMap};
use super::version_map::{KeyResult, Map};

#[derive(Clone)]
pub struct LayeredMap<Version, Key, Value> {
    layers: Map<Version, Key, Value>,
    storage: PersistentMap<Version, Key, Option<Value>>,
}

impl<Version, Key, Value> LayeredMap<Version, Key, Value> {
    pub fn wrap(storage: PersistentMap<Version, Key, Option<Value>>, version: Version) -> Self
    where
        Key: Ord,
    {
        Self {
            layers: Map::empty(version),
            storage,
        }
    }
}

impl<Version, Key, Value> LayeredMap<Version, Key, Value>
where
    Version: Copy,
    Key: Ord + Copy,
{
    pub fn get(&self, key: Key) -> Option<Value>
    where
        Version: AsBytePrefix + Serialize + DeserializeOwned,
        Key: Serialize + DeserializeOwned,
        Value: Clone + Serialize + DeserializeOwned,
    {
        match self.layers.get(&key) {
            KeyResult::Found(mb_value) => mb_value.map(Value::clone),
            KeyResult::NotFound(last_version) => self
                .storage
                .get_for(*last_version, key)
                .unwrap_or_else(|err| panic!("Storage error: {:?}", err))
                .flatten(),
        }
    }

    pub fn insert(&mut self, key: Key, value: Value) {
        self.layers.insert(key, value)
    }

    pub fn remove(&mut self, key: Key) {
        self.layers.remove(key)
    }

    pub fn freeze(&mut self) {
        self.layers.freeze();
    }

    pub fn dump(&mut self) -> anyhow::Result<()>
    where
        Version: Serialize + DeserializeOwned + AsBytePrefix,
        Key: Serialize + DeserializeOwned,
        Value: Serialize + DeserializeOwned + Clone,
    {
        let mut full_iter = self.layers.full_iter().peekable();
        while let Some((version, kvs)) = full_iter.next() {
            for (key, value) in kvs {
                self.storage.insert_with(*version, *key, value.cloned())?;
            }

            let previous = full_iter
                .peek()
                .map(|(previous, _)| **previous)
                .or_else(|| self.storage.versions.previous_of(*version).ok().flatten());
            self.storage.versions.new_version(*version, previous)?;
        }
        drop(full_iter);

        let current_version = self.layers.version;
        self.layers = Map::empty(current_version);

        Ok(())
    }

    pub fn try_fork(&self, new_version: Version) -> Option<Self>
    where
        Version: Ord,
    {
        let layers = self.layers.try_fork(new_version)?;
        Some(Self {
            layers,
            storage: self.storage.clone(),
        })
    }
}
