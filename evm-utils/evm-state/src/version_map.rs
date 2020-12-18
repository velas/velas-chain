use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::mb_value::MaybeValue;

#[derive(Clone)]
pub struct Map<Version, Key, Value> {
    pub(crate) version: Version,
    state: BTreeMap<Key, MaybeValue<Value>>,
    parent: Option<Arc<Map<Version, Key, Value>>>,
}

impl<Version, Key, Value> Default for Map<Version, Key, Value>
where
    Version: Default,
    Key: Ord,
{
    fn default() -> Self {
        Map::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyResult<V, T> {
    /// Value for existing key.
    Found(T),
    /// Key not found, Value is last looked version.
    NotFound(V),
}

impl<Version, Key, Value> Map<Version, Key, Value>
where
    Key: Ord,
{
    pub fn empty(version: Version) -> Self {
        Self {
            version,
            state: BTreeMap::new(),
            parent: None,
        }
    }

    // Create new versioned map.
    pub fn new() -> Self
    where
        Version: Default,
    {
        Self {
            version: Version::default(),
            state: BTreeMap::new(),
            parent: None,
        }
    }

    // Borrow value by key
    pub fn get(&self, key: &Key) -> KeyResult<&Version, Option<&Value>> {
        match (self.state.get(key), self.parent.as_ref()) {
            (Some(s), _) => KeyResult::Found(s.by_ref().into()),
            (None, Some(parent)) => parent.get(key),
            (None, None) => KeyResult::NotFound(&self.version),
        }
    }

    // Insert new key, didn't query key before inserting.
    pub fn insert(&mut self, key: Key, value: Value) {
        self.push_change(key, MaybeValue::Value(value));
    }

    // Remove key, didn't query key before inserting.
    pub fn remove(&mut self, key: Key) {
        self.push_change(key, MaybeValue::Removed);
    }

    pub fn clear(&mut self) {
        self.state.clear();
        self.parent = None;
    }

    // Override state of key.
    fn push_change(&mut self, key: Key, value: MaybeValue<Value>) {
        self.state.insert(key, value);
    }

    pub fn iter(
        &self,
    ) -> (
        &Version,
        impl Iterator<Item = (&Key, &MaybeValue<Value>)> + '_,
    ) {
        (
            &self.version,
            self.state.iter(), //.map(|(key, value)| (key, value.by_ref().into())),
        )
    }

    pub fn full_iter(
        &self,
    ) -> impl Iterator<
        Item = (
            &Version,
            impl Iterator<Item = (&Key, &MaybeValue<Value>)> + '_,
        ),
    > + '_ {
        std::iter::once(self.iter()).chain(self.parent.as_ref().map(|parent| parent.iter()))
    }
}

impl<Version, Key, Value> Map<Version, Key, Value>
where
    Key: Ord,
{
    pub fn freeze(&mut self)
    where
        Version: Clone,
    {
        let this = Self {
            version: self.version.clone(),
            state: std::mem::take(&mut self.state),
            parent: self.parent.as_ref().map(Arc::clone),
        };
        self.parent = Some(Arc::new(this));
    }

    // Create new version from freezed one
    pub fn try_fork(&self, new_version: Version) -> Option<Self>
    where
        Version: Ord,
    {
        assert!(new_version >= self.version);

        if !self.state.is_empty() {
            return None;
        }

        Some(Self {
            version: new_version,
            state: BTreeMap::new(),
            parent: self.parent.clone(),
        })
    }
}

impl<Version, Key, Value> fmt::Debug for Map<Version, Key, Value>
where
    Version: fmt::Debug,
    Key: fmt::Debug,
    Value: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Map")
            .field("version", &self.version)
            .field("state", &self.state)
            .field("parent", &"omited")
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use KeyResult::*;

    #[test]
    fn store_and_get_simple() {
        let mut map: Map<(), _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        assert_eq!(map.get(&"first"), Found(Some(&1)));
        assert_eq!(map.get(&"second"), Found(Some(&2)));
    }

    // Test that map can save version, and type of map is always remain the same.
    #[test]
    fn new_dynamic_version_insert_remove_test() {
        let mut map: Map<_, _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Found(Some(&1)));
        assert_eq!(map.get(&"second"), Found(Some(&2)));
        assert_eq!(map.get(&"third"), Found(Some(&3)));

        map.freeze();
        let mut map: Map<_, _, _> = map.try_fork(1).unwrap();

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), Found(None));
        assert_eq!(map.get(&"second"), Found(Some(&2)));
        assert_eq!(map.get(&"third"), Found(Some(&1)));
    }

    // Same as new_dynamic_version_insert_remove_test but dont hide type of store.
    #[test]
    fn new_static_version_insert_remove_test() {
        let mut map: Map<_, _, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Found(Some(&1)));
        assert_eq!(map.get(&"second"), Found(Some(&2)));
        assert_eq!(map.get(&"third"), Found(Some(&3)));

        map.freeze();
        let mut map = map.try_fork(1).unwrap();

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), Found(None));
        assert_eq!(map.get(&"second"), Found(Some(&2)));
        assert_eq!(map.get(&"third"), Found(Some(&1)));
    }
}
