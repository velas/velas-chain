use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

/// Represent state of value at current version.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum State<V> {
    // Value exist, and was changed.
    Changed(V),
    // Value was removed.
    Removed,
}

impl<V> State<V> {
    fn by_ref(&self) -> State<&V> {
        match self {
            State::Changed(ref v) => State::Changed(v),
            State::Removed => State::Removed,
        }
    }
}

impl<T> From<State<T>> for Option<T> {
    fn from(state: State<T>) -> Option<T> {
        match state {
            State::Changed(value) => Some(value),
            State::Removed => None,
        }
    }
}

pub struct Map<K, V, Store = Arc<dyn MapLike<Key = K, Value = V>>> {
    state: BTreeMap<K, State<V>>,
    parent: Option<Store>,
}

impl<K: Ord, V> Default for Map<K, V> {
    fn default() -> Self {
        Map::new()
    }
}

impl<K, V, Store> fmt::Debug for Map<K, V, Store>
where
    K: fmt::Debug,
    V: fmt::Debug,
    Store: MapLike<Key = K, Value = V>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Map")
            .field("state", &self.state)
            .field("parent", &"omited")
            .finish()
    }
}

impl<K, V, Store> Map<K, V, Store>
where
    K: Ord,
    Store: MapLike<Key = K, Value = V>,
{
    // Create new versioned map.
    pub fn new() -> Map<K, V, Store>
    where
        Store: Sized,
    {
        Map {
            state: BTreeMap::new(),
            parent: None,
        }
    }

    // Borrow value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        if let Some(s) = self.state.get(key) {
            s.by_ref().into()
        } else {
            self.parent.as_ref().and_then(|parent| parent.get(key))
        }
    }

    // Exclusively borrow value by key
    pub fn get_mut<Q: ?Sized>(&mut self, _key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord,
    {
        unimplemented!() // TODO: Implement a guard that will save value at drop.
    }

    // Override state of key.
    pub(crate) fn push_change(&mut self, key: K, value: State<V>) {
        self.state.insert(key, value);
    }

    // Insert new key, didn't query key before inserting.
    pub fn insert(&mut self, key: K, value: V) {
        self.push_change(key, State::Changed(value));
    }

    // Remove key, didn't query key before inserting.
    pub fn remove(&mut self, key: K) {
        self.push_change(key, State::Removed);
    }
}

impl<K, V> Map<K, V>
where
    K: Ord + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    pub fn freeze(&mut self) {
        let this = Arc::new(std::mem::take(self)) as Arc<dyn MapLike<Key = K, Value = V>>;
        self.parent = Some(this);
    }

    // Create new version from freezed one
    pub fn try_fork(&self) -> Option<Self> {
        if !self.state.is_empty() {
            return None;
        }

        Some(Self {
            state: BTreeMap::new(),
            parent: self.parent.clone(),
        })
    }
}

/// Map can store it's old version in database or in some other immutable structure.
/// This trait allows you to define your own storage
pub trait MapLike: Sync + Send {
    type Key;
    type Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
}

impl<Store: MapLike + ?Sized + Send> MapLike for Arc<Store> {
    type Key = Store::Key;
    type Value = Store::Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        <Store as MapLike>::get(self.deref(), key)
    }
}

impl<K, V, Store> MapLike for Map<K, V, Store>
where
    K: Ord + Sync + Send,
    V: Sync + Send,
    Store: MapLike<Key = K, Value = V> + Send + Sync,
{
    type Key = Store::Key;
    type Value = Store::Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        Map::get(self, key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn store_and_get_simple() {
        let mut map: Map<_, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
    }

    // Test that map can save version, and type of map is always remain the same.
    #[test]
    fn new_dynamic_version_insert_remove_test() {
        let mut map: Map<_, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&3));

        let mut map: Map<_, _> = Map::new_from_parent(Arc::new(map));

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), None);
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&1));
    }

    // Same as new_dynamic_version_insert_remove_test but dont hide type of store.
    #[test]
    fn new_static_version_insert_remove_test() {
        let mut map: Map<_, _> = Map::new();
        map.insert("first", 1);
        map.insert("second", 2);
        map.insert("third", 3);
        assert_eq!(map.get(&"first"), Some(&1));
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&3));

        let mut map = Map::new_from_parent_static(map);

        map.remove("first");
        map.insert("third", 1);

        assert_eq!(map.get(&"first"), None);
        assert_eq!(map.get(&"second"), Some(&2));
        assert_eq!(map.get(&"third"), Some(&1));
    }
}
