use std::collections::BTreeMap;
use std::sync::Arc;
use std::borrow::Borrow;
use std::ops::Deref;
use std::fmt;

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
            State::Removed => State::Removed
        }
    }

    fn into_option(self) -> Option<V> {
        match self {
            State::Changed(v) => Some(v),
            State::Removed => None
        }
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Map<K, V, Store = Arc<dyn MapLike<Key = K, Value = V>>> {
    state: BTreeMap<K, State<V>>,
    parent: Option<Store>
}

impl<K:Ord, V> Default for Map<K,V> {
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
        .field("state",&self.state)
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
    where Store: Sized {
        Map {
            state: BTreeMap::new(),
            parent: None
        }
    }

    // Borrow value by key
    pub fn get(&self, key: &K) -> Option<&V>
    {
        if let  Some(s) = self.state.get(key) {
            return s.by_ref().into_option()
        }

        if let Some(parent) = &self.parent {
            return parent.get(key)
        }
        None
    }

    // Exclusively borrow value by key
    pub fn get_mut<Q: ?Sized>(&mut self, key: &Q) -> Option<&mut V>
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
    
    // Create new version from existing one
    pub(crate) fn new_from_parent_static(parent: Store) -> Self {
        Self {
            state: BTreeMap::new(),
            parent: Some(parent)
        }
    }
}


impl<K: Ord, V> Map<K, V, Arc<dyn MapLike<Key = K, Value = V>>> { 
    // Create new version from existing one
    pub fn new_from_parent(parent: Arc<dyn MapLike<Key = K, Value = V>> ) -> Self {
        Self {
            state: BTreeMap::new(),
            parent: Some(parent)
        }
    }
}



/// Map can store it's old version in database or in some other immutable structure.
/// This trait allows you to define your own storage
pub trait MapLike {
    type Key;
    type Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>;
}

impl<Store: MapLike + ?Sized> MapLike for Arc<Store> {
    type Key = Store::Key;
    type Value = Store::Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>
    {
        <Store as MapLike> ::get(self.deref(), key)
    }
}

impl<K, V, Store> MapLike for Map<K, V, Store>
where 
K: Ord,
Store: MapLike<Key = K, Value = V>
{
    type Key = Store::Key;
    type Value = Store::Value;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value>
    {
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