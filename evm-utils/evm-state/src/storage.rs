use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::Cursor;
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;

use bincode::config::{BigEndian, DefaultOptions, Options as _, WithOtherEndian};
use lazy_static::lazy_static;
use rocksdb::{self, ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, DB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;
pub type StdResult<T, E> = std::result::Result<T, E>;

type BincodeOpts = WithOtherEndian<DefaultOptions, BigEndian>;
lazy_static! {
    static ref CODER: BincodeOpts = DefaultOptions::new().with_big_endian();
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    DatabaseErr(#[from] rocksdb::Error),
    #[error("Missed Column Familiy for type '{0}'")]
    ColumnFamilyErr(String),
    #[error(transparent)]
    BincodeErr(#[from] bincode::Error),
    #[error("Unable to construct key from bytes")]
    KeyErr(#[from] TryFromSliceError),
}

pub struct Versions<V> {
    db: Arc<DB>,
    _version: PhantomData<V>,
}

impl<V> Clone for Versions<V> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            _version: PhantomData,
        }
    }
}

type Previous<V> = Option<V>; // TODO: Vec<V>

impl<V> Versions<V>
where
    V: Copy + Serialize + DeserializeOwned,
    Previous<V>: Serialize + DeserializeOwned,
{
    pub fn previous_of(&self, version: V) -> Result<Previous<V>> {
        let version = CODER.serialize(&version)?;
        let bytes = self.db.get_pinned(version)?;
        let previous = bytes.map(|bytes| CODER.deserialize(&bytes)).transpose()?;
        Ok(previous)
    }

    pub fn versions(&self) -> impl Iterator<Item = (V, Previous<V>)> + '_ {
        self.db
            .iterator(IteratorMode::End)
            .map(move |(key, value)| {
                let version = CODER.deserialize(&key).unwrap_or_else(|err| {
                    panic!("Unable to deserialize version from {:?}: {:?}", key, err)
                });
                let previous = CODER.deserialize(&value).unwrap_or_else(|err| {
                    panic!("Unable to deserialize previous from {:?}: {:?}", value, err)
                });
                (version, previous)
            })
    }

    pub fn new_version(&self, version: V, previous: Previous<V>) -> Result<()> {
        let version = CODER.serialize(&version)?;
        debug_assert_eq!(self.db.get(&version)?, None);
        let previous = CODER.serialize(&previous)?;
        self.db.put(version, previous)?;
        Ok(())
    }
}

impl<V> Versions<V> {
    pub fn typed<S: AsRef<str>, Key, Value>(&self, type_name: S) -> Result<Storage<V, Key, Value>> {
        if self.db.cf_handle(type_name.as_ref()).is_none() {
            return Err(Error::ColumnFamilyErr(type_name.as_ref().to_owned()));
        }
        Ok(Storage::for_type(&self.db, type_name))
    }

    pub fn open<P: AsRef<Path>, S: AsRef<str>>(
        path: P,
        type_names: impl IntoIterator<Item = S>,
    ) -> Result<Self>
    where
        V: AsBytePrefix,
    {
        let db_opts = default_db_opts();

        let descriptors = type_names
            .into_iter()
            .map(|type_name| {
                let mut cf_opts = Options::default();
                cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(V::SIZE));
                ColumnFamilyDescriptor::new(type_name.as_ref(), cf_opts)
            })
            .collect::<Vec<_>>();

        let db = Arc::new(DB::open_cf_descriptors(&db_opts, &path, descriptors)?);

        Ok(Self {
            db,
            _version: PhantomData,
        })
    }
}

pub struct Storage<V, Key, Value> {
    pub versions: Versions<V>,
    type_name: String, // ColumnFamily id
    squash_guard: Arc<RwLock<()>>,

    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
}

impl<V, Key, Value> Clone for Storage<V, Key, Value> {
    fn clone(&self) -> Self {
        Self {
            versions: self.versions.clone(),
            type_name: self.type_name.to_owned(),
            squash_guard: Arc::clone(&self.squash_guard),

            _key: PhantomData,
            _value: PhantomData,
        }
    }
}

pub trait AsBytePrefix {
    const SIZE: usize;

    type Bytes: AsRef<[u8]>;
    fn to_bytes(&self) -> Self::Bytes;

    type FromBytesError;
    fn from_bytes(_: &[u8]) -> StdResult<Self, Self::FromBytesError>
    where
        Self: Sized;
}

#[derive(Serialize, Deserialize)]
struct VersionedKey<V, Key> {
    version: V,
    key: Key,
}

impl<V, Key> TryInto<Vec<u8>> for VersionedKey<V, Key>
where
    V: AsBytePrefix,
    Key: Serialize,
{
    type Error = bincode::Error;

    fn try_into(self) -> StdResult<Vec<u8>, Self::Error> {
        let mut bytes = Vec::from(self.version.to_bytes().as_ref());
        let mut cursor = Cursor::new(&mut bytes);
        cursor.set_position(<V as AsBytePrefix>::SIZE as u64);
        bincode::serialize_into(&mut cursor, &self.key)?;
        Ok(bytes)
    }
}

impl<V, Key> VersionedKey<V, Key>
where
    V: AsBytePrefix,
{
    fn version_of(bytes: &[u8]) -> Result<V>
    where
        Error: From<V::FromBytesError>,
    {
        V::from_bytes(bytes).map_err(Error::from)
    }

    fn key_from(bytes: &[u8]) -> Result<Key>
    where
        Key: DeserializeOwned,
    {
        bincode::deserialize_from(&bytes[<V as AsBytePrefix>::SIZE..]).map_err(Error::from)
    }
}

impl<V, Key, Value> Storage<V, Key, Value> {
    fn for_type<S: AsRef<str>>(db: &Arc<DB>, type_name: S) -> Self {
        let versions = Versions {
            db: Arc::clone(&db),
            _version: PhantomData,
        };
        let type_name = type_name.as_ref().to_owned();
        let squash_guard = Arc::new(RwLock::default());

        Self {
            versions,
            type_name,
            squash_guard,

            _key: PhantomData,
            _value: PhantomData,
        }
    }

    fn db(&self) -> &DB {
        self.versions.db.as_ref()
    }

    fn cf(&self) -> Result<&ColumnFamily> {
        self.db()
            .cf_handle(&self.type_name)
            .ok_or_else(|| Error::ColumnFamilyErr(self.type_name.to_owned()))
    }
}

impl<V, Key, Value> Storage<V, Key, Value>
where
    V: Copy + AsBytePrefix + Serialize + DeserializeOwned,
    Key: Copy + Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    pub fn insert_with(&self, version: V, key: Key, value: Value) -> Result<()> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let value = CODER.serialize(&value)?;
        self.db().put_cf(self.cf()?, versioned_key, value)?;
        Ok(())
    }

    pub fn get_for(&self, version: V, key: Key) -> Result<Option<Value>> {
        let _guard = self.squash_guard.read().expect("squash guard was poisoned");

        let mut next_version = Some(version);

        while let Some(version) = next_version.take() {
            let value = self.get_exact_for(version, key)?;
            if value.is_some() {
                return Ok(value);
            } else {
                next_version = self.versions.previous_of(version)?;
                continue;
            }
        }

        Ok(None)
    }

    fn get_exact_for(&self, version: V, key: Key) -> Result<Option<Value>> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let bytes = self.db().get_pinned_cf(self.cf()?, versioned_key)?;
        let mb_value = bytes.map(|bytes| CODER.deserialize(&bytes)).transpose()?;
        Ok(mb_value)
    }

    pub fn prefix_iter_for(&self, version: V) -> Result<impl Iterator<Item = (Key, Value)> + '_> {
        Ok(self
            .db()
            .prefix_iterator_cf(self.cf()?, version.to_bytes())
            .map(move |(key, value)| {
                let key = VersionedKey::<V, Key>::key_from(&key).unwrap_or_else(|err| {
                    panic!("Unable to deserialize key from {:?}: {:?}", key, err)
                });
                let value = CODER.deserialize(&value).unwrap_or_else(|err| {
                    panic!("Unable to deserialize value from {:?}: {:?}", value, err)
                });
                (key, value)
            }))
    }

    fn has_value_for(&self, version: V, key: Key) -> Result<bool> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let data_ref = self.db().get_pinned_cf(self.cf()?, versioned_key)?;
        Ok(data_ref.is_some())
    }

    pub fn squash_into_rev_pass(&self, target: V) -> Result<()>
    where
        Previous<V>: DeserializeOwned,
        Key: HasMax,
    {
        let _guard = self
            .squash_guard
            .write()
            .expect("squash guard was poisoned");

        let mut track = vec![target];
        while let Some(prev) = self.versions.previous_of(track[track.len() - 1])? {
            track.push(prev);
        }

        let mut rev_track = track.into_iter().rev().peekable();
        while let (Some(current), Some(parent)) = (rev_track.next(), rev_track.peek().copied()) {
            for (key, value) in self.prefix_iter_for(parent)? {
                if !self.has_value_for(current.clone(), key.clone())? {
                    self.insert_with(current.clone(), key, value)?;
                }
            }

            self.delete_all_for(parent.clone())?;

            // TODO: cleanup all None's
        }

        Ok(())
    }

    pub fn squash_into_tracing(&self, target: V) -> Result<()>
    where
        Previous<V>: DeserializeOwned,
        Key: HasMax,
    {
        let _guard = self
            .squash_guard
            .write()
            .expect("squash guard was poisoned");

        let mut next_parent_for = target;

        while let Some(parent) = self.versions.previous_of(next_parent_for)? {
            for (key, value) in self.prefix_iter_for(parent)? {
                if !self.has_value_for(target.clone(), key.clone())? {
                    self.insert_with(target.clone(), key.clone(), value)?;
                }
            }

            self.delete_all_for(parent.clone())?;

            next_parent_for = parent;
        }

        Ok(())
    }

    fn delete_all_for(&self, version: V) -> Result<()>
    where
        Key: HasMax,
    {
        let version_prefix: Vec<u8> = version.to_bytes().as_ref().iter().copied().collect();
        let key_max_bytes = bincode::serialized_size(&Key::MAX)? as usize + 1;
        let mut lexicographic_max: Vec<u8> = version_prefix.clone();
        lexicographic_max.extend(std::iter::repeat(0u8).take(key_max_bytes));
        self.db()
            .delete_range_cf(self.cf()?, version_prefix, lexicographic_max)?;
        Ok(())
    }
}

pub trait HasMax {
    const MAX: Self;
}

pub type KVStorage<V, Value> = Storage<V, (), Value>;

impl<V, Value> KVStorage<V, Value>
where
    V: Copy + AsBytePrefix + Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    // TODO: previous versions as argument
    pub fn insert(&self, version: V, value: Value) -> Result<()> {
        self.insert_with(version.clone(), (), value)?;
        self.versions.new_version(version, None)?;
        Ok(())
    }

    pub fn get(&self, version: V) -> Result<Option<Value>> {
        self.get_exact_for(version, ())
    }

    fn keys(&self) -> impl Iterator<Item = V> + '_ {
        self.versions.versions().map(|(version, _)| version)
    }
}

pub fn default_db_opts() -> Options {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts
}

macro_rules! nums_as_byte_prefixes {
    ($($ty:ty),+) => {
        $(
            impl AsBytePrefix for $ty {
                const SIZE: usize = size_of::<$ty>();

                type Bytes = [u8; size_of::<$ty>()];

                fn to_bytes(&self) -> Self::Bytes {
                    self.to_be_bytes()
                }

                type FromBytesError = TryFromSliceError;

                fn from_bytes(bytes: &[u8]) -> StdResult<$ty, Self::FromBytesError> {
                    Self::Bytes::try_from(bytes)
                        .map(<$ty>::from_be_bytes)
                }
            }
        )+
    }
}

nums_as_byte_prefixes! {
    u8, u16, u32, u64, u128
}

macro_rules! nums_has_max {
    ($($ty:ty),+) => {
        $(
            impl HasMax for $ty {
                const MAX: $ty = <$ty>::MAX;
            }
        )+
    }
}

nums_has_max! {
    u8, u16, u32, u64, u128
}

macro_rules! primitive_type_has_max {
    ($($ty:ty),+) => {
        $(
            impl HasMax for $ty {
                const MAX: $ty = <$ty>::repeat_byte(u8::MAX);
            }
        )+
    }

}

use primitive_types::{H160, H256, H512};

primitive_type_has_max! {
    H160, H256, H512
}

impl<V> fmt::Debug for Versions<V>
where
    V: 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::any::TypeId;
        f.debug_struct("Versions")
            .field("Version", &TypeId::of::<V>())
            .field("database", &self.db.path().display())
            .finish()
    }
}

impl<V, Key, Value> fmt::Debug for Storage<V, Key, Value>
where
    V: 'static,
    Key: 'static,
    Value: 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::any::TypeId;

        f.debug_struct("Storage")
            .field("Version", &TypeId::of::<V>())
            .field("Key", &TypeId::of::<Key>())
            .field("Value", &TypeId::of::<Value>())
            .field("database", &self.db().path().display())
            .field("type_name", &self.type_name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::array::TryFromSliceError;
    use std::collections::{BTreeMap, HashMap};
    use std::iter::FromIterator;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::{env, fs, path::PathBuf};

    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    use crate::test_utils::TmpDir;

    use super::*;

    fn open<P, S, V, Key, Value>(path: P, type_name: S) -> Result<Storage<V, Key, Value>>
    where
        V: AsBytePrefix,
        P: AsRef<Path>,
        S: AsRef<str>,
    {
        Versions::open(path, &[type_name.as_ref()])?.typed(type_name.as_ref())
    }

    impl<A, B> AsBytePrefix for (A, B)
    where
        A: AsBytePrefix,
        B: AsBytePrefix,
        TryFromSliceError: From<A::FromBytesError>,
        TryFromSliceError: From<B::FromBytesError>,
    {
        const SIZE: usize = A::SIZE + B::SIZE;
        type Bytes = Vec<u8>;
        fn to_bytes(&self) -> Self::Bytes {
            let mut bytes = Vec::with_capacity(Self::SIZE);
            bytes.extend(self.0.to_bytes().as_ref());
            bytes.extend(self.1.to_bytes().as_ref());
            bytes
        }

        type FromBytesError = TryFromSliceError;
        fn from_bytes(bytes: &[u8]) -> StdResult<(A, B), Self::FromBytesError> {
            let a = A::from_bytes(&bytes[..A::SIZE])?;
            let b = B::from_bytes(&bytes[A::SIZE..(A::SIZE + B::SIZE)])?;
            Ok((a, b))
        }
    }

    #[test]
    #[ignore]
    fn it_handles_full_range_mapping() -> Result<()> {
        use rand::Rng;

        type Version = u8;
        type Key = u8;
        type Value = u64;
        type Assoc = HashMap<Version, HashMap<Key, Value>>;

        let mut rng = rand::thread_rng();

        let mut assoc: Assoc = (0..=Version::MAX)
            .map(|version| {
                (
                    version,
                    (0..=Key::MAX).map(|key| (key, rng.gen())).collect(),
                )
            })
            .collect();
        println!("assoc is ready");

        let dir = TmpDir::new("it_handles_full_range_mapping");
        {
            let s = open(&dir, "vkv")?;

            for (version, map) in &assoc {
                for (key, value) in map {
                    s.insert_with(*version, key, value)?;
                }
                s.versions.new_version(*version, None)?;
            }
            s.db().flush()?;
            println!("assoc is stored");
        }
        {
            let s = open(&dir, "vkv")?;
            for (version, _) in s.versions.versions() {
                let new_map = HashMap::from_iter(s.prefix_iter_for(&version)?);
                assert_eq!(assoc.remove(&version), Some(new_map));
            }
            assert!(assoc.is_empty());
        }
        Ok(())
    }

    type K = u16;
    type V = u64;
    type ThreadId = u64;

    #[quickcheck]
    fn qc_version_precedes_key_in_serialized_data(version: u64, key: u64) -> Result<()> {
        let version_data = CODER.serialize(&version)?;
        let versioned_key = VersionedKey { version, key };
        let versioned_key_data = CODER.serialize(&versioned_key)?;
        assert!(versioned_key_data.starts_with(&version_data));
        Ok(())
    }

    macro_rules! pair_works_as_byte_prefix {
        ($foo:ty, $bar:ty) => {
            paste::item! {
                mod [< $foo _ $bar _ as_version >] {
                    use super::*;

                    type Pair = ($foo, $bar);
                    type Key = Vec<u8>;
                    type ComplexKey = VersionedKey<Pair, Key>;

                    #[quickcheck]
                    fn [< qc_pair_of _ $foo _ $bar _works_as_byte_prefix >](version: Pair, key: Key) -> Result<()> {
                        assert_eq!(version.to_bytes().len(), Pair::SIZE);

                        let data: Vec<u8> = ComplexKey { version, key: key.clone() }.try_into()?;

                        assert_eq!(ComplexKey::version_of(&data)?, version);
                        assert_eq!(ComplexKey::key_from(&data)?, key);
                        Ok(())
                    }
                }
            }
        };
    }

    // TODO: recursive
    // pairs_works_as_byte_prefix! {
    //     @foo: u8, u16, u32, u64, u128,
    //     @bar: u8, u16, u32, u64, u128,
    // }
    pair_works_as_byte_prefix!(u8, u16);
    pair_works_as_byte_prefix!(u8, u64);
    pair_works_as_byte_prefix!(u64, u16);

    #[quickcheck]
    fn qc_keyless_storage_behaves_like_a_map_with_version_as_key(
        map: BTreeMap<K, V>,
    ) -> Result<()> {
        let dir = TmpDir::new("qc_keyless_storage_behaves_like_a_map_with_version_as_key");
        {
            let s = open(&dir, "kv")?;
            for (k, v) in &map {
                s.insert(*k, v)?;
            }
            s.db().flush()?;
        }
        {
            let s = open(&dir, "kv")?;
            let mut new_map = BTreeMap::new();
            for key in s.keys() {
                new_map.insert(key, s.get(key)?.unwrap());
            }
            assert_eq!(map, new_map);
        }
        Ok(())
    }

    #[quickcheck]
    fn qc_two_concurrent_threads_works_on_shared_db_via_version_assoc(
        (foo, bar): (BTreeMap<K, V>, BTreeMap<K, V>),
    ) -> Result<()> {
        type Storage = KVStorage<(ThreadId, K), V>;

        let dir = TmpDir::new("qc_two_concurrent_threads_works_on_shared_db_via_version_assoc");
        let s: Arc<Storage> = Arc::new(open(&dir, "kv_assoc")?);

        fn spawn_insert(s: &Arc<Storage>, map: BTreeMap<K, V>) -> JoinHandle<Result<ThreadId>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<ThreadId> {
                let id = thread_id();
                for (k, v) in map {
                    s.insert((id, k), v)?;
                }
                s.db().flush()?;
                Ok(id)
            })
        }

        let foo_wh = spawn_insert(&s, foo.clone());
        let bar_wh = spawn_insert(&s, bar.clone());

        let foo_id = foo_wh.join().unwrap()?;
        let bar_id = bar_wh.join().unwrap()?;

        fn spawn_read(
            s: &Arc<Storage>,
            id: ThreadId,
            keys: impl IntoIterator<Item = K> + Send + 'static,
        ) -> JoinHandle<Result<BTreeMap<K, V>>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<BTreeMap<K, V>> {
                keys.into_iter()
                    .map(|key| s.get((id, key)).map(|value| (key, value.unwrap())))
                    .collect::<Result<_>>()
            })
        }

        let foo_rh = spawn_read(&s, foo_id, foo.keys().copied().collect::<Vec<K>>());
        let bar_rh = spawn_read(&s, bar_id, bar.keys().copied().collect::<Vec<K>>());

        let new_foo = foo_rh.join().unwrap()?;
        let new_bar = bar_rh.join().unwrap()?;

        assert_eq!(foo, new_foo);
        assert_eq!(bar, new_bar);

        Ok(())
    }

    #[quickcheck]
    fn qc_two_concurrent_threads_works_on_shared_db_via_own_version_slot(
        (foo, bar): (BTreeMap<K, V>, BTreeMap<K, V>),
    ) -> Result<()> {
        type TStorage = Storage<ThreadId, K, V>;
        let dir = TmpDir::new("qc_two_concurrent_threads_works_on_shared_db_via_own_version_slot");
        let s: Arc<TStorage> = Arc::new(open(&dir, "slot_assoc")?);

        fn spawn_insert(s: &Arc<TStorage>, map: BTreeMap<K, V>) -> JoinHandle<Result<ThreadId>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<ThreadId> {
                let id = thread_id();
                for (k, v) in map {
                    s.insert_with(id, k, v)?;
                }
                s.versions.new_version(id, None)?;
                s.db().flush()?;
                Ok(id)
            })
        }

        let foo_wh = spawn_insert(&s, foo.clone());
        let bar_wh = spawn_insert(&s, bar.clone());

        let foo_id = foo_wh.join().unwrap()?;
        let bar_id = bar_wh.join().unwrap()?;

        fn spawn_read(
            s: &Arc<TStorage>,
            id: ThreadId,
            keys: impl IntoIterator<Item = K> + Send + 'static,
        ) -> JoinHandle<Result<BTreeMap<K, V>>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<BTreeMap<K, V>> {
                keys.into_iter()
                    .map(|key| s.get_exact_for(id, key).map(|value| (key, value.unwrap())))
                    .collect::<Result<_>>()
            })
        }

        let foo_rh = spawn_read(&s, foo_id, foo.keys().copied().collect::<Vec<K>>());
        let bar_rh = spawn_read(&s, bar_id, bar.keys().copied().collect::<Vec<K>>());

        let new_foo = foo_rh.join().unwrap()?;
        let new_bar = bar_rh.join().unwrap()?;

        assert_eq!(foo, new_foo);
        assert_eq!(bar, new_bar);

        Ok(())
    }

    #[quickcheck]
    fn qc_reads_the_same_as_inserts(assoc: HashMap<K, HashMap<K, V>>) -> Result<()> {
        let dir = TmpDir::new("qc_reads_the_same_as_inserts");
        {
            let s = open(&dir, "vkv")?;
            for (version, map) in &assoc {
                for (k, v) in map {
                    s.insert_with(*version, k, v)?;
                }
                s.versions.new_version(*version, None)?;
            }
            s.db().flush()?;
        }
        {
            let s = open(&dir, "vkv")?;

            let mut new_assoc = HashMap::<K, HashMap<K, V>>::new();
            for (version, _) in s.versions.versions() {
                new_assoc.insert(version, s.prefix_iter_for(&version).unwrap().collect());
            }

            assert_eq!(assoc, new_assoc);
        }
        Ok(())
    }

    fn thread_id() -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish()
    }
}
