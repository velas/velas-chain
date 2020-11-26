use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::Cursor;
use std::marker::PhantomData;
use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;

use bincode::config::{BigEndian, DefaultOptions, Options as _, WithOtherEndian};
use lazy_static::lazy_static;
use rocksdb::{self, ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, DB};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::version_map::MapLike;

type Result<T> = std::result::Result<T, Error>;
type StdResult<T, E> = std::result::Result<T, E>;

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

type Roots<V> = Option<V>; // TODO: Vec<V>

impl<V> Versions<V> {
    pub fn roots_of(&self, version: &V) -> Result<Option<Roots<V>>>
    where
        V: Serialize,
        Roots<V>: DeserializeOwned,
    {
        let version = CODER.serialize(version)?;
        let bytes = self.db.get_pinned(version)?;
        let mb_roots = bytes.map(|bytes| CODER.deserialize(&bytes)).transpose()?;
        Ok(mb_roots)
    }

    pub fn versions(&self) -> impl Iterator<Item = (V, Roots<V>)> + '_
    where
        V: DeserializeOwned,
    {
        self.db
            .iterator(IteratorMode::End)
            .map(move |(key, value)| {
                let version = CODER.deserialize(&key).unwrap_or_else(|err| {
                    panic!("Unable to deserialize version from {:?}: {:?}", key, err)
                });
                let roots = CODER.deserialize(&value).unwrap_or_else(|err| {
                    panic!("Unable to deserialize roots from {:?}: {:?}", value, err)
                });
                (version, roots)
            })
    }

    pub fn new_version(&self, version: V, roots: Roots<V>) -> Result<()>
    where
        V: Serialize,
    {
        let version = CODER.serialize(&version)?;
        debug_assert_eq!(self.db.get(&version)?, None);
        let roots = CODER.serialize(&roots)?;
        self.db.put(version, roots)?;
        Ok(())
    }

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
    versions: Versions<V>,
    type_name: String, // ColumnFamily id

    _version: PhantomData<V>,
    _key: PhantomData<Key>,
    _value: PhantomData<Value>,
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

        Self {
            versions,
            type_name,
            _version: PhantomData,
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

    pub fn insert_with(&self, version: V, key: Key, value: Value) -> Result<()>
    where
        V: AsBytePrefix,
        Key: Serialize,
        Value: Serialize,
    {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let value = CODER.serialize(&value)?;
        self.db().put_cf(self.cf()?, versioned_key, value)?;
        Ok(())
    }

    pub fn get_for(&self, version: V, key: Key) -> Result<Option<Value>>
    where
        V: AsBytePrefix,
        Key: Serialize,
        Value: DeserializeOwned,
    {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let bytes = self.db().get_pinned_cf(self.cf()?, versioned_key)?;
        let mb_value = bytes.map(|bytes| CODER.deserialize(&bytes)).transpose()?;
        Ok(mb_value)
    }

    pub fn prefix_iter_for(&self, version: V) -> Result<impl Iterator<Item = (Key, Value)> + '_>
    where
        V: AsBytePrefix,
        Key: DeserializeOwned,
        Value: DeserializeOwned,
    {
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
}

impl<V, Key, Value> MapLike for (&V, &Storage<V, Key, Value>)
where
    V: Sync + Send,
    Key: Ord + Sync + Send,
    Value: Sync + Send,
{
    type Key = Key;
    type Value = Value;

    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        todo!() // Cow type
    }
}

pub type KVStorage<V, Value> = Storage<V, (), Value>;

impl<V, Value> KVStorage<V, Value> {
    // TODO: roots as argument
    fn insert(&self, version: V, value: Value) -> Result<()>
    where
        V: AsBytePrefix + Serialize + Clone, // TODO: remove Clone
        Value: Serialize,
    {
        self.insert_with(version.clone(), (), value)?;
        self.versions.new_version(version, None)?;
        Ok(())
    }

    fn get(&self, version: V) -> Result<Option<Value>>
    where
        V: AsBytePrefix,
        Value: DeserializeOwned,
    {
        self.get_for(version, ())
    }

    fn keys(&self) -> impl Iterator<Item = V> + '_
    where
        V: DeserializeOwned,
    {
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
    use super::*;

    use std::collections::{BTreeMap, HashMap};
    use std::iter::FromIterator;
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::{env, fs, path::PathBuf};

    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    #[derive(Clone)]
    struct TmpDir(PathBuf);

    impl TmpDir {
        fn new<P: AsRef<Path>>(sub_dir: P) -> Self {
            let path = env::temp_dir().join(sub_dir);
            let pprint = path.as_path().display();
            if path.exists() {
                panic!("Path is {} already exists", pprint);
            }
            fs::create_dir(&path)
                .unwrap_or_else(|err| panic!("Unable to create tmp dir {}: {:?}", pprint, err));
            println!("{}", pprint);
            Self(path)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            fs::remove_dir_all(self.0.as_path()).unwrap_or_else(|err| {
                panic!(
                    "Unable to remove tmp dir {}: {:?}",
                    self.0.as_path().display(),
                    err
                )
            });
        }
    }

    impl AsRef<Path> for TmpDir {
        fn as_ref(&self) -> &Path {
            self.0.as_path()
        }
    }

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
                let new_map = HashMap::from_iter(s.prefix_iter_for(version)?);
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
                    .map(|key| s.get_for(id, key).map(|value| (key, value.unwrap())))
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
                new_assoc.insert(version, s.prefix_iter_for(version).unwrap().collect());
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
