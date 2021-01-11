use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Display},
    fs,
    io::{Cursor, Error as IoError},
    marker::PhantomData,
    mem::size_of,
    ops::{Deref, Sub},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use bincode::config::{BigEndian, DefaultOptions, Options as _, WithOtherEndian};
use lazy_static::lazy_static;
use log::*;
use rocksdb::{
    self,
    backup::{BackupEngine, BackupEngineOptions, RestoreOptions},
    ColumnFamily, ColumnFamilyDescriptor, IteratorMode, Options, DB,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tempfile::TempDir;

use crate::mb_value::MaybeValue;

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
    #[error("Type {1} :: {0}")]
    BincodeErr(bincode::Error, &'static str),
    #[error("Unable to construct key from bytes")]
    KeyErr(#[from] TryFromSliceError),
    #[error("Internal IO error: {0:?}")]
    InternalErr(#[from] IoError),
}

/// Marker-like wrapper for cleaning temporary directory.
/// Temporary directory is only used in tests.
enum Location {
    Temporary(TempDir),
    Persisent(PathBuf),
}

impl AsRef<Path> for Location {
    fn as_ref(&self) -> &Path {
        match self {
            Self::Temporary(temp_dir) => temp_dir.path(),
            Self::Persisent(path) => path.as_ref(),
        }
    }
}

pub struct VersionedStorage<V> {
    db: Arc<DB>,
    squash_guard: Arc<RwLock<()>>,
    _location: Arc<Location>,
    _version: PhantomData<V>,
}

impl<V> Clone for VersionedStorage<V> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            squash_guard: Arc::clone(&self.squash_guard),
            _location: Arc::clone(&self._location),
            _version: PhantomData,
        }
    }
}

type Previous<V> = Option<V>; // TODO: Vec<V>

trait BincodeResultExt<T> {
    fn typed_ctx(self) -> Result<T>;
}

impl<T> BincodeResultExt<T> for StdResult<T, bincode::Error> {
    fn typed_ctx(self) -> Result<T> {
        self.map_err(|err| Error::BincodeErr(err, std::any::type_name::<T>()))
    }
}

impl<V> VersionedStorage<V>
where
    V: Copy + Serialize + DeserializeOwned,
    Previous<V>: Serialize + DeserializeOwned,
{
    pub fn is_exists(&self, version: V) -> Result<bool> {
        let key = CODER.serialize(&version).typed_ctx()?;
        Ok(self.db.get_pinned(key)?.is_some())
    }

    pub fn previous_of(&self, version: V) -> Result<Previous<V>> {
        let version = CODER.serialize(&version).typed_ctx()?;

        if let Some(bytes) = self.db.get_pinned(version)? {
            let previous = CODER.deserialize::<Previous<V>>(&bytes).typed_ctx()?;
            Ok(previous)
        } else {
            Ok(None)
        }
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

    pub fn new_version(&self, version: V, previous: Previous<V>) -> Result<()>
    where
        V: PartialEq + Debug,
    {
        assert_ne!(Some(version), previous);
        let key = CODER.serialize(&version).typed_ctx()?;

        match self.db.get_pinned(&key)? {
            None => {
                let value = CODER.serialize(&previous).typed_ctx()?;
                self.db.put(key, value)?;
            }
            Some(data) => {
                warn!("Found confict previous: previous = {:?}, version = {:?}, previous_in_db = {:?}", previous,
                version,
                CODER.deserialize::<Previous<V>>(&data).typed_ctx() );
                // TODO: assert or do some check
                // assert_eq!(
                //     previous,
                //     CODER.deserialize(&data).typed_ctx()?,
                //     "attempt to insert for {:?}",
                //     version
                // );
            }
        }

        Ok(())
    }
}

impl<V> VersionedStorage<V> {
    pub fn save_into<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        assert!(
            path.is_dir() && path.exists(),
            "storage can be saved only into some existing directory"
        );
        info!(
            "saving storage data into {} (as new backup)",
            path.display()
        );
        let mut engine = BackupEngine::open(&BackupEngineOptions::default(), path)?;
        engine.create_new_backup_flush(self.db.as_ref(), true)?;
        Ok(())
    }

    pub fn restore_from<P1: AsRef<Path>, P2: AsRef<Path>>(path: P1, target: P2) -> Result<()> {
        let path = path.as_ref();
        let target = target.as_ref();

        // TODO: check target dir is empty or doesn't exists at all
        fs::create_dir_all(target).expect("Unable to create target dir");

        assert!(
            path.is_dir() && path.exists(),
            "storage can be loaded only from existing directory"
        );
        info!(
            "loading storage data from {} into {} (restore from backup)",
            path.display(),
            target.display()
        );
        let mut engine = BackupEngine::open(&BackupEngineOptions::default(), path)?;
        assert!(
            target.is_dir(),
            "loaded storage data must lays in target dir"
        );
        engine.restore_from_latest_backup(&target, &target, &RestoreOptions::default())?;

        Ok(())
    }
}

pub trait PersistentAssoc {
    const COLUMN_NAME: &'static str;
    type Key: Serialize + DeserializeOwned;
    type Value: Serialize + DeserializeOwned;
}

#[macro_export]
macro_rules! persistent_types {
    ($($Marker:ident in $Column:expr => $Key:ty : $Value:ty,)+) => {
        const COLUMN_NAMES: &[&'static str] = &[$($Column),+];

        $(
            pub(crate) enum $Marker {}
            impl PersistentAssoc for $Marker {
                const COLUMN_NAME: &'static str = $Column;
                type Key = $Key;
                type Value = $Value;
            }
        )+
    };
    ($($Marker:ident in $Column:expr => $Key:ty : $Value:ty),+) => {
        persistent_types! { $($Marker in $Column => $Key : $Value,)+ }
    }
}

impl<V> VersionedStorage<V>
where
    V: AsBytePrefix,
{
    pub fn open_persistent<P: AsRef<Path>, S: AsRef<str>>(
        path: P,
        column_names: impl IntoIterator<Item = S>,
    ) -> Result<Self> {
        Self::open(Location::Persisent(path.as_ref().to_owned()), column_names)
    }

    pub fn create_temporary<S: AsRef<str>>(
        column_names: impl IntoIterator<Item = S>,
    ) -> Result<Self> {
        let temp_dir = TempDir::new()?;
        Self::open(Location::Temporary(temp_dir), column_names)
    }

    fn open<S: AsRef<str>>(
        location: Location,
        column_names: impl IntoIterator<Item = S>,
    ) -> Result<Self> {
        let db_opts = default_db_opts();

        let descriptors = column_names
            .into_iter()
            .map(|type_name| {
                let mut cf_opts = Options::default();
                cf_opts.set_prefix_extractor(rocksdb::SliceTransform::create_fixed_prefix(V::SIZE));
                ColumnFamilyDescriptor::new(type_name.as_ref(), cf_opts)
            })
            .collect::<Vec<_>>();

        let db = Arc::new(DB::open_cf_descriptors(&db_opts, &location, descriptors)?);
        let squash_guard = Arc::new(RwLock::default());

        Ok(Self {
            db,
            squash_guard,
            _location: Arc::new(location),
            _version: PhantomData,
        })
    }

    pub fn typed<M: PersistentAssoc>(&self) -> PersistentMap<'_, V, M> {
        assert!(self.db.cf_handle(M::COLUMN_NAME).is_some());

        PersistentMap {
            storage: &self,
            _marker: PhantomData,
        }
    }
}

pub struct PersistentMap<'a, V, M: PersistentAssoc> {
    // TODO: revise this ref type
    storage: &'a VersionedStorage<V>,
    _marker: PhantomData<M>,
}

impl<'a, V, M: PersistentAssoc> Deref for PersistentMap<'a, V, M> {
    type Target = VersionedStorage<V>;
    fn deref(&self) -> &Self::Target {
        &self.storage
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
    type Error = Error;

    fn try_into(self) -> StdResult<Vec<u8>, Self::Error> {
        let mut bytes = Vec::from(self.version.to_bytes().as_ref());
        let mut cursor = Cursor::new(&mut bytes);
        cursor.set_position(<V as AsBytePrefix>::SIZE as u64);
        bincode::serialize_into(&mut cursor, &self.key).typed_ctx()?;
        Ok(bytes)
    }
}

impl<V, Key> VersionedKey<V, Key>
where
    V: AsBytePrefix,
{
    #[allow(dead_code)]
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
        bincode::deserialize_from(&bytes[<V as AsBytePrefix>::SIZE..]).typed_ctx()
    }
}

impl<'a, V, M: PersistentAssoc> PersistentMap<'a, V, M> {
    fn db(&self) -> &DB {
        self.storage.db.as_ref()
    }

    fn cf(&self) -> &ColumnFamily {
        self.db()
            .cf_handle(M::COLUMN_NAME)
            .unwrap_or_else(|| panic!("Missed Column Family '{}'", M::COLUMN_NAME))
    }
}

mod track {
    use std::fmt::{self, Display};
    use std::ops::{Range, Sub};

    #[derive(Debug, Clone)]
    enum RevTrack<V> {
        Single(V),
        Sequence(std::ops::Range<V>),
    }

    use RevTrack::*;

    impl<V> RevTrack<V> {
        fn single(v: V) -> Self {
            Self::Single(v)
        }

        fn is_prev(&self, other: V) -> bool
        where
            V: Copy + Sub<Output = V> + PartialEq + Stepped,
        {
            (match self {
                Single(v) => *v,
                Sequence(range) => range.start,
            }) - other
                == V::ONE
        }

        fn prepend(&mut self, prev: V)
        where
            V: Copy,
        {
            match self {
                Single(v) => {
                    *self = Sequence(Range {
                        start: prev,
                        end: *v,
                    })
                }
                Sequence(range) => range.start = prev,
            }
        }
    }

    pub(super) struct Checked<V>(Vec<RevTrack<V>>);

    impl<V> Default for Checked<V> {
        fn default() -> Self {
            Self(vec![])
        }
    }

    impl<V> Checked<V> {
        pub fn prepend(&mut self, prev: V)
        where
            V: Copy + Sub<Output = V> + PartialEq + Stepped,
        {
            match self.0.last_mut() {
                Some(ref mut last) if last.is_prev(prev) => last.prepend(prev),
                Some(_) | None => self.0.push(Single(prev)),
            }
        }
    }

    impl<V: Display> Display for RevTrack<V> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Single(v) => write!(f, "{}", v),
                Sequence(range) => write!(f, "{}..{}", range.end, range.start),
            }
        }
    }

    impl<V: Display> Display for Checked<V> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "[")?;
            let mut iter = self.0.iter().peekable();
            while let Some(track) = iter.next() {
                write!(f, "{}", track)?;
                if iter.peek().is_some() {
                    write!(f, ", ")?;
                }
            }
            write!(f, "]")?;
            Ok(())
        }
    }

    #[test]
    fn it_prints_tracks_as_expected() {
        impl<V: Display> Checked<V> {
            fn assert_display(&self, s: &str) {
                assert_eq!(format!("{}", self), s);
            }
        }
        let mut c = Checked::<u64>::default();
        c.assert_display("[]");
        c.prepend(42);
        c.assert_display("[42]");
        c.prepend(19);
        c.assert_display("[42, 19]");
        c.prepend(18);
        c.assert_display("[42, 19..18]");
        c.prepend(17);
        c.assert_display("[42, 19..17]");
        c.prepend(15);
        c.prepend(14);
        c.prepend(13);
        c.assert_display("[42, 19..17, 15..13]");
    }

    pub trait Stepped {
        const ONE: Self;
    }

    macro_rules! nums_as_stepped {
        ($($ty:ty),+) => {
            $(
                impl Stepped for $ty {
                    const ONE: $ty = 1;
                }
            )+
        }
    }

    nums_as_stepped! {
        u8, u16, u32, u64, u128
    }
}

impl<'a, V, M: PersistentAssoc> PersistentMap<'a, V, M>
where
    V: Copy + AsBytePrefix + Serialize + DeserializeOwned,
    M::Key: Copy,
{
    pub fn insert_with(&self, version: V, key: M::Key, value: MaybeValue<M::Value>) -> Result<()> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let value = CODER.serialize(&value).typed_ctx()?;
        self.db().put_cf(self.cf(), versioned_key, value)?;
        Ok(())
    }

    pub fn get_for(&self, version: V, key: M::Key) -> Result<Option<MaybeValue<M::Value>>>
    where
        V: Display + Debug + PartialEq + Sub<Output = V> + track::Stepped,
        M::Key: Debug,
        M::Value: Debug,
    {
        let _guard = self
            .storage
            .squash_guard
            .read()
            .expect("squash guard was poisoned");

        let mut next_version = Some(version);

        let mut track = track::Checked::<V>::default();

        while let Some(version) = next_version.take() {
            track.prepend(version);
            let value = self.get_exact_for(version, key)?;
            if value.is_some() {
                debug!(
                    "get_for: key {:?} found with track {}: value {:?}",
                    key, track, &value
                );
                return Ok(value);
            } else {
                let previous = self.storage.previous_of(version)?;
                assert_ne!(Some(version), previous);
                next_version = previous;
                continue;
            }
        }

        debug!("get_for: key {:?} not found {}", key, track);

        Ok(None)
    }

    fn get_exact_for(&self, version: V, key: M::Key) -> Result<Option<MaybeValue<M::Value>>> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let bytes = self.db().get_pinned_cf(self.cf(), versioned_key)?;
        let mb_value = bytes
            .map(|bytes| {
                CODER
                    .deserialize::<MaybeValue<M::Value>>(&bytes)
                    .typed_ctx()
            })
            .transpose()?;
        Ok(mb_value)
    }

    pub fn prefix_iter_for(
        &self,
        version: V,
    ) -> Result<impl Iterator<Item = (M::Key, MaybeValue<M::Value>)> + '_> {
        Ok(self
            .db()
            .prefix_iterator_cf(self.cf(), version.to_bytes())
            .map(move |(key, value)| {
                let key = VersionedKey::<V, M::Key>::key_from(&key).unwrap_or_else(|err| {
                    panic!("Unable to deserialize key from {:?}: {:?}", key, err)
                });
                let value = CODER.deserialize(&value).unwrap_or_else(|err| {
                    panic!("Unable to deserialize value from {:?}: {:?}", value, err)
                });
                (key, value)
            }))
    }

    fn has_value_for(&self, version: V, key: M::Key) -> Result<bool> {
        let versioned_key: Vec<u8> = VersionedKey { version, key }.try_into()?;
        let data_ref = self.db().get_pinned_cf(self.cf(), versioned_key)?;
        Ok(data_ref.is_some())
    }

    pub fn squash_into_rev_pass(&self, target: V) -> Result<()>
    where
        Previous<V>: DeserializeOwned,
        M::Key: HasMax,
    {
        let _guard = self
            .storage
            .squash_guard
            .write()
            .expect("squash guard was poisoned");

        let mut track = vec![target];
        while let Some(prev) = self.storage.previous_of(track[track.len() - 1])? {
            track.push(prev);
        }

        let mut rev_track = track.into_iter().rev().peekable();
        while let (Some(current), Some(parent)) = (rev_track.next(), rev_track.peek().copied()) {
            for (key, value) in self.prefix_iter_for(parent)? {
                if !self.has_value_for(current, key)? {
                    self.insert_with(current, key, value)?;
                }
            }

            self.delete_all_for(parent)?;

            // TODO: cleanup all None's
        }

        Ok(())
    }

    pub fn squash_into_tracing(&self, target: V) -> Result<()>
    where
        Previous<V>: DeserializeOwned,
        M::Key: HasMax,
    {
        let _guard = self
            .storage
            .squash_guard
            .write()
            .expect("squash guard was poisoned");

        let mut next_parent_for = target;

        while let Some(parent) = self.storage.previous_of(next_parent_for)? {
            for (key, value) in self.prefix_iter_for(parent)? {
                if !self.has_value_for(target, key)? {
                    self.insert_with(target, key, value)?;
                }
            }

            self.delete_all_for(parent)?;

            next_parent_for = parent;
        }

        Ok(())
    }

    fn delete_all_for(&self, version: V) -> Result<()>
    where
        M::Key: HasMax,
    {
        let version_prefix: Vec<u8> = version.to_bytes().as_ref().iter().copied().collect();
        let key_max_bytes = bincode::serialized_size(&M::Key::MAX)
            .expect("Unable to calculate serialized len") as usize
            + 1;
        let mut lexicographic_max: Vec<u8> = version_prefix.clone();
        lexicographic_max.extend(std::iter::repeat(0u8).take(key_max_bytes));
        self.db()
            .delete_range_cf(self.cf(), version_prefix, lexicographic_max)?;
        Ok(())
    }
}

pub trait HasMax {
    const MAX: Self;
}

impl<'a, V, Value, M: PersistentAssoc<Key = (), Value = Value>> PersistentMap<'a, V, M>
where
    V: Copy + AsBytePrefix + Serialize + DeserializeOwned,
    Value: Serialize + DeserializeOwned,
{
    // TODO: previous versions as argument
    pub fn insert(&self, version: V, value: Value) -> Result<()>
    where
        V: std::fmt::Debug + PartialEq,
    {
        self.insert_with(version, (), value.into())?;
        self.storage.new_version(version, None)?;
        Ok(())
    }

    pub fn get(&self, version: V) -> Result<Option<MaybeValue<Value>>> {
        self.get_exact_for(version, ())
    }

    pub fn keys(&self) -> impl Iterator<Item = V> + '_ {
        self.storage.versions().map(|(version, _)| version)
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

impl<V> Debug for VersionedStorage<V>
where
    V: 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VersionedStorage")
            .field("Version", &std::any::type_name::<V>())
            .field("database", &self.db.path().display())
            .finish()
    }
}

impl<'a, V, M: PersistentAssoc> fmt::Debug for PersistentMap<'a, V, M>
where
    V: 'static,
    M::Key: 'static,
    M::Value: 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::any::TypeId;

        f.debug_struct("Storage")
            .field("Version", &TypeId::of::<V>())
            .field("Key", &TypeId::of::<M::Key>())
            .field("Value", &TypeId::of::<M::Value>())
            .field("database", &self.db().path().display())
            .field("column", &M::COLUMN_NAME)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::blacklisted_name)]
mod tests {
    use std::collections::{BTreeMap, HashMap};
    use std::thread::{self, JoinHandle};

    use quickcheck_macros::quickcheck;

    use crate::test_utils::TmpDir;

    use super::*;

    impl AsBytePrefix for () {
        const SIZE: usize = 0;
        type Bytes = [u8; 0];
        fn to_bytes(&self) -> Self::Bytes {
            []
        }

        type FromBytesError = TryFromSliceError;
        fn from_bytes(bytes: &[u8]) -> StdResult<Self, Self::FromBytesError> {
            Self::Bytes::try_from(bytes).map(|_| ())
        }
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
    fn it_handles_versions_as_expected() -> Result<()> {
        persistent_types! { KV in "kv" => u64 : usize } // TODO: rm, can be any
        let dir = TmpDir::new("it_handles_versions_as_expected");
        let s = VersionedStorage::<u64>::create_temporary(COLUMN_NAMES)?;
        assert_eq!(s.previous_of(0)?, None);
        Ok(())
    }

    #[test]
    fn it_handles_full_range_mapping() -> Result<()> {
        use rand::Rng;

        type Version = u8;
        type Key = u8;
        type Value = u64;
        type Assoc = HashMap<Version, HashMap<Key, Value>>;
        type Storage = VersionedStorage<Version>;
        persistent_types! { KV in "kv" => Key : Value }

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
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;

            for (&version, map) in &assoc {
                for (&key, &value) in map {
                    s.typed::<KV>().insert_with(version, key, value.into())?;
                }
                s.new_version(version, None)?;
            }
            s.db.flush()?;
            println!("assoc is stored");
        }
        {
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;
            for (version, _) in s.versions() {
                let new_map = s
                    .typed::<KV>()
                    .prefix_iter_for(version)?
                    .map(|(key, mb_value)| (key, Option::from(mb_value).unwrap()))
                    .collect::<HashMap<_, _>>();
                assert_eq!(assoc.remove(&version), Some(new_map));
            }
            assert!(assoc.is_empty());
        }
        Ok(())
    }

    #[quickcheck]
    fn qc_version_precedes_key_in_serialized_data(version: u64, key: u64) -> Result<()> {
        let version_data = CODER.serialize(&version).typed_ctx()?;

        let versioned_key = VersionedKey { version, key };
        let versioned_key_data = CODER.serialize(&versioned_key).typed_ctx()?;
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

    type K = u16;
    type V = u64;
    type ThreadId = u64;

    #[quickcheck]
    fn qc_keyless_storage_behaves_like_a_map_with_version_as_key(
        map: BTreeMap<K, V>,
    ) -> Result<()> {
        type Storage = VersionedStorage<K>;
        persistent_types! { KV in "kv" => () : V }
        let dir = TmpDir::new("qc_keyless_storage_behaves_like_a_map_with_version_as_key");
        {
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;
            for (&k, &v) in &map {
                s.typed::<KV>().insert(k, v)?;
            }
            s.db.flush()?;
        }
        {
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;
            let mut new_map = BTreeMap::new();
            for key in s.typed::<KV>().keys() {
                new_map.insert(
                    key,
                    s.typed::<KV>().get(key)?.and_then(Option::from).unwrap(),
                );
            }
            assert_eq!(map, new_map);
        }
        Ok(())
    }

    #[quickcheck]
    fn qc_two_concurrent_threads_works_on_shared_db_via_version_assoc(
        (foo, bar): (BTreeMap<K, V>, BTreeMap<K, V>),
    ) -> Result<()> {
        type Storage = VersionedStorage<(ThreadId, K)>;
        persistent_types! { TKV in "tkv" => () : V }
        let s: Arc<Storage> = Arc::new(Storage::create_temporary(COLUMN_NAMES)?);

        fn spawn_insert(s: &Arc<Storage>, map: BTreeMap<K, V>) -> JoinHandle<Result<ThreadId>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<ThreadId> {
                let id = thread_id();
                for (k, v) in map {
                    s.typed::<TKV>().insert((id, k), v)?;
                }
                s.db.flush()?;
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
                    .map(|key| {
                        s.typed::<TKV>()
                            .get((id, key))
                            .map(|value| (key, value.and_then(Option::from).unwrap()))
                    })
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
        type Storage = VersionedStorage<ThreadId>;
        persistent_types! { KV in "kv" => K : V }
        let s = Arc::new(Storage::create_temporary(COLUMN_NAMES)?);

        fn spawn_insert(s: &Arc<Storage>, map: BTreeMap<K, V>) -> JoinHandle<Result<ThreadId>> {
            let s = Arc::clone(s);
            thread::spawn(move || -> Result<ThreadId> {
                let id = thread_id();
                for (k, v) in map {
                    s.typed::<KV>().insert_with(id, k, v.into())?;
                }
                s.new_version(id, None)?;
                s.db.flush()?;
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
                    .map(|key| {
                        s.typed::<KV>()
                            .get_exact_for(id, key)
                            .map(|value| (key, value.and_then(Option::from).unwrap()))
                    })
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
    fn qc_reads_the_same_as_inserts(assoc: HashMap<K, HashMap<K, Option<V>>>) -> Result<()> {
        type Storage = VersionedStorage<K>;
        persistent_types! { KV in "kv" => K : V }
        let dir = TmpDir::new("qc_reads_the_same_as_inserts");

        {
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;
            for (&version, map) in &assoc {
                for (&k, &v) in map {
                    s.typed::<KV>().insert_with(version, k, v.into())?;
                }
                s.new_version(version, None)?;
            }
            s.db.flush()?;
        }
        {
            let s = Storage::open_persistent(&dir, COLUMN_NAMES)?;

            let mut new_assoc = HashMap::<K, HashMap<K, Option<V>>>::new();
            for (version, _) in s.versions() {
                new_assoc.insert(
                    version,
                    s.typed::<KV>()
                        .prefix_iter_for(version)
                        .unwrap()
                        .map(|(key, mb_value)| (key, Option::from(mb_value)))
                        .collect(),
                );
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
