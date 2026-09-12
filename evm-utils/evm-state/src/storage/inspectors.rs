use {
    super::{walker::Walker, Codes, Storage},
    crate::types::{Account, Code},
    anyhow::{bail, ensure, Result},
    log::*,
    primitive_types::H256,
    std::{borrow::Borrow, sync::Arc},
};

pub trait TrieInspector {
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool>;
}
pub trait DataInspector<K, V> {
    fn inspect_data(&self, key: K, value: V) -> Result<()>;
}

pub trait TrieDataInsectorRaw {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()>;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub struct NoopInspector;

// secure-triedb specific encoding.
// key - H256, data is rlp decodable
pub mod encoding {
    use {super::*, std::marker::PhantomData};

    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
    pub struct SecTrie<T, K, V> {
        pub inner: T,
        _pd: PhantomData<(K, V)>,
    }

    impl<T, K, V> SecTrie<T, K, V> {
        pub fn new(inner: T) -> Self {
            Self {
                inner,
                _pd: PhantomData,
            }
        }
    }

    impl<T, K, V> TrieDataInsectorRaw for SecTrie<T, K, V>
    where
        T: DataInspector<K, V>,
        K: TryFromSlice,
        V: rlp::Decodable,
    {
        fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()> {
            let key = TryFromSlice::try_from_slice(&key)?;
            let value = data_from_bytes(value)?;
            self.inner.inspect_data(key, value)
        }
    }

    impl<K, V, T: DataInspector<K, V>> DataInspector<K, V> for SecTrie<T, K, V> {
        fn inspect_data(&self, key: K, value: V) -> Result<()> {
            self.inner.inspect_data(key, value)
        }
    }

    impl<K, V, T: TrieInspector> TrieInspector for SecTrie<T, K, V> {
        fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
            self.inner.inspect_node(trie_key, node)
        }
    }

    pub trait TryFromSlice {
        fn try_from_slice(slice: &[u8]) -> Result<Self>
        where
            Self: Sized;
    }

    impl TryFromSlice for H256 {
        fn try_from_slice(slice: &[u8]) -> Result<Self>
        where
            Self: Sized,
        {
            ensure!(
                slice.len() == 32,
                "Cannot get H256 from slice len:{}",
                slice.len()
            );

            Ok(H256::from_slice(slice))
        }
    }

    fn data_from_bytes<Data: AsRef<[u8]>, Value>(data: Data) -> Result<Value>
    where
        Value: rlp::Decodable,
    {
        let rlp = rlp::Rlp::new(data.as_ref());
        trace!("rlp: {:?}", rlp);
        let t = Value::decode(&rlp)?;
        Ok(t)
    }
}

pub mod memorizer {
    use {
        super::*,
        dashmap::DashSet,
        std::{
            fmt::Display,
            sync::atomic::{AtomicUsize, Ordering},
        },
    };

    #[derive(Default)]
    pub struct AccountStorageRootsCollector {
        pub accounts_keys: DashSet<H256>,
        pub storage_roots: DashSet<H256>,
        pub code_hashes: DashSet<H256>,
    }

    impl DataInspector<H256, Account> for AccountStorageRootsCollector {
        fn inspect_data(&self, key: H256, account: Account) -> Result<()> {
            self.accounts_keys.insert(key);
            self.storage_roots.insert(account.storage_root);
            self.code_hashes.insert(account.code_hash);
            Ok(())
        }
    }

    #[derive(Default)]
    pub struct TrieCollector {
        pub trie_keys: DashSet<H256>,
        pub unique_node_size: AtomicUsize,
        pub node_size: AtomicUsize,
    }

    impl TrieInspector for TrieCollector {
        fn inspect_node<Data: AsRef<[u8]>>(&self, key: H256, data: Data) -> Result<bool> {
            let is_new_key = self.trie_keys.insert(key);
            self.node_size
                .fetch_add(data.as_ref().len(), Ordering::Relaxed);
            if is_new_key {
                self.unique_node_size
                    .fetch_add(data.as_ref().len(), Ordering::Relaxed);
            }
            Ok(is_new_key)
        }
    }

    impl AccountStorageRootsCollector {
        pub fn summarize(&self) {
            info!(
                "Accounts state summary: \
                       unique accounts: {}, \
                       unique storage roots: {}, \
                       unique code hashes: {}",
                self.accounts_keys.len(),
                self.storage_roots.len(),
                self.code_hashes.len(),
            );
        }
    }

    impl TrieCollector {
        pub fn summarize<T: Display>(&self, header: T) {
            info!(
                "Trie {} nodes summary: \
                       trie keys: {}, \
                       data size: {}, \
                       unique data size: {}",
                header,
                self.trie_keys.len(),
                self.node_size.load(Ordering::Relaxed),
                self.unique_node_size.load(Ordering::Relaxed),
            );
        }
    }
}

pub mod streamer {
    use super::*;

    pub struct AccountsStreamer<'a> {
        pub source: Storage,
        pub destinations: &'a [Storage],
    }

    impl<'a> TrieInspector for AccountsStreamer<'a> {
        fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
            for destination in self.destinations {
                // if we process this node, then it's a root or a parrent that point to this node - increase reference
                let trie = destination.rocksdb_trie_handle();
                trie.db.increase_atomic(trie_key)?;
                destination.db().put(trie_key, node.as_ref())?;
            }
            Ok(false)
        }
    }

    impl<'a> DataInspector<H256, Account> for AccountsStreamer<'a> {
        fn inspect_data(&self, _key: H256, account: Account) -> Result<()> {
            let source = self.source.borrow();

            // - Account Storage
            let walker = Walker::new_raw(
                source,
                StoragesKeysStreamer::new(self.destinations),
                NoopInspector,
            );
            walker.traverse(account.storage_root)?;

            for destination in self.destinations {
                // - Account Code
                let code_hash = account.code_hash;
                if let Some(code_data) = self.source.get::<Codes>(code_hash) {
                    destination.set::<Codes>(code_hash, code_data);
                } else {
                    assert_eq!(code_hash, Code::empty().hash());
                }
            }

            Ok(())
        }
    }

    pub struct StoragesKeysStreamer<'a> {
        destinations: &'a [Storage],
    }

    impl<'a> StoragesKeysStreamer<'a> {
        fn new(destinations: &'a [Storage]) -> Self {
            Self { destinations }
        }
    }

    impl<'a> TrieInspector for StoragesKeysStreamer<'a> {
        fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
            for destination in self.destinations {
                // if we process this node, then it's a root or a parrent that point to this node - increase reference
                let trie = destination.rocksdb_trie_handle();
                trie.db.increase_atomic(trie_key)?;
                destination.db().put(trie_key, node.as_ref())?;
            }
            Ok(true)
        }
    }
}

impl<K, V> DataInspector<K, V> for NoopInspector {
    fn inspect_data(&self, _key: K, _value: V) -> Result<()> {
        Ok(())
    }
}

impl TrieInspector for NoopInspector {
    fn inspect_node<Data: AsRef<[u8]>>(&self, _trie_key: H256, _node: Data) -> Result<bool> {
        Ok(false)
    }
}

impl TrieDataInsectorRaw for NoopInspector {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, _key: Vec<u8>, _value: Data) -> Result<()> {
        Ok(())
    }
}

impl<K, V, T: DataInspector<K, V>> DataInspector<K, V> for Arc<T> {
    fn inspect_data(&self, key: K, value: V) -> Result<()> {
        self.as_ref().inspect_data(key, value)
    }
}

impl<T: TrieInspector> TrieInspector for Arc<T> {
    fn inspect_node<Data: AsRef<[u8]>>(&self, trie_key: H256, node: Data) -> Result<bool> {
        self.as_ref().inspect_node(trie_key, node)
    }
}

impl<T: TrieDataInsectorRaw> TrieDataInsectorRaw for Arc<T> {
    fn inspect_data_raw<Data: AsRef<[u8]>>(&self, key: Vec<u8>, value: Data) -> Result<()> {
        self.as_ref().inspect_data_raw(key, value)
    }
}

pub mod verifier {
    use {
        super::*,
        dashmap::DashSet,
        sha3::{Digest, Keccak256},
    };

    pub struct AccountsVerifier {
        storage: Storage,
        pub storage_roots: DashSet<H256>,
    }

    impl AccountsVerifier {
        pub fn new(storage: Storage) -> Self {
            let storage_roots = DashSet::new();
            Self {
                storage,
                storage_roots,
            }
        }
    }

    impl DataInspector<H256, Account> for AccountsVerifier {
        fn inspect_data(&self, _key: H256, account: Account) -> Result<()> {
            self.storage_roots.insert(account.storage_root);

            // - Account Code
            if account.code_hash != Code::empty().hash() {
                if let Some(code) = self.storage.get::<Codes>(account.code_hash) {
                    let expected = account.code_hash;
                    let actual = code.hash();
                    ensure!(
                        actual == expected,
                        "Account code hash key {:?} differs from actual code hash {:?}",
                        expected,
                        actual
                    );
                } else {
                    bail!("Code data for {:?} is missed in storage", account.code_hash);
                }
            }

            Ok(())
        }
    }
    #[derive(Default)]
    pub struct HashVerifier;

    impl TrieInspector for HashVerifier {
        fn inspect_node<Data: AsRef<[u8]>>(&self, key: H256, data: Data) -> Result<bool> {
            let hash = H256::from_slice(Keccak256::digest(data.as_ref()).as_slice());
            ensure!(
                key == hash,
                "key {:?} differs from data hash {:?}",
                key,
                hash
            );
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        quickcheck::{Arbitrary, Gen},
        quickcheck_macros::quickcheck,
        std::convert::TryFrom,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Hash(H256);

    impl Arbitrary for Hash {
        fn arbitrary<G: Gen>(g: &mut G) -> Self {
            let mut bytes = [0; 32];
            for byte in &mut bytes {
                *byte = u8::arbitrary(g);
            }
            Hash(H256::from(bytes))
        }
    }

    #[quickcheck]
    fn qc_hash_is_reversible_from_bytes(Hash(expected): Hash) {
        assert_eq!(expected, H256::from_slice(expected.as_bytes()));
        assert_eq!(expected, H256::from_slice(expected.as_ref()));
        assert_eq!(expected.as_bytes(), expected.as_ref());
        assert_eq!(
            H256::from(<&[u8; 32]>::try_from(expected.as_bytes()).unwrap()),
            expected
        );
    }
}
