use {
    crate::blockstore::{Blockstore, BlockstoreError},
    evm_state::{storage::RootCleanup, ChangedState, Storage, H256},
    solana_program_runtime::evm_executor_context::{ChainID, StateExt},
    solana_runtime::bank::Bank,
    std::{
        path::{Path, PathBuf},
        sync::Arc,
    },
    triedb::gc::DbCounter,
};
pub mod recorder;

//TODO Fix cleanup of blocks for subchain todo!()

pub struct EvmArchiveGc {
    states_per_chain: u64,
    states_on_main_chain: u64,
}
impl EvmArchiveGc {
    pub fn new(states_per_chain: u64, states_on_main_chain: u64) -> Self {
        Self {
            states_per_chain,
            states_on_main_chain,
        }
    }
}

pub enum EvmArchiveType {
    WithGc(EvmArchiveGc),
    NoCleanup(String),
}

impl EvmArchiveType {
    pub fn default_gc() -> Self {
        EvmArchiveType::WithGc(EvmArchiveGc::new(
            EVM_ARCHIVE_LIMIT_BLOCKS_ON_SUBCHAIN,
            EVM_ARCHIVE_LIMIT_BLOCKS,
        ))
    }
    pub fn is_gc(&self) -> bool {
        matches!(self, EvmArchiveType::WithGc(_))
    }
}

pub struct EvmArchiveInner {
    archive_type: EvmArchiveType,
    storage: Storage,
    blockstore: Arc<Blockstore>,
}
pub const EVM_ARCHIVE_PATH: &str = "evm_archive_state";
pub const EVM_ARCHIVE_LIMIT_BLOCKS: u64 = 3000;
pub const EVM_ARCHIVE_LIMIT_BLOCKS_ON_SUBCHAIN: u64 = 1000;
// priv api
impl EvmArchiveInner {
    pub fn testing(ledger_path: impl AsRef<Path>, blockstore: Arc<Blockstore>) -> Self {
        let archive_type = EvmArchiveType::WithGc(EvmArchiveGc::new(10, 10));
        Self::new(archive_type, ledger_path, blockstore)
    }
    pub fn new(
        archive_type: EvmArchiveType,
        ledger_path: impl AsRef<Path>,
        blockstore: Arc<Blockstore>,
    ) -> Self {
        let storage = match &archive_type {
            EvmArchiveType::WithGc(p) => {
                info!(
                    "Opening temporary evm archive storage, persist_last_slots={}, on main chain={}",
                    p.states_per_chain, p.states_on_main_chain
                );
                let evm_state_path = PathBuf::from(ledger_path.as_ref()).join(EVM_ARCHIVE_PATH);
                Storage::open_persistent(evm_state_path, true)
                    .expect("Cannot open evm archive folder")
            }
            EvmArchiveType::NoCleanup(path) => {
                info!("Opening evm archive storage");

                Storage::open_persistent(path, false).expect("Cannot open evm archive folder")
            }
        };

        assert_eq!(storage.gc_enabled(), archive_type.is_gc());
        Self {
            archive_type,
            storage,
            blockstore,
        }
    }
    fn register_state(storage: &Storage, state_root: H256, state_updates: ChangedState) {
        if !storage.check_root_exist(state_root) {
            warn!(
                "Root not found in archive, skip writing root:{} , updates_len:{:?}",
                state_root,
                state_updates.len()
            );
            return;
        }
        let root = storage.flush_changes(state_root, state_updates);
        let trie = storage.rocksdb_trie_handle();
        log::trace!("pin root: {:?}", root);
        // register root
        trie.gc_pin_root(root);
    }
    fn unregister_state(
        storage: &Storage,
        state_root: H256,
    ) -> Result<(), evm_state::storage::Error> {
        let trie = storage.rocksdb_trie_handle();
        trie.gc_unpin_root(state_root);
        RootCleanup::new(storage, vec![state_root]).cleanup()?;
        Ok(())
    }

    fn write_evm_block(blockstore: &Blockstore, chain: Option<ChainID>, block: evm_state::Block) {
        // let (chain, block) = evm_records_receiver.recv_timeout(Duration::from_secs(1))?;
        let block_header = block.header;
        info!(
            "Writing evm block num = {} for chain = {:?}",
            block_header.block_number, chain
        );
        blockstore
            .write_evm_block_header(&chain, &block_header)
            .expect("Expected database write to succed");
        for (hash, tx) in block.transactions {
            blockstore
                .write_evm_transaction(
                    &chain,
                    block_header.block_number,
                    block_header.native_chain_slot,
                    hash,
                    tx,
                )
                .expect("Expected database write to succed");
        }
    }
    fn cleanup_block(
        storage: &Storage,
        blockstore: &Blockstore,
        chain: Option<ChainID>,
        block_num: u64,
    ) -> Result<(), BlockstoreError> {
        info!(
            "Cleaning evm block num = {} for chain = {:?}",
            block_num, chain
        );
        let (block, _) = blockstore.get_evm_block(chain, block_num)?;
        blockstore.remove_evm_block(&chain, &block.header)?;
        Self::unregister_state(storage, block.header.state_root)
            .map_err(|_| BlockstoreError::Other("Failed to process block cleanup"))?;
        Ok(())
    }
}

// pub api
// pub fn - can use in rpc
// fn - can be used in recorder
impl EvmArchiveInner {
    pub fn count_evm_blocks(
        blockstore: &Blockstore,
        chain: Option<ChainID>,
    ) -> Result<u64, BlockstoreError> {
        let first = blockstore.get_first_available_evm_block(chain)?;
        let last = blockstore.get_last_available_evm_block(chain)?;
        if let Some(last) = last {
            Ok(last - first + 1)
        } else {
            Ok(0)
        }
    }
    // Get num_blocks/states per subchain
    // get accumulated purged blocks per subchain
    // get total size (in blocks, mbs) of db

    // fn collect_metrics(&self)  {
    //     for chain in chain_list {

    //         let first = self.blockstore.get_first_available_evm_block(chain)?;
    //         let last = self.blockstore.get_last_available_evm_block(chain)?;
    //         let num_blocks = (last - first);
    //     }
    // }

    fn write_evm_record(&self, record: recorder::RecorderEntry) {
        Self::write_evm_block(&self.blockstore, record.chain, record.block.clone());
        // push state to archive
        Self::register_state(&self.storage, record.state_root, record.state_updates);
        // ensure that block contain root to new state

        let block_num = record.block.header.block_number;
        if let EvmArchiveType::WithGc(gc) = &self.archive_type {
            let first_block_num = match self.blockstore.get_first_available_evm_block(record.chain)
            {
                // at least one block should exist
                Ok(block) => block,
                Err(e) => {
                    // evm archive errors should not fail validator.
                    error!("Evm archive cleanup failed unable to get first available block for chain {:?}: {:?}", record.chain, e);
                    return;
                }
            };

            debug_assert!(first_block_num <= block_num);

            let num_states_to_persist = if record.chain.is_some() {
                gc.states_per_chain
            } else {
                gc.states_on_main_chain
            };
            assert!(first_block_num <= block_num);
            let block_to_purge = block_num.saturating_sub(num_states_to_persist - 1);

            // cleanup old blocks
            for block_num in first_block_num..block_to_purge {
                match Self::cleanup_block(&self.storage, &self.blockstore, record.chain, block_num)
                {
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            "Evm archive cleanup failed for block {} on chain {:?}: {:?}",
                            block_num, record.chain, e
                        );
                    }
                }
            }
        }
    }

    pub fn get_state(
        &self,
        chain_id: Option<ChainID>,
        _root: H256,

        mocked_bank: &Bank,
        timestamp: Option<u64>,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        let state = match chain_id {
            Some(subchain_id) => mocked_bank
                .evm()
                .side_chains()
                .get(&subchain_id)?
                .state()
                .clone(),
            None => mocked_bank.evm().main_chain().state().clone(),
        };
        // TODO(L): block_hashes history
        let timestamp = timestamp.unwrap_or(mocked_bank.clock().unix_timestamp as u64);
        match state.new_from_parent(timestamp, true) {
            evm_state::EvmState::Incomming(mut i) => {
                i.kvs = self.storage.clone();
                // TODO: Fix root??
                Some(i)
            }
            _ => unreachable!(),
        }
    }
    pub fn get_storage(&self) -> Storage {
        self.storage.clone()
    }
    pub fn is_gc(&self) -> bool {
        debug_assert_eq!(self.storage.gc_enabled(), self.archive_type.is_gc());
        self.archive_type.is_gc()
    }
}

pub type EvmArchive = Arc<EvmArchiveInner>;

#[cfg(test)]
mod test {
    use {
        super::*,
        evm_state::{AccountState, Block, BlockHeader, Maybe, H160},
        std::collections::HashMap,
        tempfile::tempdir,
        triedb::empty_trie_hash,
    };

    fn make_changes(idx: u8) -> ChangedState {
        let key = H160::repeat_byte(idx);
        let acc = AccountState {
            nonce: idx.into(),
            balance: idx.into(),
            code: Default::default(),
        };
        let mut state = HashMap::new();
        state.insert(key, (Maybe::Just(acc), HashMap::new()));
        state
    }
    fn next(tmp_storage: &Storage, record: &recorder::RecorderEntry) -> recorder::RecorderEntry {
        let changes = make_changes(record.block.header.block_number as u8);
        let old_root = record.block.header.state_root;
        let new_state = tmp_storage.flush_changes(old_root, changes.clone());
        log::info!("Old root = {:?}", old_root);
        log::info!("New root = {:?}", new_state);
        assert_ne!(new_state, old_root);
        let block_header = BlockHeader {
            block_number: record.block.header.block_number + 1,
            parent_hash: record.block.header.hash(),
            state_root: new_state,
            ..record.block.header.clone()
        };
        let block = Block {
            header: block_header,
            transactions: Default::default(),
        };
        recorder::RecorderEntry {
            chain: record.chain,
            block,
            state_root: old_root,
            state_updates: changes,
        }
    }
    // create archive with gc and num_blocks = 1
    // push blocks to archive
    // get state with root of first state to purge
    // add one block to ensure that state is purged
    // check if state ref is still available
    #[test]
    fn test_lock_get_state() {
        solana_logger::setup_with_default("trace,triedb=warn");
        let ledger_path = tempdir().unwrap();

        let num_blocks = 3;
        let blockstore = Arc::new(Blockstore::open(ledger_path.path()).unwrap());
        let new_archive = EvmArchiveInner::new(
            EvmArchiveType::WithGc(EvmArchiveGc::new(num_blocks, num_blocks)),
            ledger_path.path(),
            blockstore.clone(),
        );

        assert!(new_archive.is_gc());
        let chain = None;
        let mut record = recorder::RecorderEntry {
            chain,
            block: Block {
                header: BlockHeader::new(
                    Default::default(),
                    0,
                    empty_trie_hash(),
                    0,
                    0,
                    0,
                    0,
                    H256::zero(),
                    vec![].into_iter(),
                    evm_state::BlockVersion::VersionConsistentHashes,
                ),
                transactions: Default::default(),
            },
            state_root: empty_trie_hash(),
            state_updates: Default::default(),
        }; // first update without changes in state

        new_archive.write_evm_record(record.clone());
        let mut states = vec![];

        let tmp_storage = Storage::create_temporary().unwrap();
        for _ in 0..num_blocks {
            record = next(&tmp_storage, &record);
            new_archive.write_evm_record(record.clone());
            states.push(record.clone());
        }
        assert_eq!(states.len(), num_blocks as usize);
        for state in &states {
            assert!(new_archive.storage.check_root_exist(state.state_root))
        }
        log::info!("Starting gc");
        let lock_root = states[0].block.header.state_root;
        let mocked_bank = Bank::default_for_tests();
        // while this state exist lock_root should also exist in db
        let state = new_archive
            .get_state(chain, lock_root, &mocked_bank, None)
            .unwrap();

        let new_record = next(&tmp_storage, &record);
        assert_ne!(new_record.state_root, states[0].block.header.state_root);
        new_archive.write_evm_record(new_record);
        log::info!("first state root = {:?}", states[0].block.header.state_root);
        // first state should be removed
        assert!(new_archive
            .storage
            .check_root_exist(states[0].block.header.state_root));
        drop(state);

        assert!(!new_archive
            .storage
            .check_root_exist(states[0].block.header.state_root))
    }
}

// 1. todo remove
// 2. lock_state - unit test
// 3. start node
// 4. metrics
// 5. lock_state fix
// 6. rpc test
