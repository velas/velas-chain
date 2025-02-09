use {
    crate::blockstore::{Blockstore, BlockstoreError},
    evm_state::{ChangedState, EvmState, Incomming, Storage, H256},
    solana_program_runtime::evm_executor_context::{ChainID, StateExt},
    solana_runtime::bank::Bank,
    std::{
        path::{Path, PathBuf},
        sync::Arc,
    },
    triedb::gc::DbCounter,
};
pub mod recoreder;

//TODO Fix cleanup of blocks for subchain todo!()

pub struct EvmArchiveGc {
    states_per_chain: u64,
}
impl EvmArchiveGc {
    pub fn new(states_per_chain: u64) -> Self {
        Self { states_per_chain }
    }
}

pub enum EvmArchiveType {
    WithGc(EvmArchiveGc),
    NoCleanup(String),
}

impl EvmArchiveType {
    pub fn default_gc() -> Self {
        EvmArchiveType::WithGc(EvmArchiveGc::new(EVM_ARCHIVE_LIMIT_BLOCKS))
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
pub const EVM_ARCHIVE_LIMIT_BLOCKS: u64 = 1000;
// priv api
impl EvmArchiveInner {
    pub fn testing(ledger_path: impl AsRef<Path>, blockstore: Arc<Blockstore>) -> Self {
        let archive_type = EvmArchiveType::WithGc(EvmArchiveGc::new(10));
        Self::new(archive_type, ledger_path, blockstore)
    }
    pub fn new(
        archive_type: EvmArchiveType,
        ledger_path: impl AsRef<Path>,
        blockstore: Arc<Blockstore>,
    ) -> Self {
        let storage = match &archive_type {
            EvmArchiveType::WithGc(_) => {
                info!("Opening temporary evm archive storage");
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
        // register root
        trie.gc_pin_root(root);
    }
    fn unregister_state(storage: &Storage, state_root: H256) {
        let trie = storage.rocksdb_trie_handle();
        trie.gc_unpin_root(state_root);
        todo!() // cleanup trie if needed
    }
}

// pub api
impl EvmArchiveInner {
    fn cleanup_block(
        storage: &Storage,
        blockstore: &Blockstore,
        chain: Option<ChainID>,
        block_num: u64,
    ) -> Result<(), BlockstoreError> {
        let (block, _) = blockstore.get_evm_block(chain, block_num)?;
        blockstore.remove_evm_block(&chain, &block.header)?;
        Self::unregister_state(storage, block.header.state_root);
        Ok(())
    }

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

    fn write_evm_record(&self, record: recoreder::RecorderEntry) {
        Self::write_evm_block(&self.blockstore, record.chain, record.block.clone());
        // TODO: Push block?
        // push state to archive
        Self::register_state(&self.storage, record.state_root, record.state_updates);

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

            assert!(first_block_num <= block_num);
            let block_to_purge = block_num.saturating_sub(gc.states_per_chain);

            // cleanup old blocks
            for block_num in first_block_num..=block_to_purge {
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

    fn write_evm_block(blockstore: &Blockstore, chain: Option<ChainID>, block: evm_state::Block) {
        // let (chain, block) = evm_records_receiver.recv_timeout(Duration::from_secs(1))?;
        let block_header = block.header;
        debug!(
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
