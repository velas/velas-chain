use {
    crate::{
        accounts::Accounts,
        accounts_db::{
            AccountShrinkThreshold, AccountStorageEntry, AccountsDb, AccountsDbConfig, AppendVecId,
            AtomicAppendVecId, BankHashInfo, IndexGenerationInfo, SnapshotStorage,
        },
        accounts_index::AccountSecondaryIndexes,
        accounts_update_notifier_interface::AccountsUpdateNotifier,
        append_vec::{AppendVec, StoredMetaWriteVersion},
        bank::{Bank, BankFieldsToDeserialize, BankRc},
        blockhash_queue::{BlockHashEvm, BlockhashQueue},
        builtins::Builtins,
        epoch_stakes::EpochStakes,
        hardened_unpack::UnpackedAppendVecMap,
        rent_collector::RentCollector,
        stakes::Stakes,
    },
    bincode::{self, config::Options, Error},
    log::*,
    rayon::prelude::*,
    serde::{de::DeserializeOwned, de::Error as _, Deserialize, Serialize},
    solana_measure::measure::Measure,
    solana_sdk::{
        clock::{Epoch, Slot, UnixTimestamp},
        deserialize_utils::default_on_eof,
        epoch_schedule::EpochSchedule,
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        genesis_config::GenesisConfig,
        hard_forks::HardForks,
        hash::Hash,
        inflation::Inflation,
        pubkey::Pubkey,
    },
    std::{
        collections::{HashMap, HashSet},
        io::{self, BufReader, BufWriter, Read, Write},
        path::{Path, PathBuf},
        result::Result,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, RwLock,
        },
        thread::Builder,
    },
    storage::{SerializableStorage, SerializedAppendVecId},
};

mod newer;
mod storage;
mod tests;
mod utils;

// a number of test cases in accounts_db use this
#[cfg(test)]
pub(crate) use tests::reconstruct_accounts_db_via_serialization;

// NOTE(velas):
// - old enum `SerdeStyle` was removed as single variant enum
// - this enum should be treated as new, EVM only related enum without any previous history
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum EvmStateVersion {
    V1_4_0,
    V1_5_0,
}

impl EvmStateVersion {
    pub fn support_gc(&self) -> bool {
        match self {
            Self::V1_4_0 => false, // old snapshot support only archive mode
            Self::V1_5_0 => true,
        }
    }
}

const MAX_STREAM_SIZE: u64 = 32 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, AbiExample)]
struct AccountsDbFields<T>(
    HashMap<Slot, Vec<T>>,
    StoredMetaWriteVersion,
    Slot,
    BankHashInfo,
    /// all slots that were roots within the last epoch
    #[serde(deserialize_with = "default_on_eof")]
    Vec<Slot>,
    /// slots that were roots within the last epoch for which we care about the hash value
    #[serde(deserialize_with = "default_on_eof")]
    Vec<(Slot, Hash)>,
);

/// Helper type to wrap BufReader streams when deserializing and reconstructing from either just a
/// full snapshot, or both a full and incremental snapshot
pub struct SnapshotStreams<'a, R> {
    pub full_snapshot_stream: &'a mut BufReader<R>,
    pub incremental_snapshot_stream: Option<&'a mut BufReader<R>>,
}

/// Helper type to wrap AccountsDbFields when reconstructing AccountsDb from either just a full
/// snapshot, or both a full and incremental snapshot
#[derive(Debug)]
struct SnapshotAccountsDbFields<T> {
    full_snapshot_accounts_db_fields: AccountsDbFields<T>,
    incremental_snapshot_accounts_db_fields: Option<AccountsDbFields<T>>,
}

impl<T> SnapshotAccountsDbFields<T> {
    /// Collapse the SnapshotAccountsDbFields into a single AccountsDbFields.  If there is no
    /// incremental snapshot, this returns the AccountsDbFields from the full snapshot.
    /// Otherwise, use the AccountsDbFields from the incremental snapshot, and a combination
    /// of the storages from both the full and incremental snapshots.
    fn collapse_into(self) -> Result<AccountsDbFields<T>, Error> {
        match self.incremental_snapshot_accounts_db_fields {
            None => Ok(self.full_snapshot_accounts_db_fields),
            Some(AccountsDbFields(
                mut incremental_snapshot_storages,
                incremental_snapshot_version,
                incremental_snapshot_slot,
                incremental_snapshot_bank_hash_info,
                incremental_snapshot_prior_roots,
                incremental_snapshot_prior_roots_with_hash,
            )) => {
                let full_snapshot_storages = self.full_snapshot_accounts_db_fields.0;
                let full_snapshot_slot = self.full_snapshot_accounts_db_fields.2;

                // filter out incremental snapshot storages with slot <= full snapshot slot
                incremental_snapshot_storages.retain(|slot, _| *slot > full_snapshot_slot);

                // There must not be any overlap in the slots of storages between the full snapshot and the incremental snapshot
                incremental_snapshot_storages
                    .iter()
                    .all(|storage_entry| !full_snapshot_storages.contains_key(storage_entry.0)).then_some(()).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "Snapshots are incompatible: There are storages for the same slot in both the full snapshot and the incremental snapshot!")
                    })?;

                let mut combined_storages = full_snapshot_storages;
                combined_storages.extend(incremental_snapshot_storages.into_iter());

                Ok(AccountsDbFields(
                    combined_storages,
                    incremental_snapshot_version,
                    incremental_snapshot_slot,
                    incremental_snapshot_bank_hash_info,
                    incremental_snapshot_prior_roots,
                    incremental_snapshot_prior_roots_with_hash,
                ))
            }
        }
    }
}

trait TypeContext<'a> {
    type SerializableAccountStorageEntry: Serialize
        + DeserializeOwned
        + From<&'a AccountStorageEntry>
        + SerializableStorage
        + Sync;

    fn serialize_bank_and_storage<S: serde::ser::Serializer>(
        serializer: S,
        serializable_bank: &SerializableBankAndStorage<'a, Self>,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        Self: std::marker::Sized;

    #[cfg(test)]
    fn serialize_bank_and_storage_without_extra_fields<S: serde::ser::Serializer>(
        serializer: S,
        serializable_bank: &SerializableBankAndStorageNoExtra<'a, Self>,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        Self: std::marker::Sized;

    fn serialize_accounts_db_fields<S: serde::ser::Serializer>(
        serializer: S,
        serializable_db: &SerializableAccountsDb<'a, Self>,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        Self: std::marker::Sized;

    fn deserialize_bank_fields<R>(
        stream: &mut BufReader<R>,
    ) -> Result<
        (
            BankFieldsToDeserialize,
            AccountsDbFields<Self::SerializableAccountStorageEntry>,
        ),
        Error,
    >
    where
        R: Read;

    fn deserialize_accounts_db_fields<R>(
        stream: &mut BufReader<R>,
    ) -> Result<AccountsDbFields<Self::SerializableAccountStorageEntry>, Error>
    where
        R: Read;
}

fn deserialize_from<R, T>(reader: R) -> bincode::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    bincode::options()
        .with_limit(MAX_STREAM_SIZE)
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize_from::<R, T>(reader)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bank_from_streams<R>(
    evm_state_path: &Path,
    evm_state_version: EvmStateVersion,
    snapshot_streams: &mut SnapshotStreams<R>,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    genesis_config: &GenesisConfig,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_secondary_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
    evm_state_backup_path: &Path,
    skip_purge_verify: bool,
    evm_archive: Option<evm_state::Storage>,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
) -> std::result::Result<Bank, Error>
where
    R: Read,
{
    macro_rules! INTO {
        ($style:ident) => {{
            let (full_snapshot_bank_fields, full_snapshot_accounts_db_fields) =
                $style::Context::deserialize_bank_fields(snapshot_streams.full_snapshot_stream)?;
            let (incremental_snapshot_bank_fields, incremental_snapshot_accounts_db_fields) =
                if let Some(ref mut incremental_snapshot_stream) =
                    snapshot_streams.incremental_snapshot_stream
                {
                    let (bank_fields, accounts_db_fields) =
                        $style::Context::deserialize_bank_fields(incremental_snapshot_stream)?;
                    (Some(bank_fields), Some(accounts_db_fields))
                } else {
                    (None, None)
                };
            let snapshot_accounts_db_fields = SnapshotAccountsDbFields {
                full_snapshot_accounts_db_fields,
                incremental_snapshot_accounts_db_fields,
            };
            let bank = reconstruct_bank_from_fields(
                incremental_snapshot_bank_fields.unwrap_or(full_snapshot_bank_fields),
                snapshot_accounts_db_fields,
                genesis_config,
                evm_state_path,
                account_paths,
                unpacked_append_vec_map,
                debug_keys,
                additional_builtins,
                account_secondary_indexes,
                caching_enabled,
                limit_load_slot_count_from_snapshot,
                shrink_ratio,
                verify_index,
                accounts_db_config,
                accounts_update_notifier,
                evm_state_backup_path,
                skip_purge_verify,
                evm_state_version.support_gc(), // is remote snapshot supported gc?
                true,                           // enable gc mode in current evm state
                evm_archive,
            )?;
            Ok(bank)
        }};
    }
    INTO!(newer).map_err(|err| {
        warn!("bankrc_from_stream error: {:?}", err);
        err
    })
}

pub(crate) fn bank_to_stream<W>(
    evm_version: EvmStateVersion,
    stream: &mut BufWriter<W>,
    bank: &Bank,
    snapshot_storages: &[SnapshotStorage],
) -> Result<(), Error>
where
    W: Write,
{
    let gc_enabled = bank.evm_state.read().unwrap().kvs().gc_enabled();
    if evm_version.support_gc() != gc_enabled {
        return Err(Error::custom(format!(
            "Snapshot gc config is different from config in storage storage_gc={}, version={:?}",
            gc_enabled, evm_version
        )));
    }
    macro_rules! INTO {
        ($style:ident) => {
            bincode::serialize_into(
                stream,
                &SerializableBankAndStorage::<$style::Context> {
                    bank,
                    snapshot_storages,
                    phantom: std::marker::PhantomData::default(),
                },
            )
        };
    }
    INTO!(newer).map_err(|err| {
        warn!("bankrc_to_stream error: {:?}", err);
        err
    })
}

#[cfg(test)]
pub(crate) fn bank_to_stream_no_extra_fields<W>(
    stream: &mut BufWriter<W>,
    bank: &Bank,
    snapshot_storages: &[SnapshotStorage],
) -> Result<(), Error>
where
    W: Write,
{
    macro_rules! INTO {
        ($style:ident) => {
            bincode::serialize_into(
                stream,
                &SerializableBankAndStorageNoExtra::<$style::Context> {
                    bank,
                    snapshot_storages,
                    phantom: std::marker::PhantomData::default(),
                },
            )
        };
    }
    INTO!(newer).map_err(|err| {
        warn!("bankrc_to_stream error: {:?}", err);
        err
    })
}

struct SerializableBankAndStorage<'a, C> {
    bank: &'a Bank,
    snapshot_storages: &'a [SnapshotStorage],
    phantom: std::marker::PhantomData<C>,
}

impl<'a, C: TypeContext<'a>> Serialize for SerializableBankAndStorage<'a, C> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        C::serialize_bank_and_storage(serializer, self)
    }
}

#[cfg(test)]
struct SerializableBankAndStorageNoExtra<'a, C> {
    bank: &'a Bank,
    snapshot_storages: &'a [SnapshotStorage],
    phantom: std::marker::PhantomData<C>,
}

#[cfg(test)]
impl<'a, C: TypeContext<'a>> Serialize for SerializableBankAndStorageNoExtra<'a, C> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        C::serialize_bank_and_storage_without_extra_fields(serializer, self)
    }
}

#[cfg(test)]
impl<'a, C> From<SerializableBankAndStorageNoExtra<'a, C>> for SerializableBankAndStorage<'a, C> {
    fn from(s: SerializableBankAndStorageNoExtra<'a, C>) -> SerializableBankAndStorage<'a, C> {
        let SerializableBankAndStorageNoExtra {
            bank,
            snapshot_storages,
            phantom,
        } = s;
        SerializableBankAndStorage {
            bank,
            snapshot_storages,
            phantom,
        }
    }
}

struct SerializableAccountsDb<'a, C> {
    accounts_db: &'a AccountsDb,
    slot: Slot,
    account_storage_entries: &'a [SnapshotStorage],
    phantom: std::marker::PhantomData<C>,
}

impl<'a, C: TypeContext<'a>> Serialize for SerializableAccountsDb<'a, C> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        C::serialize_accounts_db_fields(serializer, self)
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl<'a, C> solana_frozen_abi::abi_example::IgnoreAsHelper for SerializableAccountsDb<'a, C> {}

#[allow(clippy::too_many_arguments)]
fn reconstruct_bank_from_fields<E>(
    bank_fields: BankFieldsToDeserialize,
    snapshot_accounts_db_fields: SnapshotAccountsDbFields<E>,
    genesis_config: &GenesisConfig,
    evm_state_path: &Path,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_secondary_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
    evm_state_backup_path: &Path,
    skip_purge_verify: bool,
    // true if we restoring from full backup, or from gc
    load_full_backup: bool,
    // true if gc should be enabled
    enable_gc: bool,
    evm_archive: Option<evm_state::Storage>,
) -> Result<Bank, Error>
where
    E: SerializableStorage + std::marker::Sync,
{
    let (accounts_db, reconstructed_accounts_db_info) = reconstruct_accountsdb_from_fields(
        snapshot_accounts_db_fields,
        account_paths,
        unpacked_append_vec_map,
        genesis_config,
        account_secondary_indexes,
        caching_enabled,
        limit_load_slot_count_from_snapshot,
        shrink_ratio,
        verify_index,
        accounts_db_config,
        accounts_update_notifier,
    )?;

    let bank_rc = BankRc::new(Accounts::new_empty(accounts_db), bank_fields.slot);
    // EVM State load
    if evm_state_path.exists() {
        warn!(
            "deleting existing evm state folder {}",
            evm_state_path.display()
        );
        std::fs::remove_dir_all(evm_state_path)?;
    }

    info!(
        "Restoring evm-state snapshot from = {:?}, for root = {}, skip_purge_verify = {}, snapshot_gc = {}, our_state_gc = {}.",
        evm_state_backup_path,
        bank_fields.evm_persist_fields.last_root(),
        skip_purge_verify,
        load_full_backup,
        enable_gc
    );

    // if we force verify, or our gc settings is not equal to settings in snapshot
    if !skip_purge_verify || enable_gc != load_full_backup {
        let mut tmp_evm_state_path_parent = evm_state_path.to_path_buf();
        tmp_evm_state_path_parent.pop();
        let tmp_dir = tempfile::TempDir::new_in(tmp_evm_state_path_parent)?;
        let mut measure = Measure::start("EVM tmp state database restore");
        evm_state::Storage::restore_from(evm_state_backup_path, tmp_dir.path()).map_err(|e| {
            Error::custom(format!("Unable to restore tmp evm backup storage {}", e))
        })?;
        measure.stop();
        info!("{}", measure);
        let src =
            evm_state::Storage::open_persistent(tmp_dir.path(), load_full_backup).map_err(|e| {
                Error::custom(format!("Unable to restore tmp evm backup storage {}", e))
            })?;

        let destination = evm_state::Storage::open_persistent(evm_state_path, enable_gc)
            .map_err(|e| Error::custom(format!("Unable to open destination evm-state {}", e)))?;

        let mut measure = Measure::start("EVM snapshot purging");

        info!("Recreating evm state.");
        // vars to save temp arrays for copy_and_purge
        let (archive_dest, regular_dest);
        let destination: &[_] = if let Some(evm_archive) = evm_archive {
            info!("Copying current evm state to archive during evm purging.");
            archive_dest = [destination, evm_archive];
            &archive_dest
        } else {
            regular_dest = [destination];
            &regular_dest
        };
        evm_state::storage::copy_and_purge(
            src,
            destination,
            bank_fields.evm_persist_fields.last_root(),
        )
        .map_err(|e| Error::custom(format!("Unable to copy_and_purge storage {}", e)))?;
        measure.stop();
        info!("{}", measure);
    } else {
        let mut measure = Measure::start("EVM state database restore");
        evm_state::Storage::restore_from(evm_state_backup_path, evm_state_path)
            .map_err(|e| Error::custom(format!("Unable to restore evm backup storage {}", e)))?;
        measure.stop();
        info!("{}", measure);
        if let Some(evm_archive) = evm_archive {
            info!("Copying current evm state to archive.");
            let src =
                evm_state::Storage::open_persistent(evm_state_path, enable_gc).map_err(|e| {
                    Error::custom(format!("Unable to restore tmp evm backup storage {}", e))
                })?;
            evm_state::storage::copy_and_purge(
                src,
                &[evm_archive],
                bank_fields.evm_persist_fields.last_root(),
            )
            .map_err(|e| Error::custom(format!("Unable to copy_and_purge storage {}", e)))?;
        };
    }

    let evm_state = evm_state::EvmState::load_from(
        evm_state_path,
        bank_fields.evm_persist_fields.clone(),
        enable_gc,
    )
    .map_err(|e| Error::custom(format!("Unable to open EVM state storage {}", e)))?;

    evm_state
        .kvs()
        .cleanup_slots(bank_fields.slot, bank_fields.evm_persist_fields.last_root())
        .map_err(|e| Error::custom(format!("Unable to register slot for evm root {}", e)))?;

    // if limit_load_slot_count_from_snapshot is set, then we need to side-step some correctness checks beneath this call
    let debug_do_not_add_builtins = limit_load_slot_count_from_snapshot.is_some();

    let bank = Bank::new_from_fields(
        evm_state,
        bank_rc,
        genesis_config,
        bank_fields,
        debug_keys,
        additional_builtins,
        debug_do_not_add_builtins,
        reconstructed_accounts_db_info.accounts_data_len,
    );

    info!("rent_collector: {:?}", bank.rent_collector());

    Ok(bank)
}

fn reconstruct_single_storage<E>(
    slot: &Slot,
    append_vec_path: &Path,
    storage_entry: &E,
    append_vec_id: AppendVecId,
    new_slot_storage: &mut HashMap<AppendVecId, Arc<AccountStorageEntry>>,
) -> Result<(), Error>
where
    E: SerializableStorage,
{
    let (accounts, num_accounts) =
        AppendVec::new_from_file(append_vec_path, storage_entry.current_len())?;
    let u_storage_entry =
        AccountStorageEntry::new_existing(*slot, append_vec_id, accounts, num_accounts);

    new_slot_storage.insert(append_vec_id, Arc::new(u_storage_entry));
    Ok(())
}

/// This struct contains side-info while reconstructing the accounts DB from fields.
#[derive(Debug, Default, Copy, Clone)]
struct ReconstructedAccountsDbInfo {
    accounts_data_len: u64,
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_accountsdb_from_fields<E>(
    snapshot_accounts_db_fields: SnapshotAccountsDbFields<E>,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    genesis_config: &GenesisConfig,
    account_secondary_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
    limit_load_slot_count_from_snapshot: Option<usize>,
    shrink_ratio: AccountShrinkThreshold,
    verify_index: bool,
    accounts_db_config: Option<AccountsDbConfig>,
    accounts_update_notifier: Option<AccountsUpdateNotifier>,
) -> Result<(AccountsDb, ReconstructedAccountsDbInfo), Error>
where
    E: SerializableStorage + std::marker::Sync,
{
    let mut accounts_db = AccountsDb::new_with_config(
        account_paths.to_vec(),
        &genesis_config.cluster_type,
        account_secondary_indexes,
        caching_enabled,
        shrink_ratio,
        accounts_db_config,
        accounts_update_notifier,
    );

    let AccountsDbFields(
        snapshot_storages,
        snapshot_version,
        snapshot_slot,
        snapshot_bank_hash_info,
        _snapshot_prior_roots,
        _snapshot_prior_roots_with_hash,
    ) = snapshot_accounts_db_fields.collapse_into()?;

    let snapshot_storages = snapshot_storages.into_iter().collect::<Vec<_>>();

    // Ensure all account paths exist
    for path in &accounts_db.paths {
        std::fs::create_dir_all(path)
            .unwrap_or_else(|err| panic!("Failed to create directory {}: {}", path.display(), err));
    }

    // Remap the deserialized AppendVec paths to point to correct local paths
    let num_collisions = AtomicUsize::new(0);
    let next_append_vec_id = AtomicAppendVecId::new(0);
    let mut measure_remap = Measure::start("remap");
    let mut storage = (0..snapshot_storages.len())
        .into_par_iter()
        .map(|i| {
            let (slot, slot_storage) = &snapshot_storages[i];
            let mut new_slot_storage = HashMap::new();
            for storage_entry in slot_storage {
                let file_name = AppendVec::file_name(*slot, storage_entry.id());

                let append_vec_path = unpacked_append_vec_map.get(&file_name).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} not found in unpacked append vecs", file_name),
                    )
                })?;

                // Remap the AppendVec ID to handle any duplicate IDs that may previously existed
                // due to full snapshots and incremental snapshots generated from different nodes
                let (remapped_append_vec_id, remapped_append_vec_path) = loop {
                    let remapped_append_vec_id = next_append_vec_id.fetch_add(1, Ordering::AcqRel);
                    let remapped_file_name = AppendVec::file_name(*slot, remapped_append_vec_id);
                    let remapped_append_vec_path =
                        append_vec_path.parent().unwrap().join(remapped_file_name);

                    // Break out of the loop in the following situations:
                    // 1. The new ID is the same as the original ID.  This means we do not need to
                    //    rename the file, since the ID is the "correct" one already.
                    // 2. There is not a file already at the new path.  This means it is safe to
                    //    rename the file to this new path.
                    //    **DEVELOPER NOTE:**  Keep this check last so that it can short-circuit if
                    //    possible.
                    if storage_entry.id() == remapped_append_vec_id as SerializedAppendVecId
                        || std::fs::metadata(&remapped_append_vec_path).is_err()
                    {
                        break (remapped_append_vec_id, remapped_append_vec_path);
                    }

                    // If we made it this far, a file exists at the new path.  Record the collision
                    // and try again.
                    num_collisions.fetch_add(1, Ordering::Relaxed);
                };
                // Only rename the file if the new ID is actually different from the original.
                if storage_entry.id() != remapped_append_vec_id as SerializedAppendVecId {
                    std::fs::rename(append_vec_path, &remapped_append_vec_path)?;
                }

                reconstruct_single_storage(
                    slot,
                    &remapped_append_vec_path,
                    storage_entry,
                    remapped_append_vec_id,
                    &mut new_slot_storage,
                )?;
            }
            Ok((*slot, new_slot_storage))
        })
        .collect::<Result<HashMap<Slot, _>, Error>>()?;
    measure_remap.stop();

    // discard any slots with no storage entries
    // this can happen if a non-root slot was serialized
    // but non-root stores should not be included in the snapshot
    storage.retain(|_slot, stores| !stores.is_empty());
    assert!(
        !storage.is_empty(),
        "At least one storage entry must exist from deserializing stream"
    );

    let next_append_vec_id = next_append_vec_id.load(Ordering::Acquire);
    let max_append_vec_id = next_append_vec_id - 1;
    assert!(
        max_append_vec_id <= AppendVecId::MAX / 2,
        "Storage id {} larger than allowed max",
        max_append_vec_id
    );

    // Process deserialized data, set necessary fields in self
    accounts_db
        .bank_hashes
        .write()
        .unwrap()
        .insert(snapshot_slot, snapshot_bank_hash_info);
    accounts_db.storage.map.extend(
        storage
            .into_iter()
            .map(|(slot, slot_storage_entry)| (slot, Arc::new(RwLock::new(slot_storage_entry)))),
    );
    accounts_db
        .next_id
        .store(next_append_vec_id, Ordering::Release);
    accounts_db
        .write_version
        .fetch_add(snapshot_version, Ordering::Release);

    let mut measure_notify = Measure::start("accounts_notify");

    let accounts_db = Arc::new(accounts_db);
    let accounts_db_clone = accounts_db.clone();
    let handle = Builder::new()
        .name("notify_account_restore_from_snapshot".to_string())
        .spawn(move || {
            accounts_db_clone.notify_account_restore_from_snapshot();
        })
        .unwrap();

    let IndexGenerationInfo { accounts_data_len } = accounts_db.generate_index(
        limit_load_slot_count_from_snapshot,
        verify_index,
        genesis_config,
    );

    accounts_db.maybe_add_filler_accounts(&genesis_config.epoch_schedule);

    handle.join().unwrap();
    measure_notify.stop();

    datapoint_info!(
        "reconstruct_accountsdb_from_fields()",
        ("remap-time-us", measure_remap.as_us(), i64),
        (
            "remap-collisions",
            num_collisions.load(Ordering::Relaxed),
            i64
        ),
        ("accountsdb-notify-at-start-us", measure_notify.as_us(), i64),
    );

    Ok((
        Arc::try_unwrap(accounts_db).unwrap(),
        ReconstructedAccountsDbInfo { accounts_data_len },
    ))
}
