use {
    crate::{
        accounts::Accounts,
        accounts_db::{AccountStorageEntry, AccountsDb, AppendVecId, BankHashInfo},
        accounts_index::{AccountSecondaryIndexes, Ancestors},
        append_vec::AppendVec,
        bank::{Bank, BankFieldsToDeserialize, BankRc, Builtins},
        blockhash_queue::{BlockHashEvm, BlockhashQueue},
        epoch_stakes::EpochStakes,
        hardened_unpack::UnpackedAppendVecMap,
        message_processor::MessageProcessor,
        rent_collector::RentCollector,
        serde_snapshot::future::SerializableStorage,
        stakes::Stakes,
    },
    bincode,
    bincode::{config::Options, Error},
    log::*,
    serde::{de::DeserializeOwned, de::Error as _, Deserialize, Serialize},
    solana_sdk::{
        clock::{Epoch, Slot, UnixTimestamp},
        epoch_schedule::EpochSchedule,
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        genesis_config::ClusterType,
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
        sync::{atomic::Ordering, Arc, RwLock},
        time::Instant,
    },
};

#[cfg(RUSTC_WITH_SPECIALIZATION)]
use solana_frozen_abi::abi_example::IgnoreAsHelper;

mod common;
mod future;
mod tests;
mod utils;

use future::Context as TypeContextFuture;
use solana_measure::measure::Measure;
#[allow(unused_imports)]
use utils::{serialize_iter_as_map, serialize_iter_as_seq, serialize_iter_as_tuple};

// a number of test cases in accounts_db use this
#[cfg(test)]
pub(crate) use self::tests::reconstruct_accounts_db_via_serialization;

pub(crate) use crate::accounts_db::{SnapshotStorage, SnapshotStorages};

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
struct AccountsDbFields<T>(HashMap<Slot, Vec<T>>, u64, Slot, BankHashInfo);

trait TypeContext<'a> {
    type SerializableAccountStorageEntry: Serialize
        + DeserializeOwned
        + From<&'a AccountStorageEntry>
        + SerializableStorage;

    fn serialize_bank_and_storage<S: serde::ser::Serializer>(
        serializer: S,
        serializable_bank: &SerializableBankAndStorage<'a, Self>,
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
pub(crate) fn bank_from_stream<R>(
    evm_state_path: &Path,
    evm_state_version: EvmStateVersion,
    stream: &mut BufReader<R>,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    genesis_config: &GenesisConfig,
    frozen_account_pubkeys: &[Pubkey],
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
    evm_state_backup_path: &Path,
    skip_purge_verify: bool,
    evm_archive: Option<evm_state::Storage>,
) -> std::result::Result<Bank, Error>
where
    R: Read,
{
    let (bank_fields, accounts_db_fields) = TypeContextFuture::deserialize_bank_fields(stream)?;
    reconstruct_bank_from_fields(
        bank_fields,
        accounts_db_fields,
        genesis_config,
        frozen_account_pubkeys,
        evm_state_path,
        account_paths,
        unpacked_append_vec_map,
        debug_keys,
        additional_builtins,
        account_indexes,
        caching_enabled,
        evm_state_backup_path,
        evm_state_version.support_gc(),
        skip_purge_verify,
        true, // enable gc
        evm_archive,
    )
    .map_err(|err| {
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
    bincode::serialize_into(
        stream,
        &SerializableBankAndStorage::<TypeContextFuture> {
            bank,
            snapshot_storages,
            phantom: std::marker::PhantomData::default(),
        },
    )
    .map_err(|err| {
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
impl<'a, C> IgnoreAsHelper for SerializableAccountsDb<'a, C> {}

#[allow(clippy::too_many_arguments)]
fn reconstruct_bank_from_fields<E>(
    bank_fields: BankFieldsToDeserialize,
    accounts_db_fields: AccountsDbFields<E>,
    genesis_config: &GenesisConfig,
    frozen_account_pubkeys: &[Pubkey],
    evm_state_path: &Path,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    debug_keys: Option<Arc<HashSet<Pubkey>>>,
    additional_builtins: Option<&Builtins>,
    account_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
    evm_state_backup_path: &Path,
    // true if we restoring from full backup, or from gc
    load_full_backup: bool,
    skip_purge_verify: bool,
    // true if gc should be enabled
    enable_gc: bool,
    evm_archive: Option<evm_state::Storage>,
) -> Result<Bank, Error>
where
    E: SerializableStorage,
{
    let mut accounts_db = reconstruct_accountsdb_from_fields(
        accounts_db_fields,
        account_paths,
        unpacked_append_vec_map,
        &genesis_config.cluster_type,
        account_indexes,
        caching_enabled,
    )?;
    accounts_db.freeze_accounts(&bank_fields.ancestors, frozen_account_pubkeys);

    let bank_rc = BankRc::new(Accounts::new_empty(accounts_db), bank_fields.slot);
    // EVM State load
    if evm_state_path.exists() {
        warn!(
            "deleting existing evm state folder {}",
            evm_state_path.display()
        );
        std::fs::remove_dir_all(&evm_state_path)?;
    }

    info!(
        "Restoring evm-state snapshot, for root = {}, skip_purge_verify = {}, snapshot_gc = {}, our_state_gc = {}.",
        bank_fields.evm_persist_feilds.last_root(),
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
        evm_state::Storage::restore_from(evm_state_backup_path, &tmp_dir.path()).map_err(|e| {
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
            bank_fields.evm_persist_feilds.last_root(),
        )
        .map_err(|e| Error::custom(format!("Unable to copy_and_purge storage {}", e)))?;
        measure.stop();
        info!("{}", measure);
    } else {
        let mut measure = Measure::start("EVM state database restore");
        evm_state::Storage::restore_from(evm_state_backup_path, &evm_state_path)
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
                bank_fields.evm_persist_feilds.last_root(),
            )
            .map_err(|e| Error::custom(format!("Unable to copy_and_purge storage {}", e)))?;
        };
    }

    let evm_state = evm_state::EvmState::load_from(
        evm_state_path,
        bank_fields.evm_persist_feilds.clone(),
        enable_gc,
    )
    .map_err(|e| Error::custom(format!("Unable to open EVM state storage {}", e)))?;

    evm_state
        .kvs()
        .cleanup_slots(bank_fields.slot, bank_fields.evm_persist_feilds.last_root())
        .map_err(|e| Error::custom(format!("Unable to register slot for evm root {}", e)))?;

    let bank = Bank::new_from_fields(
        evm_state,
        bank_rc,
        genesis_config,
        bank_fields,
        debug_keys,
        additional_builtins,
    );

    Ok(bank)
}

fn reconstruct_accountsdb_from_fields<E>(
    accounts_db_fields: AccountsDbFields<E>,
    account_paths: &[PathBuf],
    unpacked_append_vec_map: UnpackedAppendVecMap,
    cluster_type: &ClusterType,
    account_indexes: AccountSecondaryIndexes,
    caching_enabled: bool,
) -> Result<AccountsDb, Error>
where
    E: SerializableStorage,
{
    let mut accounts_db = AccountsDb::new_with_config(
        account_paths.to_vec(),
        cluster_type,
        account_indexes,
        caching_enabled,
    );
    let AccountsDbFields(storage, version, slot, bank_hash_info) = accounts_db_fields;

    // Ensure all account paths exist
    for path in &accounts_db.paths {
        std::fs::create_dir_all(path)
            .unwrap_or_else(|err| panic!("Failed to create directory {}: {}", path.display(), err));
    }

    let mut last_log_update = Instant::now();
    let mut remaining_slots_to_process = storage.len();

    // Remap the deserialized AppendVec paths to point to correct local paths
    let mut storage = storage
        .into_iter()
        .map(|(slot, mut slot_storage)| {
            let now = Instant::now();
            if now.duration_since(last_log_update).as_secs() >= 10 {
                info!("{} slots remaining...", remaining_slots_to_process);
                last_log_update = now;
            }
            remaining_slots_to_process -= 1;

            let mut new_slot_storage = HashMap::new();
            for storage_entry in slot_storage.drain(..) {
                let file_name = AppendVec::file_name(slot, storage_entry.id());

                let append_vec_path = unpacked_append_vec_map.get(&file_name).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{} not found in unpacked append vecs", file_name),
                    )
                })?;

                let (accounts, num_accounts) =
                    AppendVec::new_from_file(append_vec_path, storage_entry.current_len())?;
                let u_storage_entry = AccountStorageEntry::new_existing(
                    slot,
                    storage_entry.id(),
                    accounts,
                    num_accounts,
                );

                new_slot_storage.insert(storage_entry.id(), Arc::new(u_storage_entry));
            }
            Ok((slot, new_slot_storage))
        })
        .collect::<Result<HashMap<Slot, _>, Error>>()?;

    // discard any slots with no storage entries
    // this can happen if a non-root slot was serialized
    // but non-root stores should not be included in the snapshot
    storage.retain(|_slot, stores| !stores.is_empty());

    accounts_db
        .bank_hashes
        .write()
        .unwrap()
        .insert(slot, bank_hash_info);

    // Process deserialized data, set necessary fields in self
    let max_id: usize = *storage
        .values()
        .flat_map(HashMap::keys)
        .max()
        .expect("At least one storage entry must exist from deserializing stream");

    {
        accounts_db.storage.0.extend(
            storage.into_iter().map(|(slot, slot_storage_entry)| {
                (slot, Arc::new(RwLock::new(slot_storage_entry)))
            }),
        );
    }

    if max_id > AppendVecId::MAX / 2 {
        panic!("Storage id {} larger than allowed max", max_id);
    }

    accounts_db.next_id.store(max_id + 1, Ordering::Relaxed);
    accounts_db
        .write_version
        .fetch_add(version, Ordering::Relaxed);
    accounts_db.generate_index();
    Ok(accounts_db)
}
