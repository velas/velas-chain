//! The `genesis_config` module is a library for generating the chain's genesis config.

#![cfg(feature = "full")]

use crate::{
    account::Account,
    clock::{UnixTimestamp, DEFAULT_TICKS_PER_SLOT},
    epoch_schedule::EpochSchedule,
    fee_calculator::FeeRateGovernor,
    hash::{hash, Hash},
    inflation::Inflation,
    native_token::lamports_to_sol,
    poh_config::PohConfig,
    pubkey::Pubkey,
    rent::Rent,
    shred_version::compute_shred_version,
    signature::{Keypair, Signer},
    system_program,
    timing::years_as_slots,
};

use bincode::{deserialize, serialize};
use chrono::{TimeZone, Utc};
use evm_state::H256;
use itertools::Itertools;
use log::warn;
use memmap2::Mmap;
use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

// deprecated default that is no longer used
pub const UNUSED_DEFAULT: u64 = 1024;
pub const EVM_GENESIS: &str = "evm-state-genesis";

// Dont load to memory accounts, more specified count
use evm_state::MAX_IN_MEMORY_EVM_ACCOUNTS;
// The order can't align with release lifecycle only to remain ABI-compatible...
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, AbiEnumVisitor, AbiExample)]
pub enum ClusterType {
    Testnet,
    MainnetBeta,
    Devnet,
    Development,
}

impl ClusterType {
    pub const STRINGS: [&'static str; 4] = ["development", "devnet", "testnet", "mainnet-beta"];
}

impl FromStr for ClusterType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "development" => Ok(ClusterType::Development),
            "devnet" => Ok(ClusterType::Devnet),
            "testnet" => Ok(ClusterType::Testnet),
            "mainnet-beta" => Ok(ClusterType::MainnetBeta),
            _ => Err(format!("{} is unrecognized for cluster type", s)),
        }
    }
}

#[frozen_abi(digest = "FX48h9vjJZPvka4J9UvcPQkVcMdYLQujhbvUmVFq6qLx")]
#[derive(Serialize, Deserialize, Debug, Clone, AbiExample)]
pub struct GenesisConfig {
    /// when the network (bootstrap validator) was started relative to the UNIX Epoch
    pub creation_time: UnixTimestamp,
    /// initial accounts
    pub accounts: BTreeMap<Pubkey, Account>,
    /// built-in programs
    pub native_instruction_processors: Vec<(String, Pubkey)>,
    /// accounts for network rewards, these do not count towards capitalization
    pub rewards_pools: BTreeMap<Pubkey, Account>,
    pub ticks_per_slot: u64,
    pub unused: u64,
    /// network speed configuration
    pub poh_config: PohConfig,
    /// this field exists only to ensure that the binary layout of GenesisConfig remains compatible
    /// with the Solana v0.23 release line
    pub __backwards_compat_with_v0_23: u64,
    /// transaction fee config
    pub fee_rate_governor: FeeRateGovernor,
    /// rent config
    pub rent: Rent,
    /// inflation config
    pub inflation: Inflation,
    /// how slots map to epochs
    pub epoch_schedule: EpochSchedule,
    /// network runlevel
    pub cluster_type: ClusterType,
    /// Initial data for evm part
    pub evm_root_hash: H256,
    /// EVM chain id
    pub evm_chain_id: u64,
}

pub static EVM_MAINNET_CHAIN_ID: u64 = 106;
pub static EVM_TESTNET_CHAIN_ID: u64 = 111;
pub static EVM_DEVELOP_CHAIN_ID: u64 = 0xdead;

// useful for basic tests
pub fn create_genesis_config(lamports: u64) -> (GenesisConfig, Keypair) {
    let faucet_keypair = Keypair::new();
    (
        GenesisConfig::new(
            &[(
                faucet_keypair.pubkey(),
                Account::new(lamports, 0, &system_program::id()),
            )],
            &[],
        ),
        faucet_keypair,
    )
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            creation_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as UnixTimestamp,
            accounts: BTreeMap::default(),
            native_instruction_processors: Vec::default(),
            rewards_pools: BTreeMap::default(),
            ticks_per_slot: DEFAULT_TICKS_PER_SLOT,
            unused: UNUSED_DEFAULT,
            poh_config: PohConfig::default(),
            inflation: Inflation::default(),
            __backwards_compat_with_v0_23: 0,
            fee_rate_governor: FeeRateGovernor::default(),
            rent: Rent::default(),
            epoch_schedule: EpochSchedule::default(),
            cluster_type: ClusterType::Development,
            evm_root_hash: evm_state::empty_trie_hash(),
            evm_chain_id: EVM_DEVELOP_CHAIN_ID,
        }
    }
}

impl GenesisConfig {
    pub fn new(
        accounts: &[(Pubkey, Account)],
        native_instruction_processors: &[(String, Pubkey)],
    ) -> Self {
        Self {
            accounts: accounts
                .iter()
                .cloned()
                .collect::<BTreeMap<Pubkey, Account>>(),
            native_instruction_processors: native_instruction_processors.to_vec(),
            ..GenesisConfig::default()
        }
    }

    pub fn hash(&self) -> Hash {
        let serialized = serialize(&self).unwrap();
        hash(&serialized)
    }

    fn genesis_filename(ledger_path: &Path) -> PathBuf {
        Path::new(ledger_path).join("genesis.bin")
    }

    pub fn load(ledger_path: &Path) -> Result<Self, std::io::Error> {
        let filename = Self::genesis_filename(&ledger_path);
        let file = OpenOptions::new()
            .read(true)
            .open(&filename)
            .map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unable to open {:?}: {:?}", filename, err),
                )
            })?;

        //UNSAFE: Required to create a Mmap
        let mem = unsafe { Mmap::map(&file) }.map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unable to map {:?}: {:?}", filename, err),
            )
        })?;

        let genesis_config = deserialize(&mem).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unable to deserialize {:?}: {:?}", filename, err),
            )
        })?;
        Ok(genesis_config)
    }

    pub fn write(&self, ledger_path: &Path) -> Result<(), std::io::Error> {
        let serialized = serialize(&self).map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unable to serialize: {:?}", err),
            )
        })?;

        std::fs::create_dir_all(&ledger_path)?;

        let mut file = File::create(Self::genesis_filename(&ledger_path))?;
        file.write_all(&serialized)
    }

    pub fn generate_evm_state(
        &self,
        ledger_path: &Path,
        evm_state_json: Option<&Path>,
    ) -> Result<(), std::io::Error> {
        let evm_state_path = tempfile::TempDir::new()?;
        let evm_state = evm_state::EvmState::new(evm_state_path.path())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{}.", e)))?;
        let mut evm_state = if let evm_state::EvmState::Incomming(evm_state) = evm_state {
            evm_state
        } else {
            unreachable!("Expected new evm-state to be writable.");
        };

        if let Some(evm_state_json) = evm_state_json {
            let accounts = evm_genesis::read_accounts(evm_state_json)?;

            for chunk in &accounts.chunks(MAX_IN_MEMORY_EVM_ACCOUNTS) {
                let chunk: Result<Vec<_>, _> = chunk.collect();
                let chunk = chunk?;
                log::info!("Adding {} accounts to evm state.", chunk.len());
                evm_state.set_initial(chunk);
            }
        } else {
            warn!("Generating genesis with empty evm state");
            match self.cluster_type {
                ClusterType::Development | ClusterType::Devnet => (),
                cluster_type => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Trying to generate genesis for cluster = {:?} without evm state root hash provided.", cluster_type),
                    ))
                }
            }
        };
        // create zero block
        let committed = evm_state.commit_block(0, H256::zero());
        let genesis_evm_block = &committed.state.block;
        assert_eq!(genesis_evm_block.state_root, self.evm_root_hash);
        // TOOD: assert block number, and parent block_hash
        let mut evm_backup = ledger_path.to_path_buf();
        evm_backup.push(EVM_GENESIS);

        let evm_state: evm_state::EvmState = committed.into();
        let tmp_backup = evm_state
            .make_backup()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{}.", e)))?;
        std::fs::create_dir_all(ledger_path)?;
        evm_genesis::copy_dir(tmp_backup, evm_backup).unwrap(); // use copy instead of move, to work with cross device-links (backup makes hardlink and is immovable between devices).
        Ok(())
    }

    pub fn set_evm_root_hash(&mut self, root_hash: H256) {
        self.evm_root_hash = root_hash;
    }

    pub fn add_account(&mut self, pubkey: Pubkey, account: Account) {
        self.accounts.insert(pubkey, account);
    }

    pub fn add_native_instruction_processor(&mut self, name: String, program_id: Pubkey) {
        self.native_instruction_processors.push((name, program_id));
    }

    pub fn hashes_per_tick(&self) -> Option<u64> {
        self.poh_config.hashes_per_tick
    }

    pub fn ticks_per_slot(&self) -> u64 {
        self.ticks_per_slot
    }

    pub fn ns_per_slot(&self) -> u128 {
        self.poh_config.target_tick_duration.as_nanos() * self.ticks_per_slot() as u128
    }

    pub fn slots_per_year(&self) -> f64 {
        years_as_slots(
            1.0,
            &self.poh_config.target_tick_duration,
            self.ticks_per_slot(),
        )
    }
}

impl fmt::Display for GenesisConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\
             Creation time: {}\n\
             Cluster type: {:?}\n\
             Genesis hash: {}\n\
             Shred version: {}\n\
             Ticks per slot: {:?}\n\
             Hashes per tick: {:?}\n\
             Slots per epoch: {}\n\
             Warmup epochs: {}abled\n\
             {:?}\n\
             {:?}\n\
             {:?}\n\
             Capitalization: {} VLX in {} accounts\n\
             Native instruction processors: {:#?}\n\
             Rewards pool: {:#?}\n\
             EVM chain id: {}\n\
             ",
            Utc.timestamp(self.creation_time, 0).to_rfc3339(),
            self.cluster_type,
            self.hash(),
            compute_shred_version(&self.hash(), None),
            self.ticks_per_slot,
            self.poh_config.hashes_per_tick,
            self.epoch_schedule.slots_per_epoch,
            if self.epoch_schedule.warmup {
                "en"
            } else {
                "dis"
            },
            self.inflation,
            self.rent,
            self.fee_rate_governor,
            lamports_to_sol(
                self.accounts
                    .iter()
                    .map(|(pubkey, account)| {
                        if account.lamports == 0 {
                            panic!("{:?}", (pubkey, account));
                        }
                        account.lamports
                    })
                    .sum::<u64>()
            ),
            self.accounts.len(),
            self.native_instruction_processors,
            self.rewards_pools,
            self.evm_chain_id,
        )
    }
}

pub mod evm_genesis {
    use evm_rpc::{Bytes, Hex};
    use evm_state::{MemoryAccount, H160, H256, U256};

    use serde::{de, Deserialize, Serialize};
    use serde_json::{de::IoRead, Deserializer};
    use sha3::{Digest, Keccak256};
    use std::fs::File;
    use std::io::{BufRead, BufReader, Error, ErrorKind};
    use std::iter;
    use std::path::Path;
    use std::{collections::BTreeMap, io::Write};

    use std::fs;
    use std::path::PathBuf;

    pub fn copy_dir(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let mut stack = vec![PathBuf::from(from.as_ref())];

        let output_root = PathBuf::from(to.as_ref());
        let input_root = PathBuf::from(from.as_ref()).components().count();

        while let Some(working_path) = stack.pop() {
            // Generate a relative path
            let src: PathBuf = working_path.components().skip(input_root).collect();

            // Create a destination if missing
            let dest = if src.components().count() == 0 {
                output_root.clone()
            } else {
                output_root.join(&src)
            };
            if fs::metadata(&dest).is_err() {
                fs::create_dir_all(&dest)?;
            }

            for entry in fs::read_dir(working_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    match path.file_name() {
                        Some(filename) => {
                            let dest_path = dest.join(filename);
                            fs::copy(&path, &dest_path)?;
                        }
                        None => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Cannot copy file {}", path.display()),
                            ))
                        }
                    }
                }
            }
        }

        Ok(())
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ExtendedMemoryAccount {
        /// Account nonce.
        #[serde(deserialize_with = "deserialize_skip_hex_prefix")]
        pub nonce: U256,
        /// Account balance.
        #[serde(deserialize_with = "deserialize_skip_hex_prefix")]
        pub balance: U256,
        /// Full account storage.
        pub storage: Option<BTreeMap<Hex<H256>, Hex<H256>>>,
        /// Account code.
        #[serde(deserialize_with = "deserialize_skip_hex_prefix_bytes")]
        #[serde(default)]
        pub code: Option<Bytes>,
        pub code_hash: Option<Hex<H256>>,
        pub storage_root: Option<Hex<H256>>,
    }

    fn deserialize_skip_hex_prefix<'de, D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let data = String::deserialize(deserializer)?;
        U256::from_str_radix(&data, 16).map_err(|e| de::Error::custom(format!("{}", e)))
    }

    fn deserialize_skip_hex_prefix_bytes<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let data = Option::<String>::deserialize(deserializer)?;
        data.map(|data| {
            hex::decode(data)
                .map(Bytes)
                .map_err(|e| de::Error::custom(format!("{}", e)))
        })
        .transpose()
    }

    impl From<ExtendedMemoryAccount> for MemoryAccount {
        fn from(extended: ExtendedMemoryAccount) -> MemoryAccount {
            MemoryAccount {
                nonce: extended.nonce,
                balance: extended.balance,
                storage: extended
                    .storage
                    .into_iter()
                    .flatten()
                    .map(|(k, v)| (k.0, v.0))
                    .collect(),
                code: extended.code.unwrap_or_else(|| Bytes(Vec::new())).0,
            }
        }
    }

    /// Streaming deserializer for key,value pair in json.
    /// input format is following:
    ///
    /// line0:   { "state": {
    /// line1-N: "0x....": {...},
    /// lineN:   }}
    ///
    /// serde_json StreamDeserializer can only work with valid json Value. '"key":{object}' - is not a valid json Value.
    ///
    pub struct StreamAccountReader<R> {
        reader: R,
    }

    impl<'a, R: BufRead> StreamAccountReader<IoRead<R>> {
        pub fn new(mut reader: R) -> Result<Self, Error> {
            let mut buffer = String::new();

            let _header_size = reader.read_line(&mut buffer)?;
            if buffer.as_str() != "{ \"state\": {\n" {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Trying to read header of evm state json file, and it is invalid, should be '{{ \"state\": {{' got: {}", buffer),
                ));
            }

            Ok(Self {
                reader: IoRead::new(reader),
            })
        }
    }

    impl<'a, R: serde_json::de::Read<'a>> StreamAccountReader<R> {
        /// Return true if end brackets found.
        fn end_brackets(&mut self) -> Result<bool, Error> {
            self.skip_whitespaces()?;
            let end_bracket = self
                .reader
                .peek()
                .map_err(|e| Error::new(ErrorKind::Other, format!("Read buffer error {:?}", e)))?;

            if let Some(b'}') = end_bracket {
                // json should close 'state' object, and main object: '{"state": { .. }}'
                for _ in 0..2 {
                    // check that 3 brackets found
                    let end_bracket = self.reader.next().map_err(|e| {
                        Error::new(ErrorKind::Other, format!("Read buffer error {:?}", e))
                    })?;
                    if end_bracket.is_none() {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "No enough end brackets at end of file found.".to_string(),
                        ));
                    }
                }
                return Ok(true);
            }
            Ok(false)
        }

        fn skip_trailing_comma(&mut self) -> Result<(), Error> {
            if let Some(b',') = self.reader.peek()? {
                self.reader.discard()
            }
            Ok(())
        }

        fn skip_whitespaces(&mut self) -> Result<(), Error> {
            while let Some(c) = self.reader.peek()? {
                // Discard all whitespaces, return if other
                if !char::from(c).is_whitespace() {
                    return Ok(());
                }

                self.reader.discard()
            }
            Ok(())
        }

        fn skip_colon(&mut self) -> Result<(), Error> {
            match self.reader.next() {
                Ok(Some(b':')) => Ok(()),
                s => Err(Error::new(
                    ErrorKind::Other,
                    format!("cannot skip colon {:?}", s),
                )),
            }
        }

        fn read_token<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, Error> {
            let mut stream = Deserializer::new(&mut self.reader).into_iter::<T>();

            match stream.next() {
                None => Err(Error::new(
                    ErrorKind::Other,
                    "Buffer ended unexpected".to_string(),
                )),
                Some(Err(e)) => Err(Error::new(
                    ErrorKind::Other,
                    format!("Deserialization error {:?}", e),
                )),
                Some(Ok(o)) => Ok(o),
            }
        }

        /// Read account, try to validate code_hash and storage_root.
        ///
        /// Result<Option<...>> instead of Option<Result<>>, to allow power of `Try` for error handling.
        pub fn read_account(&mut self) -> Result<Option<(H160, MemoryAccount)>, Error> {
            if self.end_brackets()? {
                return Ok(None);
            }
            let key: Hex<H160> = self.read_token()?;
            self.skip_colon()?;

            let value: ExtendedMemoryAccount = self.read_token()?;

            self.skip_trailing_comma()?;

            match (&value.storage_root, &value.storage) {
                (Some(expected_storage), Some(storage)) => {
                    let storage_root =
                        triehash::sec_trie_root::<keccak_hasher::KeccakHasher, _, _, _>(
                            storage.iter().map(|(k, v)| {
                                (&k.0, rlp::encode(&U256::from_big_endian(&v.0[..])))
                            }),
                        );
                    let storage_root = H256::from_slice(&storage_root);
                    assert_eq!(storage_root, expected_storage.0, "Storage hash mismatched")
                }
                (None, None) => {}
                _ => panic!(
                    "Expected storage_root and storage properties to exist in account: {:?}.",
                    key
                ),
            }
            match (&value.code_hash, &value.code) {
                (Some(expected_code), Some(code)) => {
                    let code_hash = H256::from_slice(Keccak256::digest(&code.0).as_slice());
                    assert_eq!(code_hash, expected_code.0, "Code hash mismatched")
                }
                (None, None) => {}
                _ => panic!(
                    "Expected code_hash and code properties to exist in account: {:?}.",
                    key
                ),
            }

            Ok(Some((key.0, value.into())))
        }
    }

    pub fn read_accounts(
        evm_state_snapshot: &Path,
    ) -> Result<impl Iterator<Item = Result<(H160, MemoryAccount), Error>>, Error> {
        let evm_file = BufReader::new(File::open(&evm_state_snapshot)?);

        let mut reader = StreamAccountReader::new(evm_file)?;
        Ok(iter::from_fn(move || reader.read_account().transpose()))
    }

    pub fn generate_evm_state_json(file: &Path) -> Result<H256, Error> {
        let json = b"{ \"state\": {\n}}";
        let mut file = std::fs::File::create(file)?;
        file.write_all(&*json)?;
        Ok(evm_state::empty_trie_hash())
    }
}

#[cfg(test)]
mod tests {
    use evm_state::{MemoryAccount, H160};

    use super::evm_genesis::*;
    use super::*;
    use crate::signature::{Keypair, Signer};
    use std::path::PathBuf;

    fn make_tmp_path(name: &str) -> PathBuf {
        let out_dir = std::env::var("FARF_DIR").unwrap_or_else(|_| "farf".to_string());
        let keypair = Keypair::new();

        let path = [
            out_dir,
            "tmp".to_string(),
            format!("{}-{}", name, keypair.pubkey()),
        ]
        .iter()
        .collect();

        // whack any possible collision
        let _ignored = std::fs::remove_dir_all(&path);
        // whack any possible collision
        let _ignored = std::fs::remove_file(&path);

        path
    }

    #[test]
    fn test_evm_genesis_config() {
        let faucet_keypair = Keypair::new();
        let mut config = GenesisConfig::default();
        config.add_account(
            faucet_keypair.pubkey(),
            Account::new(10_000, 0, &Pubkey::default()),
        );
        config.add_account(
            solana_sdk::pubkey::new_rand(),
            Account::new(1, 0, &Pubkey::default()),
        );
        config.add_native_instruction_processor("hi".to_string(), solana_sdk::pubkey::new_rand());

        assert_eq!(config.accounts.len(), 2);
        assert!(config
            .accounts
            .iter()
            .any(|(pubkey, account)| *pubkey == faucet_keypair.pubkey()
                && account.lamports == 10_000));

        let path = &make_tmp_path("genesis_config");
        let evm_state_path = &make_tmp_path("evm_state_path");
        std::fs::create_dir_all(&evm_state_path).unwrap();
        let evm_state_path = evm_state_path.join("file.json");
        let evm_state_root = evm_genesis::generate_evm_state_json(&evm_state_path).unwrap();
        config.evm_root_hash = evm_state_root;
        config
            .generate_evm_state(&path, Some(&evm_state_path))
            .expect("generate_evm_state");
        config.write(&path).expect("write");
        let loaded_config = GenesisConfig::load(&path).expect("load");
        assert_eq!(config.hash(), loaded_config.hash());
        let _ignored = std::fs::remove_file(&evm_state_path);
        let _ignored = std::fs::remove_file(&path);
    }

    #[test]
    fn test_genesis_config() {
        let faucet_keypair = Keypair::new();
        let mut config = GenesisConfig::default();
        config.add_account(
            faucet_keypair.pubkey(),
            Account::new(10_000, 0, &Pubkey::default()),
        );
        config.add_account(
            solana_sdk::pubkey::new_rand(),
            Account::new(1, 0, &Pubkey::default()),
        );
        config.add_native_instruction_processor("hi".to_string(), solana_sdk::pubkey::new_rand());
        config.evm_chain_id = 0x42;

        assert_eq!(config.accounts.len(), 2);
        assert!(config
            .accounts
            .iter()
            .any(|(pubkey, account)| *pubkey == faucet_keypair.pubkey()
                && account.lamports == 10_000));

        let path = &make_tmp_path("genesis_config");
        config.write(&path).expect("write");
        let loaded_config = GenesisConfig::load(&path).expect("load");
        assert_eq!(config.hash(), loaded_config.hash());
        let _ignored = std::fs::remove_file(&path);
    }

    fn check_evm_genesis_file(data: &str) -> Result<BTreeMap<H160, MemoryAccount>, std::io::Error> {
        let mut reader = StreamAccountReader::new(data.as_bytes())?;

        std::iter::from_fn(move || reader.read_account().transpose()).collect()
    }

    #[test]
    fn test_invalid_evm_genesis() {
        let no_header = r#"
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"}
        }}"#;
        assert!(dbg!(check_evm_genesis_file(no_header)).is_err());

        let no_footer = r#"{ "state": {
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"}
        "#;
        assert!(dbg!(check_evm_genesis_file(no_footer)).is_err());

        let no_colon = r#"{ "state": {
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c", {"balance": "2544faa778090e00000", "nonce": "0"}
        }}"#;
        assert!(dbg!(check_evm_genesis_file(no_colon)).is_err());

        let not_valid_key = r#"{ "state": {
            "0xKKKKKKKKKKKKKKKKKKKKK": {"balance": "2544faa778090e00000", "nonce": "0"}
        }}"#;
        assert!(dbg!(check_evm_genesis_file(not_valid_key)).is_err());
    }

    #[test]
    #[should_panic]
    fn invalid_code_hash() {
        let invalid_code_hash = r#"{ "state": {
            "0x984cf4e0001003d4ef5328d0fea9a3a430b78027": {"balance": "0", "nonce": "1", "code_hash": "0x11111111111111111111111110be7c0893f036ad196680a723a9665e3681e165", "code": "60102233" }
        }}"#;
        let _expect_panic = check_evm_genesis_file(invalid_code_hash);
    }
    #[test]
    #[should_panic]
    fn invalid_storage_hash() {
        let invalid_storage_hash = r#"{ "state": {
            "0x984cf4e0001003d4ef5328d0fea9a3a430b78037": {"balance": "0", "nonce": "1", "storage_root": "0x11111111111111111111111110be7c0893f036ad196680a723a9665e3681e165", "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000c47fa223c0b394a6bebb360603c9505dcebdcbe6",
                    "0x0000000000000000000000000000000000000000000000000000000000000003": "0x0000000000000000000000003a1a9a4f4167b8c55f13b7189f210cc7b989d52b"
            }}
        }}"#;
        let _expect_panic = check_evm_genesis_file(invalid_storage_hash);
    }

    #[test]
    fn test_valid_evm_genesis() {
        let json_one_account = r#"{ "state": {
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"}
        }}"#;
        assert_eq!(check_evm_genesis_file(json_one_account).unwrap().len(), 1);

        let json_two_accounts = r#"{ "state": {
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"},
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5e": {"balance": "2544faa778090e00000", "nonce": "0"}
        }}"#;
        assert_eq!(check_evm_genesis_file(json_two_accounts).unwrap().len(), 2);

        let json_two_accounts_full = r#"{ "state": {
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"},
            "0x984cf4e0001003d4ef5328d0fea9a3a430b78027": {"balance": "0", "nonce": "1", "code_hash": "0x5304993ef62b8112c1e117e13d564987d722edb2588c485c7a074aac542ad710", "code": "60102233", "storage_root": "0xee496207d2c8ef7e41788519fc346ced8255be4850587f290b84d63bf405266a", "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000c47fa223c0b394a6bebb360603c9505dcebdcbe6",
                    "0x0000000000000000000000000000000000000000000000000000000000000003": "0x0000000000000000000000003a1a9a4f4167b8c55f13b7189f210cc7b989d52b"
            }}
        }}"#;
        assert_eq!(
            check_evm_genesis_file(json_two_accounts_full)
                .unwrap()
                .len(),
            2
        );

        let json_two_accounts_full = r#"{ "state": {
            "0x984cf4e0001003d4ef5328d0fea9a3a430b78027": {"balance": "0", "nonce": "1", "code_hash": "0x5304993ef62b8112c1e117e13d564987d722edb2588c485c7a074aac542ad710", "code": "60102233", "storage_root": "0xee496207d2c8ef7e41788519fc346ced8255be4850587f290b84d63bf405266a", "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000c47fa223c0b394a6bebb360603c9505dcebdcbe6",
                    "0x0000000000000000000000000000000000000000000000000000000000000003": "0x0000000000000000000000003a1a9a4f4167b8c55f13b7189f210cc7b989d52b"
            }},
            "0xffbb13a995ddf6ad35cf533e69f38d38887e8f5c": {"balance": "2544faa778090e00000", "nonce": "0"},
            "0x984cf4e0001003d4ef5328d0fea9a3a430b78037": {"balance": "0", "nonce": "1", "storage_root": "0xee496207d2c8ef7e41788519fc346ced8255be4850587f290b84d63bf405266a", "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": "0x000000000000000000000000c47fa223c0b394a6bebb360603c9505dcebdcbe6",
                    "0x0000000000000000000000000000000000000000000000000000000000000003": "0x0000000000000000000000003a1a9a4f4167b8c55f13b7189f210cc7b989d52b"
            }}
        }}"#;
        assert_eq!(
            check_evm_genesis_file(json_two_accounts_full)
                .unwrap()
                .len(),
            3
        );
    }
}
