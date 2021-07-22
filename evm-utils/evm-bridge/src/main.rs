use log::*;

use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use evm_rpc::basic::BasicERPC;
use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain_mock::ChainMockERPC;
use evm_rpc::error::{Error, *};
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use futures_util::future::Either;
use jsonrpc_core::Result;
use serde_json::json;
use snafu::ResultExt;

use solana_account_decoder::{parse_token::UiTokenAmount, UiAccount};
use solana_core::rpc::{self, OptionalContext};
use solana_evm_loader_program::{scope::*, tx_chunks::TxChunks};
use solana_sdk::{
    clock::DEFAULT_TICKS_PER_SECOND, commitment_config::CommitmentLevel,
    fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE, instruction::AccountMeta,
    pubkey::Pubkey,
};

use solana_runtime::commitment::BlockCommitmentArray;
use solana_sdk::{
    clock::{Slot, UnixTimestamp},
    commitment_config::CommitmentConfig,
    epoch_info::EpochInfo,
    epoch_schedule::EpochSchedule,
    instruction::InstructionError,
    message::Message,
    signature::Signer,
    signers::Signers,
    system_instruction,
    transaction::TransactionError,
};
use solana_transaction_status::{EncodedConfirmedTransaction, TransactionStatus, UiConfirmedBlock};

use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    rpc_client::RpcClient,
    rpc_config::*,
    rpc_request::{RpcRequest, RpcResponseErrorData},
    rpc_response::Response as RpcResponse,
    rpc_response::*,
};

use std::result::Result as StdResult;
type EvmResult<T> = StdResult<T, evm_rpc::Error>;
type FutureEvmResult<T> = EvmResult<T>;

// A compatibility layer, to make software more fluently.
mod compatibility {
    use evm_rpc::Hex;
    use evm_state::{Gas, TransactionAction, H256, U256};
    use rlp::{Decodable, DecoderError, Rlp};

    #[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct TransactionSignature {
        pub v: u64,
        pub r: U256,
        pub s: U256,
    }
    #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
    pub struct Transaction {
        pub nonce: U256,
        pub gas_price: Gas,
        pub gas_limit: Gas,
        pub action: TransactionAction,
        pub value: U256,
        pub signature: TransactionSignature,
        pub input: Vec<u8>,
    }

    impl Decodable for Transaction {
        fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
            Ok(Self {
                nonce: rlp.val_at(0)?,
                gas_price: rlp.val_at(1)?,
                gas_limit: rlp.val_at(2)?,
                action: rlp.val_at(3)?,
                value: rlp.val_at(4)?,
                input: rlp.val_at(5)?,
                signature: TransactionSignature {
                    v: rlp.val_at(6)?,
                    r: rlp.val_at(7)?,
                    s: rlp.val_at(8)?,
                },
            })
        }
    }

    impl From<Transaction> for evm_state::Transaction {
        fn from(tx: Transaction) -> evm_state::Transaction {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            tx.signature.r.to_big_endian(&mut r);
            tx.signature.s.to_big_endian(&mut s);
            evm_state::Transaction {
                nonce: tx.nonce,
                gas_limit: tx.gas_limit,
                gas_price: tx.gas_price,
                action: tx.action,
                value: tx.value,
                input: tx.input,
                signature: evm_state::TransactionSignature {
                    v: tx.signature.v,
                    r: r.into(),
                    s: s.into(),
                },
            }
        }
    }

    pub fn patch_block(block: evm_rpc::RPCBlock) -> evm_rpc::RPCBlock {
        let txs_empty = match &block.transactions {
            evm_rpc::Either::Left(txs) => txs.is_empty(),
            evm_rpc::Either::Right(txs) => txs.is_empty(),
        };
        if txs_empty && block.transactions_root.0 == H256::zero() {
            evm_rpc::RPCBlock {
                transactions_root: Hex(evm_state::empty_trie_hash()),
                receipts_root: Hex(evm_state::empty_trie_hash()),
                ..block
            }
        } else {
            block
        }
    }
}

pub struct EvmBridge {
    evm_chain_id: u64,
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    rpc_client: RpcClient,
    verbose_errors: bool,
    no_simulate: bool,
}

impl EvmBridge {
    fn new(
        evm_chain_id: u64,
        keypath: &str,
        evm_keys: Vec<SecretKey>,
        addr: String,
        verbose_errors: bool,
        no_simulate: bool,
    ) -> Self {
        info!("EVM chain id {}", evm_chain_id);

        let accounts = evm_keys
            .into_iter()
            .map(|secret_key| {
                let public_key =
                    evm_state::PublicKey::from_secret_key(&evm_state::SECP256K1, &secret_key);
                let public_key = evm_state::addr_from_public_key(&public_key);
                (public_key, secret_key)
            })
            .collect();

        info!("Trying to create rpc client with addr: {}", addr);
        let rpc_client = RpcClient::new(addr);

        info!("Loading keypair from: {}", keypath);
        Self {
            evm_chain_id,
            key: solana_sdk::signature::read_keypair_file(&keypath).unwrap(),
            accounts,
            rpc_client,
            verbose_errors,
            no_simulate,
        }
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    fn send_tx(
        &self,
        tx: evm::Transaction,
        mut meta_keys: HashSet<Pubkey>,
    ) -> FutureEvmResult<Hex<H256>> {
        let hash = tx.tx_id_hash();
        let bytes = bincode::serialize(&tx).unwrap();

        let rpc_tx = RPCTransaction::from_transaction(tx.clone())?;

        if !self.no_simulate {
            // Try simulate transaction execution
            match RpcClient::send::<Bytes>(
                &self.rpc_client,
                RpcRequest::EthCall,
                json!([rpc_tx, "latest"]),
            ) {
                Err(e) => return Err(from_client_error(e)),
                Ok(_o) => {}
            }
        }

        if bytes.len() > evm::TX_MTU {
            debug!("Sending tx = {}, by chunks", hash);
            match self.deploy_big_tx(&self.key, &tx) {
                Ok(_tx) => return Ok(Hex(hash)),
                Err(e) => {
                    error!("Error creating big tx = {}", e);
                    return Err(e);
                }
            }
        }

        debug!(
            "Printing tx_info from = {:?}, to = {:?}, nonce = {}, chain_id = {:?}",
            tx.caller(),
            tx.address(),
            tx.nonce,
            tx.signature.chain_id()
        );

        // Shortcut for swap tokens to native, will add solana account to transaction.
        if let TransactionAction::Call(addr) = tx.action {
            use solana_evm_loader_program::precompiles::*;

            if addr == *ETH_TO_VLX_ADDR {
                debug!("Found transferToNative transaction");
                match ETH_TO_VLX_CODE.parse_abi(&tx.input) {
                    Ok(pk) => {
                        info!("Adding account to meta = {}", pk);
                        meta_keys.insert(pk);
                    }
                    Err(e) => {
                        error!("Error in parsing abi = {}", e);
                    }
                }
            }
        }
        meta_keys.insert(Pubkey::from_str("BTpMi82Q9SNKUJPmZjRg2TpAoGH26nLYPn6X1YhWRi1p").unwrap());

        let mut ix =
            solana_evm_loader_program::send_raw_tx(self.key.pubkey(), tx, Some(self.key.pubkey()));

        // Add meta accounts as additional arguments
        for account in meta_keys {
            ix.accounts.push(AccountMeta::new(account, false))
        }

        let message = Message::new(&[ix], Some(&self.key.pubkey()));
        let mut send_raw_tx: solana::Transaction = solana::Transaction::new_unsigned(message);

        debug!("Getting block hash");
        let (blockhash, _fee_calculator, _) = match self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
        {
            Ok(ok) => ok.value,
            Err(e) => {
                return Err(Error::NativeRpcError {
                    details: String::from("Failed to get recent blockhash"),
                    source: e.into(),
                    verbose: self.verbose_errors,
                })
            }
        };

        send_raw_tx.sign(&vec![&self.key], blockhash);
        debug!("Sending tx = {:?}", send_raw_tx);

        self.rpc_client
            .send_transaction_with_config(
                &send_raw_tx,
                RpcSendTransactionConfig {
                    preflight_commitment: Some(CommitmentLevel::Processed),
                    skip_preflight: self.no_simulate,
                    ..Default::default()
                },
            )
            .map(|_| Hex(hash))
            .map_err(from_client_error)
    }

    fn deploy_big_tx(
        &self,
        payer: &solana_sdk::signature::Keypair,
        tx: &evm::Transaction,
    ) -> EvmResult<()> {
        let payer_pubkey = payer.pubkey();

        let storage = solana_sdk::signature::Keypair::new();
        let storage_pubkey = storage.pubkey();

        let signers = [payer, &storage];

        debug!("Create new storage {} for EVM tx {:?}", storage_pubkey, tx);

        let tx_bytes = bincode::serialize(&tx).into_native_error(self.verbose_errors)?;
        debug!(
            "Storage {} : tx bytes size = {}, chunks crc = {:#x}",
            storage_pubkey,
            tx_bytes.len(),
            TxChunks::new(tx_bytes.as_slice()).crc(),
        );

        let balance = self
            .rpc_client
            .get_minimum_balance_for_rent_exemption(tx_bytes.len())
            .into_native_error(self.verbose_errors)?;

        let (blockhash, _, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::finalized())
            .into_native_error(self.verbose_errors)?
            .value;

        let create_storage_ix = system_instruction::create_account(
            &payer_pubkey,
            &storage_pubkey,
            balance,
            tx_bytes.len() as u64,
            &solana_evm_loader_program::ID,
        );

        let allocate_storage_ix =
            solana_evm_loader_program::big_tx_allocate(&storage_pubkey, tx_bytes.len());

        let create_and_allocate_tx = solana::Transaction::new_signed_with_payer(
            &[create_storage_ix, allocate_storage_ix],
            Some(&payer_pubkey),
            &signers,
            blockhash,
        );

        debug!(
            "Create and allocate tx signatures = {:?}",
            create_and_allocate_tx.signatures
        );

        self.rpc_client
            .send_and_confirm_transaction(&create_and_allocate_tx)
            .map(|signature| {
                debug!(
                    "Create and allocate {} tx was done, signature = {:?}",
                    storage_pubkey, signature
                )
            })
            .map_err(|e| {
                error!("Error create and allocate {} tx: {:?}", storage_pubkey, e);
                e
            })
            .into_native_error(self.verbose_errors)?;

        let (blockhash, _) = self
            .rpc_client
            .get_new_blockhash(&blockhash)
            .into_native_error(self.verbose_errors)?;

        let write_data_txs: Vec<solana::Transaction> = tx_bytes
            // TODO: encapsulate
            .chunks(evm_state::TX_MTU)
            .enumerate()
            .map(|(i, chunk)| {
                solana_evm_loader_program::big_tx_write(
                    &storage_pubkey,
                    (i * evm_state::TX_MTU) as u64,
                    chunk.to_vec(),
                )
            })
            .map(|instruction| {
                solana::Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&payer_pubkey),
                    &signers,
                    blockhash,
                )
            })
            .collect();

        debug!("Write data txs: {:?}", write_data_txs);

        send_and_confirm_transactions(&self.rpc_client, write_data_txs, &signers)
            .map(|_| debug!("All write txs for storage {} was done", storage_pubkey))
            .map_err(|e| {
                error!("Error on write data to storage {}: {:?}", storage_pubkey, e);
                e
            })
            .into_native_error(self.verbose_errors)?;

        let (blockhash, _, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
            .into_native_error(self.verbose_errors)?
            .value;

        let execute_tx = solana::Transaction::new_signed_with_payer(
            &[solana_evm_loader_program::big_tx_execute(
                &storage_pubkey,
                Some(&payer_pubkey),
            )],
            Some(&payer_pubkey),
            &signers,
            blockhash,
        );

        debug!("Execute EVM transaction at storage {} ...", storage_pubkey);

        let rpc_send_cfg = RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Processed),
            ..Default::default()
        };

        self.rpc_client
            .send_transaction_with_config(&execute_tx, rpc_send_cfg)
            .map(|signature| {
                debug!(
                    "Execute EVM tx at {} was done, signature = {:?}",
                    storage_pubkey, signature
                )
            })
            .map_err(|e| {
                error!("Execute EVM tx at {} failed: {:?}", storage_pubkey, e);
                e
            })
            .map_err(from_client_error)?;

        // TODO: here we can transfer back lamports and delete storage

        Ok(())
    }
}

macro_rules! proxy_evm_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            debug!("evm proxy received {}", stringify!($rpc_call));
            match RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*])) {
                Err(e) => Err(from_client_error(e).into()),
                Ok(o) => Ok(o)
            }
        }
    )
}

pub struct BridgeErpcImpl;

impl BridgeERPC for BridgeErpcImpl {
    type Metadata = Arc<EvmBridge>;

    fn accounts(&self, meta: Self::Metadata) -> EvmResult<Vec<Hex<Address>>> {
        Ok(meta.accounts.iter().map(|(k, _)| Hex(*k)).collect())
    }

    fn sign(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _data: Bytes,
    ) -> EvmResult<Bytes> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        meta_keys: Option<Vec<String>>,
    ) -> FutureEvmResult<Hex<H256>> {
        let address = tx.from.map(|a| a.0).unwrap_or_default();

        debug!("send_transaction from = {}", address);

        let meta_keys: StdResult<HashSet<_>, _> = meta_keys
            .into_iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
            .collect();

        let secret_key = meta
            .accounts
            .get(&address)
            .ok_or(Error::KeyNotFound { account: address })?;
        let nonce = tx
            .nonce
            .map(|a| a.0)
            .or_else(|| meta.rpc_client.get_evm_transaction_count(&address).ok())
            .unwrap_or_default();
        let tx_create = evm::UnsignedTransaction {
            nonce,
            gas_price: tx.gas_price.map(|a| a.0).unwrap_or_else(|| 0.into()),
            gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
            action: tx
                .to
                .map(|a| evm::TransactionAction::Call(a.0))
                .unwrap_or(evm::TransactionAction::Create),
            value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
            input: tx.input.map(|a| a.0).unwrap_or_default(),
        };

        let tx = tx_create.sign(&secret_key, Some(meta.evm_chain_id));

        meta.send_tx(tx, meta_keys.into_native_error(meta.verbose_errors)?)
    }

    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
        meta_keys: Option<Vec<String>>,
    ) -> FutureEvmResult<Hex<H256>> {
        debug!("send_raw_transaction");
        let meta_keys: StdResult<HashSet<_>, _> = meta_keys
            .into_iter()
            .flatten()
            .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
            .collect();

        let tx: compatibility::Transaction = rlp::decode(&bytes.0).with_context(|| RlpError {
            struct_name: "RawTransaction".to_string(),
            input_data: hex::encode(&bytes.0),
        })?;
        let tx: evm::Transaction = tx.into();

        // TODO: Check chain_id.
        // TODO: check gas price.

        let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
        let hash = unsigned_tx.signing_hash(Some(meta.evm_chain_id));
        debug!("loaded tx_hash = {}", hash);
        meta.send_tx(tx, meta_keys.into_native_error(meta.verbose_errors)?)
    }

    fn gas_price(&self, _meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        const GWEI: u64 = 1_000_000_000;
        //TODO: Add gas logic
        let gas_price = 21000 * solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE
            / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE; // 21000 is smallest call in evm

        let gas_price = gas_price - gas_price % GWEI; //round to gwei for metamask
        Ok(Hex(gas_price.into()))
    }

    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct ChainMockErpcProxy;
impl ChainMockERPC for ChainMockErpcProxy {
    type Metadata = Arc<EvmBridge>;

    fn network_id(&self, meta: Self::Metadata) -> EvmResult<String> {
        // NOTE: also we can get chain id from meta, but expects the same value
        Ok(format!("{}", meta.evm_chain_id))
    }

    fn chain_id(&self, meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(meta.evm_chain_id))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> EvmResult<Hex<H256>> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    fn client_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("SolanaEvm/v0.1.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn coinbase(&self, _meta: Self::Metadata) -> EvmResult<Hex<Address>> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0x00"))
    }

    fn block_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        if block_hash == Hex(H256::zero()) {
            Ok(Some(RPCBlock::default()))
        } else {
            proxy_evm_rpc!(meta.rpc_client, EthGetBlockByHash, block_hash, full)
                .map(|o: Option<_>| o.map(compatibility::patch_block))
        }
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: String,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        if block == "0x0" {
            Ok(Some(RPCBlock::default()))
        } else {
            proxy_evm_rpc!(meta.rpc_client, EthGetBlockByNumber, block, full)
                .map(|o: Option<_>| o.map(compatibility::patch_block))
        }
    }

    fn block_transaction_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Ok(None)
    }

    fn block_transaction_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct BasicErpcProxy;
impl BasicERPC for BasicErpcProxy {
    type Metadata = Arc<EvmBridge>;

    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        proxy_evm_rpc!(meta.rpc_client, EthBlockNumber)
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Hex<U256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetBalance, address, block)
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        block: Option<String>,
    ) -> EvmResult<Hex<H256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetStorageAt, address, data, block)
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Hex<U256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionCount, address, block)
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthGetCode, address, block)
    }

    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionByHash, tx_hash)
    }

    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCReceipt>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionReceipt, tx_hash)
    }

    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthCall, tx, block, meta_keys)
    }

    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
        meta_keys: Option<Vec<String>>,
    ) -> EvmResult<Hex<Gas>> {
        proxy_evm_rpc!(meta.rpc_client, EthEstimateGas, tx, block, meta_keys)
    }

    fn logs(&self, meta: Self::Metadata, log_filter: RPCLogFilter) -> EvmResult<Vec<RPCLog>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetLogs, log_filter)
    }
}

fn from_client_error(client_error: ClientError) -> evm_rpc::Error {
    let client_error_kind = client_error.kind();
    match client_error_kind {
        ClientErrorKind::RpcError(solana_client::rpc_request::RpcError::RpcResponseError {
            code,
            message,
            data,
            original_err,
        }) => {
            match data {
                // if transaction preflight, try to get last log message, and return it as error.
                RpcResponseErrorData::SendTransactionPreflightFailure(
                    RpcSimulateTransactionResult {
                        err:
                            Some(TransactionError::InstructionError(
                                _,
                                InstructionError::InvalidArgument,
                            )),
                        logs: Some(logs),
                        ..
                    },
                ) if !logs.is_empty() => {
                    let last_log = logs.last().unwrap();
                    return evm_rpc::Error::ProxyRpcError {
                        source: jsonrpc_core::Error {
                            code: (*code).into(),
                            message: last_log.clone(),
                            data: original_err.clone().into(),
                        },
                    };
                }
                _ => {}
            }
            evm_rpc::Error::ProxyRpcError {
                source: jsonrpc_core::Error {
                    code: (*code).into(),
                    message: message.clone(),
                    data: original_err.clone().into(),
                },
            }
        }
        _ => evm_rpc::Error::NativeRpcError {
            details: format!("{:?}", client_error),
            source: client_error.into(),
            verbose: false, // don't verbose native errors.
        },
    }
}

macro_rules! proxy_sol_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
            debug!("proxy received {}", stringify!($rpc_call));

            #[allow(deprecated)]
            // some methods can be deprecated, but because we are proxy, we should support them.
            match RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*])) {
                Err(e) => Err(from_client_error(e).into()),
                Ok(o) => Ok(o)
            }
        }
    )
}

pub struct RpcSolProxy;

impl rpc::rpc_minimal::Minimal for RpcSolProxy {
    type Metadata = Arc<EvmBridge>;

    fn get_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcGetBalanceConfig>,
    ) -> Result<RpcResponse<UiLamports>> {
        proxy_sol_rpc!(meta.rpc_client, GetBalance, pubkey_str, config)
    }

    fn get_epoch_info(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<EpochInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochInfo, commitment)
    }

    fn get_health(&self, meta: Self::Metadata) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetHealth)
    }

    fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity> {
        proxy_sol_rpc!(meta.rpc_client, GetMinimumBalanceForRentExemption)
    }

    fn get_slot(&self, meta: Self::Metadata, commitment: Option<CommitmentConfig>) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetSlot, commitment)
    }

    fn get_block_height(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockHeight, commitment)
    }

    fn get_snapshot_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetSnapshotSlot)
    }
    fn get_transaction_count(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTransactionCount, commitment)
    }

    fn get_version(&self, meta: Self::Metadata) -> Result<RpcVersionInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetVersion)
    }

    fn get_vote_accounts(
        &self,
        meta: Self::Metadata,
        commitment: Option<RpcGetVoteAccountsConfig>,
    ) -> Result<RpcVoteAccountStatus> {
        proxy_sol_rpc!(meta.rpc_client, GetVoteAccounts, commitment)
    }

    fn get_leader_schedule(
        &self,
        meta: Self::Metadata,
        options: Option<RpcLeaderScheduleConfigWrapper>,
        config: Option<RpcLeaderScheduleConfig>,
    ) -> Result<Option<RpcLeaderSchedule>> {
        proxy_sol_rpc!(meta.rpc_client, GetLeaderSchedule, options, config)
    }
}

impl rpc::rpc_full::Full for RpcSolProxy {
    type Metadata = Arc<EvmBridge>;

    fn get_account_info(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Option<UiAccount>>> {
        proxy_sol_rpc!(meta.rpc_client, GetAccountInfo, pubkey_str, config)
    }

    fn get_multiple_accounts(
        &self,
        meta: Self::Metadata,
        pubkey_strs: Vec<String>,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<Option<UiAccount>>>> {
        proxy_sol_rpc!(meta.rpc_client, GetMultipleAccounts, pubkey_strs, config)
    }

    fn get_minimum_balance_for_rent_exemption(
        &self,
        meta: Self::Metadata,
        data_len: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            data_len,
            commitment
        )
    }

    fn get_program_accounts(
        &self,
        meta: Self::Metadata,
        program_id_str: String,
        config: Option<RpcProgramAccountsConfig>,
    ) -> Result<OptionalContext<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(meta.rpc_client, GetProgramAccounts, program_id_str, config)
    }

    fn get_inflation_governor(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcInflationGovernor> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationGovernor, commitment)
    }

    fn get_inflation_rate(&self, meta: Self::Metadata) -> Result<RpcInflationRate> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationRate)
    }

    fn get_epoch_schedule(&self, meta: Self::Metadata) -> Result<EpochSchedule> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochSchedule)
    }

    fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>> {
        proxy_sol_rpc!(meta.rpc_client, GetClusterNodes)
    }

    fn get_block_commitment(
        &self,
        meta: Self::Metadata,
        block: Slot,
    ) -> Result<RpcBlockCommitment<BlockCommitmentArray>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockCommitment, block)
    }

    fn get_genesis_hash(&self, meta: Self::Metadata) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetGenesisHash)
    }

    fn get_recent_blockhash(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>> {
        proxy_sol_rpc!(meta.rpc_client, GetRecentBlockhash, commitment)
    }

    fn get_fees(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcFees>> {
        proxy_sol_rpc!(meta.rpc_client, GetFees, commitment)
    }

    fn get_fee_calculator_for_blockhash(
        &self,
        meta: Self::Metadata,
        blockhash: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Option<RpcFeeCalculator>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetFeeCalculatorForBlockhash,
            blockhash,
            commitment
        )
    }

    fn get_fee_rate_governor(
        &self,
        meta: Self::Metadata,
    ) -> Result<RpcResponse<RpcFeeRateGovernor>> {
        proxy_sol_rpc!(meta.rpc_client, GetFeeRateGovernor)
    }

    fn get_signature_statuses(
        &self,
        meta: Self::Metadata,
        signature_strs: Vec<String>,
        config: Option<RpcSignatureStatusConfig>,
    ) -> Result<RpcResponse<Vec<Option<TransactionStatus>>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureStatuses,
            signature_strs,
            config
        )
    }

    fn get_total_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTotalSupply, commitment)
    }

    fn get_largest_accounts(
        &self,
        meta: Self::Metadata,
        config: Option<RpcLargestAccountsConfig>,
    ) -> Result<RpcResponse<Vec<RpcAccountBalance>>> {
        proxy_sol_rpc!(meta.rpc_client, GetLargestAccounts, config)
    }

    fn get_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcSupply>> {
        proxy_sol_rpc!(meta.rpc_client, GetSupply, commitment)
    }

    fn request_airdrop(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        lamports: u64,
        config: Option<RpcRequestAirdropConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(
            meta.rpc_client,
            RequestAirdrop,
            pubkey_str,
            lamports,
            config
        )
    }

    fn get_inflation_reward(
        &self,
        meta: Self::Metadata,
        address_strs: Vec<String>,
        config: Option<RpcEpochConfig>,
    ) -> Result<Vec<Option<RpcInflationReward>>> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationReward, address_strs, config)
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSendTransactionConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, SendTransaction, data, config)
    }

    fn simulate_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSimulateTransactionConfig>,
    ) -> Result<RpcResponse<RpcSimulateTransactionResult>> {
        proxy_sol_rpc!(meta.rpc_client, SimulateTransaction, data, config)
    }

    fn get_slot_leader(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetSlotLeader, commitment)
    }

    fn minimum_ledger_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, MinimumLedgerSlot)
    }

    fn get_confirmed_block(
        &self,
        meta: Self::Metadata,
        slot: Slot,
        config: Option<RpcEncodingConfigWrapper<RpcConfirmedBlockConfig>>,
    ) -> Result<Option<UiConfirmedBlock>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlock, slot, config)
    }

    fn get_confirmed_blocks(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        config: Option<RpcConfirmedBlocksConfigWrapper>,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocks,
            start_slot,
            config,
            commitment
        )
    }

    fn get_block_time(&self, meta: Self::Metadata, slot: Slot) -> Result<Option<UnixTimestamp>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockTime, slot)
    }

    fn get_confirmed_transaction(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        config: Option<RpcEncodingConfigWrapper<RpcConfirmedTransactionConfig>>,
    ) -> Result<Option<EncodedConfirmedTransaction>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedTransaction,
            signature_str,
            config
        )
    }

    fn get_confirmed_signatures_for_address(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<String>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress,
            pubkey_str,
            start_slot,
            end_slot
        )
    }

    fn get_confirmed_signatures_for_address2(
        &self,
        meta: Self::Metadata,
        address: String,
        config: Option<RpcGetConfirmedSignaturesForAddress2Config>,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress2,
            address,
            config
        )
    }

    fn get_first_available_block(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetFirstAvailableBlock)
    }

    fn get_stake_activation(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcEpochConfig>,
    ) -> Result<RpcStakeActivation> {
        proxy_sol_rpc!(meta.rpc_client, GetStakeActivation, pubkey_str, config)
    }

    fn get_block_production(
        &self,
        meta: Self::Metadata,
        config: Option<RpcBlockProductionConfig>,
    ) -> Result<RpcResponse<RpcBlockProduction>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockProduction, config)
    }

    fn get_token_account_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountBalance,
            pubkey_str,
            commitment
        )
    }

    fn get_token_supply(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        proxy_sol_rpc!(meta.rpc_client, GetTokenSupply, mint_str, commitment)
    }

    fn get_token_largest_accounts(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Vec<RpcTokenAccountBalance>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenLargestAccounts,
            mint_str,
            commitment
        )
    }

    fn get_token_accounts_by_owner(
        &self,
        meta: Self::Metadata,
        owner_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByOwner,
            owner_str,
            token_account_filter,
            config
        )
    }

    fn get_token_accounts_by_delegate(
        &self,
        meta: Self::Metadata,
        delegate_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByDelegate,
            delegate_str,
            token_account_filter,
            config
        )
    }

    fn get_velas_accounts_by_operational_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<RpcResponse<Vec<String>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetVelasAccountsByOperationalKey,
            pubkey_str
        )
    }

    fn get_velas_accounts_by_owner_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<RpcResponse<Vec<String>>> {
        proxy_sol_rpc!(meta.rpc_client, GetVelasAccountsByOwnerKey, pubkey_str)
    }

    fn get_velas_relying_parties_by_owner_key(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
    ) -> Result<RpcResponse<Vec<String>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetVelasRelyingPartiesByOwnerKey,
            pubkey_str
        )
    }

    fn get_recent_performance_samples(
        &self,
        meta: Self::Metadata,
        limit: Option<usize>,
    ) -> Result<Vec<RpcPerfSample>> {
        proxy_sol_rpc!(meta.rpc_client, GetRecentPerfomanceSamples, limit)
    }

    fn get_confirmed_blocks_with_limit(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        limit: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocksWithLimit,
            start_slot,
            limit,
            commitment
        )
    }

    fn get_slot_leaders(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<String>> {
        proxy_sol_rpc!(meta.rpc_client, GetSlotLeaders, start_slot, end_slot)
    }

    fn get_max_retransmit_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetMaxRetransmitSlot)
    }

    fn get_max_shred_insert_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetMaxShredInsertSlot)
    }
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
    #[structopt(default_value = "57005")] // 0xdead
    evm_chain_id: u64,
    #[structopt(long = "verbose-errors")]
    verbose_errors: bool,
    #[structopt(long = "no-simulate")]
    no_simulate: bool,
}

use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use jsonrpc_core::middleware::Middleware;
use jsonrpc_core::middleware::{NoopCallFuture, NoopFuture};

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[derive(Clone)]
struct LoggingMiddleware;
impl<M: jsonrpc_core::Metadata> Middleware<M> for LoggingMiddleware {
    type Future = NoopFuture;
    type CallFuture = NoopCallFuture;
    fn on_call<F, X>(&self, call: Call, meta: M, next: F) -> Either<Self::CallFuture, X>
    where
        F: Fn(Call, M) -> X + Send + Sync,
        X: Future<Output = Option<Output>> + Send + 'static,
    {
        debug!(target: "jsonrpc_core", "On Request = {:?}", call);
        Either::Right(next(call, meta))
    }
}

#[paw::main]
fn main(args: Args) -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    let meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
        args.verbose_errors,
        args.no_simulate,
    );
    let meta = Arc::new(meta);
    let mut io = MetaIoHandler::with_middleware(LoggingMiddleware);

    {
        use rpc::rpc_full::Full;
        let sol_rpc = RpcSolProxy;
        io.extend_with(sol_rpc.to_delegate());
    }
    let ether_bridge = BridgeErpcImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_basic = BasicErpcProxy;
    io.extend_with(ether_basic.to_delegate());
    let ether_mock = ChainMockErpcProxy;
    io.extend_with(ether_mock.to_delegate());

    info!("Creating server with: {}", binding_address);
    let meta_clone = meta.clone();
    let server = ServerBuilder::with_meta_extractor(
        io.clone(),
        move |_req: &hyper::Request<hyper::Body>| meta_clone.clone(),
    )
    .cors(DomainsValidation::AllowOnly(vec![
        AccessControlAllowOrigin::Any,
    ]))
    .threads(4)
    .cors_max_age(86400)
    .start_http(&binding_address)
    .expect("Unable to start EVM bridge server");

    let ws_server = {
        let mut websocket_binding = binding_address;
        websocket_binding.set_port(binding_address.port() + 1);
        info!("Creating websocket server: {}", websocket_binding);
        jsonrpc_ws_server::ServerBuilder::with_meta_extractor(io, move |_: &_| meta.clone())
            .start(&websocket_binding)
            .expect("Unable to start EVM bridge server")
    };
    ws_server.wait().unwrap();
    server.wait();
    Ok(())
}

fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &RpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), anyhow::Error> {
    const SEND_RETRIES: usize = 5;
    const STATUS_RETRIES: usize = 15;

    for _ in 0..SEND_RETRIES {
        // Send all transactions
        let mut transactions_signatures = transactions
            .drain(..)
            .map(|transaction| {
                if cfg!(not(test)) {
                    // Delay ~1 tick between write transactions in an attempt to reduce AccountInUse errors
                    // when all the write transactions modify the same program account (eg, deploying a
                    // new program)
                    sleep(Duration::from_millis(1000 / DEFAULT_TICKS_PER_SECOND));
                }

                debug!("Sending {:?}", transaction.signatures);

                let signature = rpc_client
                    .send_transaction_with_config(
                        &transaction,
                        RpcSendTransactionConfig {
                            skip_preflight: true, // NOTE: was true
                            ..RpcSendTransactionConfig::default()
                        },
                    )
                    .map_err(|e| error!("Send transaction error: {:?}", e))
                    .ok();

                (transaction, signature)
            })
            .collect::<Vec<_>>();

        for _ in 0..STATUS_RETRIES {
            // Collect statuses for all the transactions, drop those that are confirmed

            if cfg!(not(test)) {
                // Retry twice a second
                sleep(Duration::from_millis(500));
            }

            transactions_signatures.retain(|(_transaction, signature)| {
                let tx_status = signature
                    .and_then(|signature| rpc_client.get_signature_statuses(&[signature]).ok())
                    .and_then(|RpcResponse { mut value, .. }| value.remove(0));

                // Remove confirmed
                if let Some(TransactionStatus {
                    confirmations: Some(confirmations),
                    ..
                }) = tx_status
                {
                    confirmations == 0 // retain unconfirmed
                } else {
                    true
                }
            });

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let (blockhash, _) = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash)?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            debug!("Resending {:?}", transaction);
            transactions.push(transaction);
        }
    }
    Err(anyhow::Error::msg("Transactions failed"))
}
