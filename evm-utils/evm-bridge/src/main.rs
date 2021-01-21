use log::*;

use solana_sdk::{clock::DEFAULT_TICKS_PER_SECOND, commitment_config::CommitmentLevel};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};

use evm_rpc::basic::BasicERPC;
use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain_mock::ChainMockERPC;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_core::Result;
use serde_json::json;

use solana_account_decoder::{parse_token::UiTokenAmount, UiAccount};
use solana_evm_loader_program::scope::*;

use solana_runtime::commitment::BlockCommitmentArray;
use solana_sdk::{
    clock::{Slot, UnixTimestamp},
    commitment_config::CommitmentConfig,
    epoch_info::EpochInfo,
    epoch_schedule::EpochSchedule,
    message::Message,
    signature::{Signature, Signer},
    signers::Signers,
    transaction,
};
use solana_transaction_status::{
    EncodedConfirmedBlock, EncodedConfirmedTransaction, TransactionStatus, UiTransactionEncoding,
};

use solana_client::{
    client_error::Result as ClientResult, rpc_client::RpcClient, rpc_config::*,
    rpc_request::RpcRequest, rpc_response::Response as RpcResponse, rpc_response::*,
};

use solana_core::rpc::RpcSol;

use std::result::Result as StdResult;
type EvmResult<T> = StdResult<T, evm_rpc::Error>;
type FutureEvmResult<T> = EvmResult<T>;

const CHAIN_ID: u64 = 0x77;

pub struct EvmBridge {
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    rpc_client: RpcClient,
}

impl EvmBridge {
    fn new(keypath: &str, evm_keys: Vec<SecretKey>, addr: String) -> Self {
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
            key: solana_sdk::signature::read_keypair_file(&keypath).unwrap(),
            accounts,
            rpc_client,
        }
    }

    fn send_tx(&self, tx: evm::Transaction) -> FutureEvmResult<Hex<H256>> {
        let hash = tx.signing_hash();
        let bytes = bincode::serialize(&tx).unwrap();

        if bytes.len() > evm::TX_MTU as usize {
            debug!("Sending tx = {}, by chunks", hash);
            match deploy_big_tx(&self.key, &self.rpc_client, &tx) {
                Ok(_tx) => return Ok(Hex(hash)),
                Err(e) => {
                    error!("Error creating big tx = {}", e);
                    return Err(evm_rpc::Error::InvalidParams);
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

        let ix = solana_evm_loader_program::send_raw_tx(self.key.pubkey(), tx);

        let message = Message::new(&[ix], Some(&self.key.pubkey()));
        let mut send_raw_tx: solana::Transaction = solana::Transaction::new_unsigned(message);

        debug!("Getting block hash");
        let (blockhash, _fee_calculator, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::default())
            .unwrap()
            .value;

        send_raw_tx.sign(&vec![&self.key], blockhash);
        debug!("Sending tx = {:?}", send_raw_tx);

        self.rpc_client
            .send_transaction_with_config(&send_raw_tx, RpcSendTransactionConfig::default())
            .map(|_| Hex(hash))
            .map_err(|err| {
                error!("Err = {}", err);
                evm_rpc::Error::InvalidParams
            })
    }
}

macro_rules! proxy_evm_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
        debug!("evm proxy received {}", stringify!($rpc_call));
        RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*]))
            .map_err(|e| {
                error!("Json rpc error = {:?}", e);
                evm_rpc::Error::InvalidParams
            })
        }
    )
}

pub struct BridgeERPCImpl;

impl BridgeERPC for BridgeERPCImpl {
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
        Err(evm_rpc::Error::NotFound)
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
    ) -> FutureEvmResult<Hex<H256>> {
        let address = tx.from.map(|a| a.0).unwrap_or_default();

        debug!("send_transaction from = {}", address);

        let secret_key = meta.accounts.get(&address).unwrap();
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
            input: tx.data.map(|a| a.0).unwrap_or_default(),
        };

        let tx = tx_create.sign(&secret_key, CHAIN_ID.into());

        meta.send_tx(tx)
    }

    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
    ) -> FutureEvmResult<Hex<H256>> {
        debug!("send_raw_transaction");

        let tx: evm::Transaction = rlp::decode(&bytes.0).unwrap();
        let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
        let hash = unsigned_tx.signing_hash(CHAIN_ID.into());
        debug!("loaded tx_hash = {}", hash);
        meta.send_tx(tx)
    }

    fn gas_price(&self, _meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        //TODO: Add gas logic
        Ok(Hex(1.into()))
    }

    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Err(evm_rpc::Error::NotFound)
    }
}

pub struct ChainMockERPCProxy;
impl ChainMockERPC for ChainMockERPCProxy {
    type Metadata = Arc<EvmBridge>;

    fn network_id(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(format!("{}", CHAIN_ID))
    }

    fn chain_id(&self, _meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(CHAIN_ID))
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
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(Some(RPCBlock {
            number: U256::zero().into(),
            hash: H256::zero().into(),
            parent_hash: H256::zero().into(),
            size: 0.into(),
            gas_limit: Gas::zero().into(),
            gas_used: Gas::zero().into(),
            timestamp: 0.into(),
            transactions: Either::Left(vec![]),
            nonce: 0.into(),
            sha3_uncles: H256::zero().into(),
            logs_bloom: H256::zero().into(), // H2048
            transactions_root: H256::zero().into(),
            state_root: H256::zero().into(),
            receipts_root: H256::zero().into(),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: vec![].into(),
            uncles: vec![],
        }))
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: String,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetBlockByNumber, block, full)
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
        Err(evm_rpc::Error::NotFound)
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::NotFound)
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::NotFound)
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::NotFound)
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::NotFound)
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::NotFound)
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::NotFound)
    }
}

pub struct BasicERPCProxy;
impl BasicERPC for BasicERPCProxy {
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
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthCall, tx, block)
    }

    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
    ) -> EvmResult<Hex<Gas>> {
        proxy_evm_rpc!(meta.rpc_client, EthEstimateGas, tx, block)
    }

    fn logs(&self, meta: Self::Metadata, log_filter: RPCLogFilter) -> EvmResult<Vec<RPCLog>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetLogs, log_filter)
    }
}

macro_rules! proxy_sol_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
        debug!("proxy received {}", stringify!($rpc_call));
        RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*]))
            .map_err(|e| {
                error!("Json rpc error = {:?}", e);
                jsonrpc_core::Error::internal_error()
            })
        }
    )
}

pub struct RpcSolProxy;
impl RpcSol for RpcSolProxy {
    type Metadata = Arc<EvmBridge>;

    fn confirm_transaction(
        &self,
        meta: Self::Metadata,
        id: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<bool>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedTransaction, id, commitment)
    }

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
    ) -> Result<Vec<RpcKeyedAccount>> {
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

    fn get_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<u64>> {
        proxy_sol_rpc!(meta.rpc_client, GetBalance, pubkey_str, commitment)
    }

    fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>> {
        proxy_sol_rpc!(meta.rpc_client, GetClusterNodes)
    }

    fn get_epoch_info(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<EpochInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochInfo, commitment)
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

    fn get_leader_schedule(
        &self,
        meta: Self::Metadata,
        slot: Option<Slot>,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<RpcLeaderSchedule>> {
        proxy_sol_rpc!(meta.rpc_client, GetLeaderSchedule, slot, commitment)
    }

    fn get_recent_blockhash(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            commitment
        )
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

    fn get_signature_confirmation(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<RpcSignatureConfirmation>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureConfirmation,
            signature_str,
            commitment
        )
    }

    fn get_signature_status(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<transaction::Result<()>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureStatus,
            signature_str,
            commitment
        )
    }

    fn get_signature_statuses(
        &self,
        meta: Self::Metadata,
        signature_strs: Vec<String>,
        config: Option<RpcSignatureStatusConfig>,
    ) -> Result<RpcResponse<Vec<Option<TransactionStatus>>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            signature_strs,
            config
        )
    }

    fn get_slot(&self, meta: Self::Metadata, commitment: Option<CommitmentConfig>) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetSlot, commitment)
    }

    fn get_transaction_count(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTransactionCount, commitment)
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
        commitment: Option<CommitmentConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(
            meta.rpc_client,
            RequestAirdrop,
            pubkey_str,
            lamports,
            commitment
        )
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

    fn get_vote_accounts(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcVoteAccountStatus> {
        proxy_sol_rpc!(meta.rpc_client, GetVoteAccounts, commitment)
    }

    fn validator_exit(&self, meta: Self::Metadata) -> Result<bool> {
        proxy_sol_rpc!(meta.rpc_client, ValidatorExit)
    }

    fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity> {
        proxy_sol_rpc!(meta.rpc_client, GetMinimumBalanceForRentExemption)
    }

    fn get_version(&self, meta: Self::Metadata) -> Result<RpcVersionInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetVersion)
    }

    fn set_log_filter(&self, meta: Self::Metadata, filter: String) -> Result<()> {
        proxy_sol_rpc!(meta.rpc_client, SetLogFilter, filter)
    }

    fn get_confirmed_block(
        &self,
        meta: Self::Metadata,
        slot: Slot,
        encoding: Option<UiTransactionEncoding>,
    ) -> Result<Option<EncodedConfirmedBlock>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlock, slot, encoding)
    }

    fn get_confirmed_blocks(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        end_slot: Option<Slot>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlocks, start_slot, end_slot)
    }

    fn get_block_time(&self, meta: Self::Metadata, slot: Slot) -> Result<Option<UnixTimestamp>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockTime, slot)
    }

    fn get_confirmed_transaction(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        encoding: Option<UiTransactionEncoding>,
    ) -> Result<Option<EncodedConfirmedTransaction>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedTransaction,
            signature_str,
            encoding
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
        config: Option<RpcStakeConfig>,
    ) -> Result<RpcStakeActivation> {
        proxy_sol_rpc!(meta.rpc_client, GetStakeActivation, pubkey_str, config)
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
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocksWithLimit,
            start_slot,
            limit
        )
    }
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
}

use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use jsonrpc_core::middleware::Middleware;
use jsonrpc_core::middleware::{NoopCallFuture, NoopFuture};

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

struct LoggingMiddleware;
impl<M: jsonrpc_core::Metadata> Middleware<M> for LoggingMiddleware {
    type Future = NoopFuture;
    type CallFuture = NoopCallFuture;
    fn on_call<F, X>(
        &self,
        call: Call,
        meta: M,
        next: F,
    ) -> futures::future::Either<Self::CallFuture, X>
    where
        F: Fn(Call, M) -> X + Send + Sync,
        X: futures::Future<Item = Option<Output>> + Send + 'static,
    {
        debug!("On Request = {:?}", call);
        futures::future::Either::B(next(call, meta))
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
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
    );
    let meta = Arc::new(meta);
    let mut io = MetaIoHandler::with_middleware(LoggingMiddleware);

    let sol_rpc = RpcSolProxy;
    io.extend_with(sol_rpc.to_delegate());
    let ether_bridge = BridgeERPCImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_basic = BasicERPCProxy;
    io.extend_with(ether_basic.to_delegate());
    let ether_mock = ChainMockERPCProxy;
    io.extend_with(ether_mock.to_delegate());

    info!("Creating server with: {}", binding_address);
    let server =
        ServerBuilder::with_meta_extractor(io, move |_req: &hyper::Request<hyper::Body>| {
            meta.clone()
        })
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Any,
        ]))
        .threads(4)
        .cors_max_age(86400)
        .start_http(&binding_address)
        .expect("Unable to start EVM bridge server");

    server.wait();
    Ok(())
}

pub fn log_instruction_custom_error(
    result: ClientResult<Signature>,
) -> StdResult<Signature, Box<dyn std::error::Error>> {
    match result {
        Err(err) => {
            format!("Error processing transaction = {}", err);
            return Err("Error processing transaction".into());
        }
        Ok(sig) => Ok(sig),
    }
}

fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &RpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), Box<dyn std::error::Error>> {
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

                let signature = rpc_client
                    .send_transaction_with_config(
                        &transaction,
                        RpcSendTransactionConfig {
                            skip_preflight: true,
                            ..RpcSendTransactionConfig::default()
                        },
                    )
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
                signature
                    .and_then(|signature| rpc_client.get_signature_statuses(&[signature]).ok())
                    .map(|RpcResponse { context: _, value }| match &value[0] {
                        Some(transaction_status)
                            if matches!(transaction_status.confirmations, Some(0)) =>
                        {
                            false
                        }
                        None => false,
                        _ => true,
                    })
                    .unwrap_or(false)
            });

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let (blockhash, _fee_calculator) = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash)?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            transactions.push(transaction);
        }
    }
    Err("Transactions failed".into())
}

fn deploy_big_tx(
    keypair: &solana_sdk::signature::Keypair,
    rpc_client: &RpcClient,
    tx: &evm::Transaction,
) -> StdResult<(), Box<dyn std::error::Error>> {
    let pubkey = keypair.pubkey();

    let tx_bytes = bincode::serialize(&tx)?;

    let seed = H256::random();
    let (blockhash, _fee_calculator, _) = rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::max())?
        .value;

    let ix = solana_evm_loader_program::big_tx_allocate(&pubkey, seed, tx_bytes.len() as u64);
    let message = Message::new(&[ix], Some(&pubkey));

    let signers = [keypair];
    let create_account_tx = solana::Transaction::new(&signers, message, blockhash);

    error!(
        "transaction signature = {}",
        create_account_tx.signatures[0]
    );
    let mut write_messages = vec![];
    for (chunk, i) in tx_bytes.chunks(evm_state::TX_MTU as usize).zip(0..) {
        let instruction = solana_evm_loader_program::big_tx_write(
            &pubkey,
            seed,
            (i * evm_state::TX_MTU) as u64,
            chunk.to_vec(),
        );
        let message = Message::new(&[instruction], Some(&pubkey));
        write_messages.push(message);
    }

    let instruction = solana_evm_loader_program::big_tx_execute(&pubkey, seed);
    let finalize_message = Message::new(&[instruction], Some(&signers[0].pubkey()));

    trace!("Creating program account");
    let result = rpc_client.send_and_confirm_transaction(&create_account_tx);
    log_instruction_custom_error(result)?;

    let (blockhash, _fee_calculator) = rpc_client.get_new_blockhash(&blockhash)?;

    let mut write_transactions = vec![];
    for message in write_messages.into_iter() {
        let mut tx = solana::Transaction::new_unsigned(message);
        tx.try_sign(&signers, blockhash)?;
        write_transactions.push(tx);
    }

    trace!("Writing transaction data");
    let result = send_and_confirm_transactions(&rpc_client, write_transactions, &signers);
    if let Err(e) = result {
        format!("Error sending write data = {}", e);
        return Err("Error sending write data".into());
    }
    let (blockhash, _fee_calculator, _) = rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::recent())?
        .value;

    let mut finalize_tx = solana::Transaction::new_unsigned(finalize_message);
    finalize_tx.try_sign(&signers, blockhash)?;

    trace!("Finalizing program account");
    let result = rpc_client.send_transaction_with_config(
        &finalize_tx,
        RpcSendTransactionConfig {
            skip_preflight: false,
            preflight_commitment: Some(CommitmentLevel::Recent),
            ..Default::default()
        },
    );

    log_instruction_custom_error(result)?;

    Ok(())
}
