use crate::pool::{
    worker_cleaner, worker_deploy, worker_signature_checker, EthPool, PooledTransaction,
    SystemClock,
};
use crate::bundler::Bundler;
use crate::rpc_client::AsyncRpcClient;
use crate::tx_filter::TxFilter;

use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    future::ready,
    result::Result as StdResult,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use borsh::BorshDeserialize;
use derivative::*;
use evm_rpc::error::{Error, *};
use evm_rpc::*;
use evm_rpc::bundler::UserOperation;
use evm_state::*;
use jsonrpc_http_server::jsonrpc_core::*;
use log::*;
use rlp::Encodable;
use secp256k1::Message;
use sha3::{Digest, Keccak256};
use snafu::ResultExt;
use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    rpc_request::RpcResponseErrorData,
    rpc_response::*,
};
use solana_evm_loader_program::instructions::FeePayerType;
use solana_evm_loader_program::scope::*;
use solana_rpc::rpc::{BatchId, BatchStateMap};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    system_instruction,
    transaction::TransactionError,
};
use tracing_attributes::instrument;

use ::tokio::sync::mpsc;
use solana_sdk::signature::Keypair;

pub type EvmResult<T> = StdResult<T, evm_rpc::Error>;

const MAX_NUM_BLOCKS_IN_BATCH: u64 = 2000; // should be less or equal to const core::evm_rpc_impl::logs::MAX_NUM_BLOCKS

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
        fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
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

    pub fn patch_tx(mut tx: evm_rpc::RPCTransaction) -> evm_rpc::RPCTransaction {
        if tx.r.unwrap_or_default() == Hex(U256::zero()) {
            tx.r = Some(Hex(0x1.into()))
        }
        if tx.s.unwrap_or_default() == Hex(U256::zero()) {
            tx.s = Some(Hex(0x1.into()))
        }
        tx
    }

    pub fn patch_block(mut block: evm_rpc::RPCBlock) -> evm_rpc::RPCBlock {
        let txs_empty = match &block.transactions {
            evm_rpc::Either::Left(txs) => txs.is_empty(),
            evm_rpc::Either::Right(txs) => txs.is_empty(),
        };
        // if no tx, and its root == zero, return empty trie hash, to avoid panics in go client.
        if txs_empty && block.transactions_root.0 == H256::zero() {
            evm_rpc::RPCBlock {
                transactions_root: Hex(evm_state::empty_trie_hash()),
                receipts_root: Hex(evm_state::empty_trie_hash()),
                ..block
            }
        } else {
            // if txs exist, check that their signatures are not zero, and fix them if so.
            block.transactions = match block.transactions {
                evm_rpc::Either::Left(txs) => evm_rpc::Either::Left(txs),
                evm_rpc::Either::Right(txs) => {
                    evm_rpc::Either::Right(txs.into_iter().map(patch_tx).collect())
                }
            };
            block
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct EvmBridge {
    evm_chain_id: u64,
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    #[derivative(Debug = "ignore")]
    rpc_client: AsyncRpcClient,
    verbose_errors: bool,
    borsh_encoding: bool,
    simulate: bool,
    max_logs_blocks: u64,
    pool: EthPool<SystemClock>,
    min_gas_price: U256,
    whitelist: Vec<TxFilter>,
    pub batch_state_map: BatchStateMap,
    max_batch_duration: Option<Duration>,
    bundler: Bundler,
}

impl EvmBridge {
    pub fn new(
        evm_chain_id: u64,
        keypath: &str,
        evm_keys: Vec<SecretKey>,
        addr: String,
        verbose_errors: bool,
        borsh_encoding: bool,
        simulate: bool,
        max_logs_blocks: u64,
        min_gas_price: U256,
    ) -> Self {
        info!("EVM chain id {}", evm_chain_id);

        let accounts = evm_keys
            .into_iter()
            .map(|secret_key| {
                let public_key =
                    evm_state::PublicKey::from_secret_key(evm_state::SECP256K1, &secret_key);
                let public_key = evm_state::addr_from_public_key(&public_key);
                (public_key, secret_key)
            })
            .collect();

        info!("Trying to create rpc client with addr: {}", addr);
        let rpc_client = AsyncRpcClient::new(addr);

        info!("Loading keypair from: {}", keypath);
        let key = solana_sdk::signature::read_keypair_file(keypath).unwrap();

        info!("Creating mempool...");
        let pool = EthPool::new(SystemClock);

        Self {
            evm_chain_id,
            key,
            accounts,
            rpc_client,
            verbose_errors,
            borsh_encoding,
            simulate,
            max_logs_blocks,
            pool,
            min_gas_price,
            whitelist: vec![],
            batch_state_map: Default::default(),
            max_batch_duration: None,
            bundler: Bundler {},
        }
    }

    pub fn new_for_test(evm_chain_id: u64, evm_keys: Vec<SecretKey>, addr: String) -> Self {
        let accounts = evm_keys
            .into_iter()
            .map(|secret_key| {
                let public_key =
                    evm_state::PublicKey::from_secret_key(evm_state::SECP256K1, &secret_key);
                let public_key = evm_state::addr_from_public_key(&public_key);
                (public_key, secret_key)
            })
            .collect();
        Self {
            evm_chain_id,
            key: Keypair::new(),
            accounts,
            rpc_client: AsyncRpcClient::new(addr),
            verbose_errors: true,
            borsh_encoding: false,
            simulate: false,
            max_logs_blocks: 0u64,
            pool: EthPool::new(SystemClock),
            min_gas_price: 0.into(),
            whitelist: vec![],
            batch_state_map: Default::default(),
            max_batch_duration: None,
            bundler: Bundler {},
        }
    }

    pub fn get_accounts(&self) -> &HashMap<evm_state::Address, evm_state::SecretKey> {
        &self.accounts
    }

    pub fn get_bundler(&self) -> &Bundler {
        &self.bundler
    }

    pub fn get_evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }

    pub fn get_key(&self) -> &solana_sdk::signature::Keypair {
        &self.key
    }

    pub fn get_min_gas_price(&self) -> U256 {
        self.min_gas_price
    }

    pub fn get_pool(&self) -> &EthPool<SystemClock> {
        &self.pool
    }

    pub fn get_rpc_client(&self) -> &AsyncRpcClient {
        &self.rpc_client
    }

    pub fn is_borsh_enabled(&self) -> bool {
        self.borsh_encoding
    }

    pub fn is_simulation_enabled(&self) -> bool {
        self.simulate
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose_errors
    }

    pub fn check_batch_timeout(&self, id: BatchId) -> Result<()> {
        let current = self.batch_state_map.get_duration(&id);
        debug!("Current batch ({}) duration {:?}", id, current);
        if matches!(self.get_max_batch_duration(), Some(max_duration) if current > max_duration ) {
            let mut error = jsonrpc_core::Error::internal_error();
            error.message = "Batch is taking too long".to_string();
            return Err(error);
        }
        Ok(())
    }

    pub fn set_whitelist(&mut self, whitelist: Vec<TxFilter>) {
        self.whitelist = whitelist;
    }

    pub fn get_max_batch_duration(&self) -> Option<Duration> {
        self.max_batch_duration
    }

    pub fn set_max_batch_duration(&mut self, max_duration: Duration) {
        self.max_batch_duration = Some(max_duration);
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    pub async fn send_tx(
        &self,
        tx: evm::Transaction,
        meta_keys: HashSet<Pubkey>,
    ) -> EvmResult<Hex<H256>> {
        let (sender, mut receiver) = mpsc::channel::<EvmResult<Hex<H256>>>(1);

        if tx.gas_price < self.min_gas_price {
            return Err(Error::GasPriceTooLow {
                need: self.min_gas_price,
            });
        }

        let tx = PooledTransaction::new(tx, meta_keys, sender)
            .map_err(|source| evm_rpc::Error::EvmStateError { source })?;
        let tx = match self.pool.import(tx) {
            // tx was already processed on this bridge, return hash.
            Err(txpool::Error::AlreadyImported(h)) => return Ok(Hex(h)),
            Ok(tx) => tx,
            Err(source) => {
                let details = format!("{source}");
                warn!("{}", &details);
                return Err(evm_rpc::Error::MempoolImport { details });
            }
        };

        if self.simulate {
            receiver.recv().await.unwrap()
        } else {
            Ok(tx.inner.tx_id_hash().into())
        }
    }

    async fn block_to_number(&self, block: Option<BlockId>) -> EvmResult<u64> {
        let block = block.unwrap_or_default();
        let block_num = match block {
            BlockId::Num(block) => block.0,
            BlockId::RelativeId(BlockRelId::Latest) => self
                .rpc_client
                .get_evm_block_number()
                .await
                .map_err(from_client_error)?,
            _ => return Err(Error::BlockNotFound { block }),
        };
        Ok(block_num)
    }

    pub async fn is_transaction_landed(&self, hash: &H256) -> Option<bool> {
        async fn is_receipt_exists(bridge: &EvmBridge, hash: &H256) -> Option<bool> {
            bridge
                .rpc_client
                .get_evm_transaction_receipt(hash)
                .await
                .ok()
                .flatten()
                .map(|_receipt| true)
        }

        async fn is_signature_exists(bridge: &EvmBridge, hash: &H256) -> Option<bool> {
            match bridge.pool.signature_of_cached_transaction(hash) {
                Some(signature) => bridge
                    .rpc_client
                    .get_signature_status(&signature)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|result| result.ok())
                    .map(|()| true),
                None => None,
            }
        }

        match is_receipt_exists(self, hash).await {
            Some(b) => Some(b),
            None => is_signature_exists(self, hash).await,
        }
    }

    pub fn make_send_tx_instructions(
        &self,
        tx: &Transaction,
        meta_keys: &HashSet<Pubkey>,
    ) -> Vec<Instruction> {
        let mut native_fee_used = false;
        let mut ix = if self.borsh_encoding {
            let mut fee_type = FeePayerType::Evm;
            if self.should_pay_for_gas(tx) {
                fee_type = FeePayerType::Native;
                native_fee_used = true;
                info!("Using Native fee for tx: {}", tx.tx_id_hash());
            }
            solana_evm_loader_program::send_raw_tx(
                self.key.pubkey(),
                tx.clone(),
                Some(self.key.pubkey()),
                fee_type,
            )
        } else {
            solana_evm_loader_program::send_raw_tx_old(
                self.key.pubkey(),
                tx.clone(),
                Some(self.key.pubkey()),
            )
        };

        // Add meta accounts as additional arguments
        for account in meta_keys {
            ix.accounts.push(AccountMeta::new(*account, false))
        }

        if native_fee_used {
            vec![
                system_instruction::assign(&self.key.pubkey(), &solana_sdk::evm_loader::ID),
                ix,
                solana_evm_loader_program::free_ownership(self.key.pubkey()),
            ]
        } else {
            vec![ix]
        }
    }

    pub fn make_send_big_tx_instructions(
        &self,
        tx: &Transaction,
        storage_pubkey: Pubkey,
        payer_pubkey: Pubkey,
    ) -> Vec<Instruction> {
        let mut native_fee_used = false;
        let ix = if self.borsh_encoding {
            let mut fee_type = FeePayerType::Evm;
            if self.should_pay_for_gas(tx) {
                fee_type = FeePayerType::Native;
                native_fee_used = true;
                info!("Using Native fee for tx: {}", tx.tx_id_hash());
            }
            solana_evm_loader_program::big_tx_execute(storage_pubkey, Some(&payer_pubkey), fee_type)
        } else {
            solana_evm_loader_program::big_tx_execute_old(storage_pubkey, Some(&payer_pubkey))
        };
        if native_fee_used {
            vec![
                system_instruction::assign(&self.key.pubkey(), &solana_sdk::evm_loader::ID),
                ix,
                solana_evm_loader_program::free_ownership(self.key.pubkey()),
            ]
        } else {
            vec![ix]
        }
    }

    fn should_pay_for_gas(&self, tx: &Transaction) -> bool {
        !self.whitelist.is_empty() && self.whitelist.iter().any(|f| f.is_match(tx))
    }
}

#[derive(Debug)]
pub struct BridgeErpcImpl;

impl BridgeERPC for BridgeErpcImpl {
    type Metadata = Arc<EvmBridge>;

    #[instrument]
    fn accounts(&self, meta: Self::Metadata) -> EvmResult<Vec<Hex<Address>>> {
        Ok(meta.accounts.keys().map(|k| Hex(*k)).collect())
    }

    #[instrument]
    fn sign(&self, meta: Self::Metadata, address: Hex<Address>, data: Bytes) -> EvmResult<Bytes> {
        let secret_key = meta
            .accounts
            .get(&address.0)
            .ok_or(Error::KeyNotFound { account: address.0 })?;
        let mut message_data =
            format!("\x19Ethereum Signed Message:\n{}", data.0.len()).into_bytes();
        message_data.extend_from_slice(&data.0);
        let hash_to_sign = solana_sdk::keccak::hash(&message_data);
        let msg: Message = Message::from_slice(&hash_to_sign.to_bytes()).unwrap();
        let sig = SECP256K1.sign_recoverable(&msg, secret_key);
        let (rid, sig) = { sig.serialize_compact() };

        let mut sig_data_arr = [0; 65];
        sig_data_arr[0..64].copy_from_slice(&sig[0..64]);
        sig_data_arr[64] = rid.to_i32() as u8;
        Ok(sig_data_arr.to_vec().into())
    }

    #[instrument]
    fn sign_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
    ) -> BoxFuture<EvmResult<Bytes>> {
        let future = async move {
            let address = tx.from.map(|a| a.0).unwrap_or_default();

            debug!("sign_transaction from = {}", address);

            let secret_key = meta
                .accounts
                .get(&address)
                .ok_or(Error::KeyNotFound { account: address })?;

            let nonce = match tx
                .nonce
                .map(|a| a.0)
                .or_else(|| meta.pool.transaction_count(&address))
            {
                Some(n) => n,
                None => meta
                    .rpc_client
                    .get_evm_transaction_count(&address)
                    .await
                    .unwrap_or_default(),
            };

            let tx = UnsignedTransaction {
                nonce,
                gas_price: tx
                    .gas_price
                    .map(|a| a.0)
                    .unwrap_or_else(|| meta.min_gas_price),
                gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
                action: tx
                    .to
                    .map(|a| TransactionAction::Call(a.0))
                    .unwrap_or(TransactionAction::Create),
                value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
                input: tx.input.map(|a| a.0).unwrap_or_default(),
            };

            let tx = tx.sign(secret_key, Some(meta.evm_chain_id));
            Ok(tx.rlp_bytes().to_vec().into())
        };
        Box::pin(future)
    }

    #[instrument]
    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        let future = async move {
            let address = tx.from.map(|a| a.0).unwrap_or_default();

            debug!("send_transaction from = {}", address);

            let meta_keys = meta_keys
                .into_iter()
                .flatten()
                .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
                .collect::<StdResult<HashSet<_>, _>>()
                .map_err(|e| into_native_error(e, meta.verbose_errors))?;

            let secret_key = meta
                .accounts
                .get(&address)
                .ok_or(Error::KeyNotFound { account: address })?;

            let nonce = match tx
                .nonce
                .map(|a| a.0)
                .or_else(|| meta.pool.transaction_count(&address))
            {
                Some(n) => n,
                None => meta
                    .rpc_client
                    .get_evm_transaction_count(&address)
                    .await
                    .unwrap_or_default(),
            };

            let tx_create = evm::UnsignedTransaction {
                nonce,
                gas_price: tx
                    .gas_price
                    .map(|a| a.0)
                    .unwrap_or_else(|| meta.min_gas_price),
                gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000i32.into()),
                action: tx
                    .to
                    .map(|a| evm::TransactionAction::Call(a.0))
                    .unwrap_or(evm::TransactionAction::Create),
                value: tx.value.map(|a| a.0).unwrap_or_else(|| 0i32.into()),
                input: tx.input.map(|a| a.0).unwrap_or_default(),
            };

            let tx = tx_create.sign(secret_key, Some(meta.evm_chain_id));

            meta.send_tx(tx, meta_keys).await
        };

        Box::pin(future)
    }

    #[instrument]
    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
        meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        let future = async move {
            debug!("send_raw_transaction");
            let meta_keys = meta_keys
                .into_iter()
                .flatten()
                .map(|s| solana_sdk::pubkey::Pubkey::from_str(&s))
                .collect::<StdResult<HashSet<_>, _>>()
                .map_err(|e| into_native_error(e, meta.verbose_errors))?;

            let tx: compatibility::Transaction =
                rlp::decode(&bytes.0).with_context(|_| RlpError {
                    struct_name: "RawTransaction".to_string(),
                    input_data: hex::encode(&bytes.0),
                })?;
            let tx: evm::Transaction = tx.into();

            // TODO: Check chain_id.
            // TODO: check gas price.

            let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
            let hash = unsigned_tx.signing_hash(Some(meta.evm_chain_id));
            debug!("loaded tx_hash = {}", hash);

            meta.send_tx(tx, meta_keys).await
        };

        Box::pin(future)
    }

    #[instrument]
    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Ok(vec![])
    }
}

#[derive(Debug)]
pub struct BundlerErpcImpl;

impl BundlerERPC for BundlerErpcImpl {
    type Metadata = Arc<EvmBridge>;

    // #[instrument]
    fn send_user_operation(
        &self,
        meta: Self::Metadata,
        user_operation: UserOperation,
        entry_point: Address,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        Box::pin(async move {
            // 1 - sanity checks
            meta.get_bundler()
                .check_user_op(&meta.rpc_client, &user_operation)
                .await?;
            // 2 - simulation
            let res = meta
                .get_bundler()
                .simulate_user_op(&meta.rpc_client, &user_operation, entry_point)
                .await?;
            if res.return_info.is_failed() {
                return Err(Error::UserOpSimulateValidationError {
                    message: "simulation failed".to_string(),
                });
            }
            let batch = [&user_operation].to_vec();
            // 3 - estimate gas
            let estimated_gas = meta
                .get_bundler()
                .estimate_handle_ops(&meta.rpc_client, &batch, entry_point)
                .await?;
            // 4 - call execute
            meta.get_bundler().send_user_ops(meta.clone(), &batch, entry_point, estimated_gas).await?;
            Ok(Hex(user_operation.hash(entry_point, meta.evm_chain_id)))
        })
    }
}

#[derive(Debug)]
pub struct GeneralErpcProxy;
impl GeneralERPC for GeneralErpcProxy {
    type Metadata = Arc<EvmBridge>;

    #[instrument]
    fn network_id(&self, meta: Self::Metadata) -> EvmResult<String> {
        // NOTE: also we can get chain id from meta, but expects the same value
        Ok(format!("{}", meta.evm_chain_id))
    }

    #[instrument]
    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(true)
    }

    #[instrument]
    fn peer_count(&self, _meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    #[instrument]
    fn chain_id(&self, meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(meta.evm_chain_id))
    }

    #[instrument]
    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> EvmResult<Hex<H256>> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    #[instrument]
    fn client_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("VelasEvm/v0.5.0"))
    }

    #[instrument]
    fn protocol_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(solana_version::semver!().into())
    }

    #[instrument]
    fn is_syncing(&self, meta: Self::Metadata) -> EvmResult<bool> {
        Err(evm_rpc::Error::ProxyRequest)
    }

    #[instrument]
    fn coinbase(&self, _meta: Self::Metadata) -> EvmResult<Hex<Address>> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    #[instrument]
    fn is_mining(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    #[instrument]
    fn hashrate(&self, _meta: Self::Metadata) -> EvmResult<Hex<U256>> {
        Ok(Hex(U256::zero()))
    }

    #[instrument]
    fn gas_price(&self, meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        Ok(Hex(meta.min_gas_price))
    }
}

#[derive(Debug)]
pub struct ChainErpcProxy;
impl ChainERPC for ChainErpcProxy {
    type Metadata = Arc<EvmBridge>;

    #[instrument]
    // The same as get_slot
    fn block_number(&self, _meta: Self::Metadata) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn balance(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<U256>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn storage_at(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _data: Hex<U256>,
        _block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<H256>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Hex<U256>>> {
        if matches!(block, Some(BlockId::RelativeId(BlockRelId::Pending))) {
            if let Some(tx_count) = meta.pool.transaction_count(&address.0) {
                return Box::pin(ready(Ok(Hex(tx_count))));
            }
        }

        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn block_transaction_count_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
    ) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn block_transaction_count_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Hex<usize>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn code(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _block: Option<BlockId>,
    ) -> BoxFuture<EvmResult<Bytes>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn block_by_hash(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        full: bool,
    ) -> BoxFuture<EvmResult<Option<RPCBlock>>> {
        if block_hash == Hex(H256::zero()) {
            Box::pin(ready(Ok(Some(RPCBlock::default()))))
        } else {
            Box::pin(async move {
                meta.rpc_client
                    .get_evm_block_by_hash(block_hash, full)
                    .await
                    .map(|o: Option<_>| o.map(compatibility::patch_block))
                    .map_err(from_client_error)
            })
        }
    }

    #[instrument]
    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        full: bool,
    ) -> BoxFuture<EvmResult<Option<RPCBlock>>> {
        if block == BlockId::Num(0x0.into()) {
            Box::pin(ready(Ok(Some(RPCBlock::default()))))
        } else {
            Box::pin(async move {
                meta.rpc_client
                    .get_evm_block_by_number(block, full)
                    .await
                    .map(|o: Option<_>| o.map(compatibility::patch_block))
                    .map_err(from_client_error)
            })
        }
    }

    #[instrument(skip(self))]
    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        // TODO: chain all possible outcomes properly
        if let Some(tx) = meta.pool.transaction_by_hash(tx_hash) {
            if let Ok(tx) = RPCTransaction::from_transaction((**tx).clone().into()) {
                // TODO: should we `patch` tx?
                return Box::pin(ready(Ok(Some(tx))));
            }
        }
        Box::pin(async move {
            meta.rpc_client
                .get_evm_transaction_by_hash(tx_hash)
                .await
                .map(|o: Option<_>| o.map(compatibility::patch_tx))
                .map_err(from_client_error)
        })
    }

    #[instrument]
    fn transaction_by_block_hash_and_index(
        &self,
        meta: Self::Metadata,
        block_hash: Hex<H256>,
        tx_id: Hex<usize>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn transaction_by_block_number_and_index(
        &self,
        meta: Self::Metadata,
        block: BlockId,
        tx_id: Hex<usize>,
    ) -> BoxFuture<EvmResult<Option<RPCTransaction>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn transaction_receipt(
        &self,
        _meta: Self::Metadata,
        _tx_hash: Hex<H256>,
    ) -> BoxFuture<EvmResult<Option<RPCReceipt>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn call(
        &self,
        _meta: Self::Metadata,
        _tx: RPCTransaction,
        _block: Option<BlockId>,
        _meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Bytes>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument]
    fn estimate_gas(
        &self,
        _meta: Self::Metadata,
        _tx: RPCTransaction,
        _block: Option<BlockId>,
        _meta_keys: Option<Vec<String>>,
    ) -> BoxFuture<EvmResult<Hex<Gas>>> {
        Box::pin(ready(Err(evm_rpc::Error::ProxyRequest)))
    }

    #[instrument(skip(self, meta))]
    fn logs(
        &self,
        meta: Self::Metadata,
        mut log_filter: RPCLogFilter,
    ) -> BoxFuture<EvmResult<Vec<RPCLog>>> {
        Box::pin(async move {
            let starting_block = meta.block_to_number(log_filter.from_block).await?;
            let ending_block = meta.block_to_number(log_filter.to_block).await?;

            if ending_block < starting_block {
                return Err(Error::InvalidBlocksRange {
                    starting: starting_block,
                    ending: ending_block,
                    batch_size: None,
                });
            }

            // request more than we can provide
            if ending_block > starting_block + meta.max_logs_blocks {
                return Err(Error::InvalidBlocksRange {
                    starting: starting_block,
                    ending: ending_block,
                    batch_size: Some(meta.max_logs_blocks),
                });
            }

            let mut starting = starting_block;
            let mut collector = Vec::new();
            while starting <= ending_block {
                let ending = (starting.saturating_add(MAX_NUM_BLOCKS_IN_BATCH)).min(ending_block);
                log_filter.from_block = Some(starting.into());
                log_filter.to_block = Some(ending.into());

                let cloned_filter = log_filter.clone();
                let cloned_meta = meta.clone();
                // Parallel execution:
                collector.push(tokio::task::spawn(async move {
                    info!("filter = {:?}", cloned_filter);
                    let result: EvmResult<Vec<RPCLog>> = cloned_meta
                        .rpc_client
                        .get_evm_logs(&cloned_filter)
                        .await
                        .map_err(from_client_error);
                    info!("logs = {:?}", result);

                    result
                }));

                starting = starting.saturating_add(MAX_NUM_BLOCKS_IN_BATCH + 1);
            }
            // join all execution, fast fail on any error.
            let mut result = Vec::new();
            for collection in collector {
                result.extend(collection.await.map_err(|details| Error::RuntimeError {
                    details: details.to_string(),
                })??)
            }
            Ok(result)
        })
    }

    #[instrument]
    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(None)
    }

    #[instrument]
    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(None)
    }

    #[instrument]
    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    #[instrument]
    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }
}

pub(crate) fn from_client_error(client_error: ClientError) -> evm_rpc::Error {
    let client_error_kind = client_error.kind();
    match client_error_kind {
        ClientErrorKind::RpcError(solana_client::rpc_request::RpcError::RpcResponseError {
                                      code,
                                      message,
                                      data,
                                      original_err,
                                  }) => {
            match data {
                // if transaction preflight, try to get last log messages, and return it as error.
                RpcResponseErrorData::SendTransactionPreflightFailure(
                    RpcSimulateTransactionResult {
                        err: Some(TransactionError::InstructionError(_, _)),
                        logs: Some(logs),
                        ..
                    },
                ) if !logs.is_empty() => {
                    let first_entry = logs.len().saturating_sub(2); // take two elements from logs
                    let last_log = logs[first_entry..].join(";");

                    return evm_rpc::Error::ProxyRpcError {
                        source: jsonrpc_core::Error {
                            code: (*code).into(),
                            message: last_log,
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
