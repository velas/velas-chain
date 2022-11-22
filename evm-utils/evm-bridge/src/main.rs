mod middleware;
mod pool;
mod rpc_client;
mod tx_filter;

use log::*;
use std::fs::File;
use std::future::ready;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain::ChainERPC;
use evm_rpc::error::{Error, *};
use evm_rpc::general::GeneralERPC;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_core::BoxFuture;
use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use snafu::ResultExt;

use derivative::*;
use solana_evm_loader_program::instructions::FeePayerType;
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    clock::MS_PER_TICK,
    fee_calculator::DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signer::Signer,
    signers::Signers,
    system_instruction,
    transaction::TransactionError,
};

use solana_client::{
    client_error::{ClientError, ClientErrorKind},
    rpc_config::*,
    rpc_request::RpcResponseErrorData,
    rpc_response::Response as RpcResponse,
    rpc_response::*,
};

use tracing_attributes::instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{
    filter::{LevelFilter, Targets},
    layer::{Layer, SubscriberExt},
};

use ::tokio;
use ::tokio::sync::mpsc;
use ::tokio::time::sleep;

use middleware::ProxyMiddleware;
use pool::{
    worker_cleaner, worker_deploy, worker_signature_checker, EthPool, PooledTransaction,
    SystemClock,
};
use rpc_client::AsyncRpcClient;
use tx_filter::TxFilter;

use rlp::Encodable;
use secp256k1::Message;
use std::result::Result as StdResult;
type EvmResult<T> = StdResult<T, evm_rpc::Error>;

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
}

impl EvmBridge {
    fn new(
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
        let key = solana_sdk::signature::read_keypair_file(&keypath).unwrap();

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
        }
    }

    fn set_whitelist(&mut self, whitelist: Vec<TxFilter>) {
        self.whitelist = whitelist;
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    async fn send_tx(
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

    fn make_send_tx_instructions(
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

    fn make_send_big_tx_instructions(
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
        Ok(meta.accounts.iter().map(|(k, _)| Hex(*k)).collect())
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

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
    #[structopt(default_value = "57005")] // 0xdead
    evm_chain_id: u64,
    #[structopt(long = "min-gas-price")]
    min_gas_price: Option<String>,
    #[structopt(long = "verbose-errors")]
    verbose_errors: bool,
    #[structopt(long = "borsh-encoding")]
    borsh_encoding: bool,
    #[structopt(long = "no-simulate")]
    no_simulate: bool, // parse inverted to keep false default
    /// Maximum number of blocks to return in eth_getLogs rpc.
    #[structopt(long = "max-logs-block-count", default_value = "500")]
    max_logs_blocks: u64,

    #[structopt(long = "jaeger-collector-url", short = "j")]
    jaeger_collector_url: Option<String>,

    #[structopt(long = "whitelist-path")]
    whitelist_path: Option<String>,
}

impl Args {
    fn min_gas_price_or_default(&self) -> U256 {
        let gwei: U256 = 1_000_000_000.into();
        fn min_gas_price() -> U256 {
            //TODO: Add gas logic
            (21000 * solana_evm_loader_program::scope::evm::LAMPORTS_TO_GWEI_PRICE
                / DEFAULT_TARGET_LAMPORTS_PER_SIGNATURE)
                .into() // 21000 is smallest call in evm
        }

        let mut gas_price = match self
            .min_gas_price
            .as_ref()
            .and_then(|gas_price| U256::from_dec_str(gas_price).ok())
        {
            Some(gas_price) => {
                info!(r#"--min-gas-price is set to {}"#, &gas_price);
                gas_price
            }
            None => {
                let default_price = min_gas_price();
                warn!(
                    r#"Value of "--min-gas-price" is not set or unable to parse. Default value is: {}"#,
                    default_price
                );
                default_price
            }
        };
        // ceil to gwei for metamask
        gas_price += gwei - 1;
        gas_price - gas_price % gwei
    }
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> StdResult<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let min_gas_price = args.min_gas_price_or_default();
    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    if let Some(collector) = args.jaeger_collector_url {
        // init tracer
        let fmt_filter = std::env::var("RUST_LOG")
            .ok()
            .and_then(|rust_log| match rust_log.parse::<Targets>() {
                Ok(targets) => Some(targets),
                Err(e) => {
                    eprintln!("failed to parse `RUST_LOG={:?}`: {}", rust_log, e);
                    None
                }
            })
            .unwrap_or_else(|| Targets::default().with_default(LevelFilter::WARN));

        let tracer = opentelemetry_jaeger::new_pipeline()
            .with_service_name("evm-bridge-tracer")
            .with_collector_endpoint(collector)
            .install_batch(opentelemetry::runtime::Tokio)
            .unwrap();
        let opentelemetry = tracing_opentelemetry::layer().with_tracer(tracer);
        let registry = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_filter(fmt_filter))
            .with(opentelemetry);

        registry.try_init().unwrap();
    }

    let mut whitelist = vec![];
    if let Some(path) = args.whitelist_path.map(PathBuf::from) {
        let file = File::open(path).unwrap();
        whitelist = serde_json::from_reader(file).unwrap();
        info!("Got whitelist: {:?}", whitelist);
    }

    let mut meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
        args.verbose_errors,
        args.borsh_encoding,
        !args.no_simulate, // invert argument
        args.max_logs_blocks,
        min_gas_price,
    );
    meta.set_whitelist(whitelist);
    let meta = Arc::new(meta);

    let mut io = MetaIoHandler::with_middleware(ProxyMiddleware {});

    let ether_bridge = BridgeErpcImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_chain = ChainErpcProxy;
    io.extend_with(ether_chain.to_delegate());
    let ether_general = GeneralErpcProxy;
    io.extend_with(ether_general.to_delegate());

    let mempool_worker = worker_deploy(meta.clone());

    let cleaner = worker_cleaner(meta.clone());

    let signature_checker = worker_signature_checker(meta.clone());

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

    let _cleaner = tokio::task::spawn(cleaner);
    let _signature_checker = tokio::task::spawn(signature_checker);
    let mempool_task = tokio::task::spawn(mempool_worker);
    let servers_waiter = tokio::task::spawn_blocking(|| {
        ws_server.wait().unwrap();
        server.wait();
    });

    // wait for any failure/stops.
    tokio::select! {
        _ = servers_waiter => {
            println!("Server exited.");
        }
        _ = mempool_task => {
            println!("Mempool task exited.");
        }
    };
    Ok(())
}

async fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &AsyncRpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), anyhow::Error> {
    const SEND_RETRIES: usize = 5;
    const STATUS_RETRIES: usize = 15;

    for _ in 0..SEND_RETRIES {
        // Send all transactions
        let mut transactions_signatures = vec![];
        for transaction in transactions.drain(..) {
            if cfg!(not(test)) {
                // Delay ~1 tick between write transactions in an attempt to reduce AccountInUse errors
                // when all the write transactions modify the same program account (eg, deploying a
                // new program)
                sleep(Duration::from_millis(MS_PER_TICK)).await;
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
                .await
                .map_err(|e| error!("Send transaction error: {:?}", e))
                .ok();

            transactions_signatures.push((transaction, signature));
        }

        for _ in 0..STATUS_RETRIES {
            // Collect statuses for all the transactions, drop those that are confirmed

            if cfg!(not(test)) {
                // Retry twice a second
                sleep(Duration::from_millis(500)).await;
            }

            let mut retained = vec![];
            for (transaction, signature) in transactions_signatures {
                if let Some(signature) = signature {
                    if rpc_client
                        .get_signature_statuses(&[signature])
                        .await
                        .ok()
                        .and_then(|RpcResponse { mut value, .. }| value.remove(0))
                        .and_then(|status| status.confirmations)
                        .map(|confirmations| confirmations == 0) // retain unconfirmed only
                        .unwrap_or(true)
                    {
                        retained.push((transaction, Some(signature)));
                    }
                } else {
                    retained.push((transaction, signature));
                }
            }
            transactions_signatures = retained;

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let blockhash = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash)
            .await?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            debug!("Resending {:?}", transaction);
            transactions.push(transaction);
        }
    }
    Err(anyhow::Error::msg("Transactions failed"))
}

#[cfg(test)]
mod tests {
    use crate::AsyncRpcClient;
    use crate::{BridgeErpcImpl, EthPool, EvmBridge, SystemClock};
    use evm_rpc::{BridgeERPC, Hex};
    use evm_state::Address;
    use secp256k1::SecretKey;
    use solana_sdk::signature::Keypair;
    use std::str::FromStr;
    use std::sync::Arc;

    #[test]
    fn test_eth_sign() {
        let signing_key =
            SecretKey::from_str("c21020a52198632ae7d5c1adaa3f83da2e0c98cf541c54686ddc8d202124c086")
                .unwrap();
        let public_key = evm_state::PublicKey::from_secret_key(evm_state::SECP256K1, &signing_key);
        let public_key = evm_state::addr_from_public_key(&public_key);
        let bridge = Arc::new(EvmBridge {
            evm_chain_id: 111u64,
            key: Keypair::new(),
            accounts: vec![(public_key, signing_key)].into_iter().collect(),
            rpc_client: AsyncRpcClient::new("".to_string()),
            verbose_errors: true,
            borsh_encoding: false,
            simulate: false,
            max_logs_blocks: 0u64,
            pool: EthPool::new(SystemClock),
            min_gas_price: 0.into(),
            whitelist: vec![],
        });

        let rpc = BridgeErpcImpl {};
        let address = Address::from_str("0x141a4802f84bb64c0320917672ef7D92658e964e").unwrap();
        let data = "qwe".as_bytes().to_vec();
        let res = rpc.sign(bridge, Hex(address), data.into()).unwrap();
        assert_eq!(res.to_string(), "0xb734e224f0f92d89825f3f69bf03924d7d2f609159d6ce856d37a58d7fcbc8eb6d224fd73f05217025ed015283133c92888211b238272d87ec48347f05ab42a000");
    }
}
