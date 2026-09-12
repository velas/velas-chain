mod listener;

use {
    crate::{from_client_error, send_and_confirm_transactions, EvmBridge, EvmResult},
    ::tokio::sync::mpsc,
    base64::{engine::general_purpose::STANDARD as BASE64, Engine},
    borsh::BorshSerialize,
    evm_rpc::{error::into_native_error, Bytes, RPCTransaction},
    evm_state::{Address, TransactionAction, H160, H256, U256},
    listener::PoolListener,
    log::*,
    once_cell::sync::Lazy,
    serde_json::json,
    solana_client::{rpc_config::RpcSendTransactionConfig, rpc_request::RpcRequest},
    solana_evm_loader_program::{
        scope::{evm, solana},
        tx_chunks::TxChunks,
    },
    solana_sdk::{
        commitment_config::{CommitmentConfig, CommitmentLevel},
        message::Message,
        pubkey::Pubkey,
        signature::Signature,
        signer::Signer,
        system_instruction,
    },
    std::{
        collections::{HashMap, HashSet},
        ops::Deref,
        sync::{Arc, Mutex},
        time::Duration,
    },
    tokio::sync::mpsc::error::SendError,
    tracing_attributes::instrument,
    txpool::{
        scoring::Choice, Pool, Readiness, Ready, Scoring, ShouldReplace, VerifiedTransaction,
    },
};

type UnixTimeMs = u64;

/// Loop delay of signature check worker
const SIG_CHECK_WORKER_PAUSE: Duration = Duration::from_secs(60);

/// Delay before next loop of cleanup of outdated entries
/// from hashmap of last deployed transactions
const CLEANUP_WORKER_PAUSE: Duration = Duration::from_secs(86400); // = 24 hours

/// Limit activity of transaction sender, who sends invalid transactions.
const SENDER_PAUSE: Duration = Duration::from_secs(15);

/// Threshold waiting for the status of the signature before
/// reimporting the transaction to the pool
/// TODO: adjust value
const TX_REIMPORT_THRESHOLD: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct CachedTransaction {
    evm_tx: evm_state::Transaction,
    meta_keys: HashSet<Pubkey>,
    cached_at: UnixTimeMs,
    signature: Signature,
}

/// Abstracting the time source for the testing purposes
pub trait Clock: Send + Sync {
    fn now(&self) -> UnixTimeMs;
}

/// Real clock used for production

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTimeMs {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

struct AlwaysReady;

impl<T> Ready<T> for AlwaysReady {
    fn is_ready(&mut self, _tx: &T) -> Readiness {
        Readiness::Ready
    }
}

#[derive(Debug)]
pub struct EthPool<C: Clock> {
    /// A pool of transactions, waiting to be deployed
    pool: Mutex<Pool<PooledTransaction, MyScoring, PoolListener>>,

    /// Timestamps of the last deployed transactions
    last_entry: Mutex<HashMap<Address, UnixTimeMs>>,

    /// List of EVM transactions, which need to be
    /// checked and redeployed in case of error
    after_deploy_check: Mutex<HashMap<H256, CachedTransaction>>,

    /// Clock used to determine whether transaction is stalled or ready to be deployed
    clock: C,
}

impl<C: Clock> EthPool<C> {
    pub fn new(clock: C) -> Self {
        Self {
            pool: Mutex::new(Pool::new(PoolListener, MyScoring, Default::default())),
            last_entry: Mutex::new(HashMap::new()),
            after_deploy_check: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Imports transaction into the pool
    pub fn import(
        &self,
        tx: PooledTransaction,
    ) -> Result<Arc<PooledTransaction>, txpool::Error<H256>> {
        self.pool.lock().unwrap().import(tx, &MyScoring)
    }

    /// Prevents pooled transactions from specified sender `address` from processing for certain amount of time
    pub fn pause_processing(&self, sender: &H160, pause: Duration) {
        let stop_before = self.clock.now() + pause.as_millis() as u64;
        self.last_entry.lock().unwrap().insert(*sender, stop_before);
    }

    /// Removes transaction from the pool
    pub fn remove(&self, hash: &H256) -> Option<Arc<PooledTransaction>> {
        self.pool.lock().unwrap().remove(hash, false)
    }

    /// Used for a special case when the transaction was replaced at a time when the worker was already processing it
    pub fn remove_by_nonce(&self, sender: &Address, nonce: U256) -> Option<Arc<PooledTransaction>> {
        let hash = {
            self.pool
                .lock()
                .unwrap()
                .pending_from_sender(AlwaysReady, sender, H256::zero())
                .find(|tx| &tx.sender == sender && tx.nonce == nonce)
                .map(|tx| tx.hash)
        };

        hash.and_then(|hash| self.remove(&hash))
    }

    /// Gets reference to the next transaction in queue ready to be deployed
    pub fn pending(&self) -> Option<Arc<PooledTransaction>> {
        let pool = self.pool.lock().unwrap();
        let last_entry = self.last_entry.lock().unwrap();

        pool.pending(
            |tx: &PooledTransaction| {
                if let Some(stop_before) = last_entry.get(&tx.sender) {
                    if self.clock.now() < *stop_before {
                        return Readiness::Stale;
                    }
                }
                Readiness::Ready
            },
            H256::zero(),
        )
        .next()
    }

    /// Returns nonce from transaction pool, or `None` if the it doesn't contain
    /// any transactions associated with the specified sender
    pub fn transaction_count(&self, sender: &Address) -> Option<U256> {
        self.pool
            .lock()
            .unwrap()
            .pending_from_sender(AlwaysReady, sender, H256::zero())
            .max_by_key(|tx| tx.nonce)
            .map(|tx| tx.nonce + 1)
    }

    /// Gets transaction from the pool by specified hash
    pub fn transaction_by_hash(&self, tx_hash: H256) -> Option<Arc<PooledTransaction>> {
        let pool = self.pool.lock().unwrap();
        pool.find(&tx_hash)
    }

    /// Strips outdated timestamps and returns the number of
    /// elements in the collection before and after the strip
    pub fn strip_outdated(&self) -> (usize, usize) {
        let now = self.clock.now();
        let mut last_entry = self.last_entry.lock().unwrap();
        let before_strip = last_entry.len();
        last_entry.retain(|_, stop_before| *stop_before > now);
        let after_strip = last_entry.len();
        (before_strip, after_strip)
    }

    /// Adds signature for later tracking of transaction status
    ///
    /// * `hash` - EVM transaction hash
    /// * `signature` - signature of Solana transaction to be checked for status
    /// * `meta_keys` -
    /// * `evm_tx` - ethereum tx to be redeployed in case of status error
    pub fn schedule_after_deploy_check(
        &self,
        hash: H256,
        signature: Signature,
        meta_keys: HashSet<Pubkey>,
        evm_tx: evm_state::Transaction,
    ) {
        let cached_at = self.clock.now();

        let cached_tx = CachedTransaction {
            evm_tx,
            meta_keys,
            cached_at,
            signature,
        };

        self.after_deploy_check
            .lock()
            .unwrap()
            .insert(hash, cached_tx);
    }

    /// Gets hashes and signatures of transactions needed to be checked for status
    pub fn get_scheduled_for_check_transactions(&self) -> Vec<(H256, UnixTimeMs)> {
        self.after_deploy_check
            .lock()
            .unwrap()
            .iter()
            .map(|(hash, tx)| (*hash, tx.cached_at))
            .collect()
    }

    /// Drops transaction from the cache when post-deploy checks lo longer required
    pub fn drop_from_cache(&self, hash: &H256) {
        self.after_deploy_check.lock().unwrap().remove(hash);
    }

    /// Extracts EVM transaction from the cache for redeploy
    pub fn transaction_for_redeploy(&self, hash: &H256) -> Option<CachedTransaction> {
        self.after_deploy_check.lock().unwrap().remove(hash)
    }

    /// Gets signature of cached transaction
    pub fn signature_of_cached_transaction(&self, hash: &H256) -> Option<Signature> {
        self.after_deploy_check
            .lock()
            .unwrap()
            .get(hash)
            .map(|cached| cached.signature)
    }
}

#[derive(Debug)]
pub struct PooledTransaction {
    pub inner: evm::Transaction,
    pub meta_keys: HashSet<Pubkey>,
    sender: Address,
    hash: H256,
    hash_sender: Option<mpsc::Sender<EvmResult<H256>>>,
}

impl PooledTransaction {
    pub fn new(
        transaction: evm::Transaction,
        meta_keys: HashSet<Pubkey>,
        hash_sender: mpsc::Sender<EvmResult<H256>>,
    ) -> Result<Self, evm_state::error::Error> {
        let hash = transaction.tx_id_hash();
        let sender = transaction.caller()?;

        Ok(Self {
            inner: transaction,
            sender,
            hash,
            meta_keys,
            hash_sender: Some(hash_sender),
        })
    }

    pub fn reimported(
        transaction: evm::Transaction,
        meta_keys: HashSet<Pubkey>,
    ) -> Result<Self, evm_state::error::Error> {
        let hash = transaction.tx_id_hash();
        let sender = transaction.caller()?;

        Ok(Self {
            inner: transaction,
            sender,
            hash,
            meta_keys,
            hash_sender: None,
        })
    }

    async fn send(&self, hash: EvmResult<H256>) -> Result<(), SendError<EvmResult<H256>>> {
        if let Some(hash_sender) = &self.hash_sender {
            hash_sender.send(hash).await
        } else {
            Ok(())
        }
    }

    fn blocking_send(&self, hash: EvmResult<H256>) -> Result<(), SendError<EvmResult<H256>>> {
        if let Some(hash_sender) = &self.hash_sender {
            hash_sender.blocking_send(hash)
        } else {
            Ok(())
        }
    }
}

impl VerifiedTransaction for PooledTransaction {
    type Hash = H256;

    type Sender = Address;

    fn hash(&self) -> &Self::Hash {
        &self.hash
    }

    fn mem_usage(&self) -> usize {
        0 // TODO: return correct value
    }

    fn sender(&self) -> &Self::Sender {
        &self.sender
    }
}

impl Deref for PooledTransaction {
    type Target = evm::Transaction;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug)]
pub struct MyScoring;

impl Scoring<PooledTransaction> for MyScoring {
    type Score = H256;

    type Event = ();

    fn compare(&self, old: &PooledTransaction, other: &PooledTransaction) -> std::cmp::Ordering {
        old.nonce.cmp(&other.nonce)
    }

    fn choose(&self, old: &PooledTransaction, new: &PooledTransaction) -> Choice {
        if old.nonce == new.nonce {
            if new.gas_price > old.gas_price {
                Choice::ReplaceOld
            } else {
                Choice::RejectNew
            }
        } else {
            Choice::InsertNew
        }
    }

    fn update_scores(
        &self,
        _txs: &[txpool::Transaction<PooledTransaction>],
        _scores: &mut [Self::Score],
        _change: txpool::scoring::Change<Self::Event>,
    ) {
    }
}

impl ShouldReplace<PooledTransaction> for MyScoring {
    fn should_replace(
        &self,
        _old: &txpool::ReplaceTransaction<PooledTransaction>,
        _new: &txpool::ReplaceTransaction<PooledTransaction>,
    ) -> Choice {
        Choice::InsertNew
    }
}

/// This worker checks for new transactions in pool and tries to deploy them
pub async fn worker_deploy(bridge: Arc<EvmBridge>) {
    info!("Running deploy worker task...");

    loop {
        let tx = bridge.pool.pending();

        if let Some(pooled_tx) = tx {
            let hash = pooled_tx.hash;
            let nonce = pooled_tx.nonce;
            let sender = pooled_tx.sender;
            let meta_keys = pooled_tx.meta_keys.clone();
            let tx = (*pooled_tx).clone();
            info!(
                "Deploy worker is trying to process tx with hash = {:?} [tx = {:?}]",
                &hash, tx
            );
            let cloned_bridge = bridge.clone();

            let processed_tx = process_tx(cloned_bridge, tx, hash, sender, meta_keys).await;

            match processed_tx {
                Ok(hash) => {
                    info!("Transaction {} processed successfully", &hash);
                    let _result = pooled_tx.send(Ok(hash)).await;
                }
                Err(e) => {
                    // Any error is a reason to limit user activity.
                    // If error is recoverable, then implement delay to avoid flooding.
                    // If error is not recoverable, then client form invalid tx.
                    bridge.pool.pause_processing(&sender, SENDER_PAUSE);

                    if is_recoverable_error(&e) {
                        debug!(
                            "Found recoverable error, for tx = {:?}. Error = {}",
                            &hash, &e
                        );
                        continue;
                    }

                    warn!(
                        "Something went wrong in transaction {:?}. Error = {}",
                        &hash, &e
                    );
                    let _result = pooled_tx.send(Err(e)).await;
                }
            }

            match bridge.pool.remove(&hash) {
                Some(tx) => {
                    info!("Transaction {} removed from the pool", tx.hash)
                }
                None => {
                    match bridge.pool.remove_by_nonce(&sender, nonce) {
                        Some(dup_tx) => {
                            info!("Tx was replaced during deploy, duplicate tx with hash = {} removed", dup_tx.hash);
                        }
                        None => {
                            warn!("Transaction from the pool dissapeared mysteriously...")
                        }
                    }
                }
            }
        } else {
            trace!("Deploy worker is idling...");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Checks updated timestamp tails in pool and removes them
pub async fn worker_cleaner(bridge: Arc<EvmBridge>) {
    info!("Running cleaner task...");
    loop {
        tokio::time::sleep(CLEANUP_WORKER_PAUSE).await;

        let (before_strip, after_strip) = bridge.pool.strip_outdated();
        info!("Cleanup of outdated `last deployed` infos. Entries before cleanup: {}, after cleanup: {}", before_strip, after_strip);
    }
}

/// Checks signatures of deployed transactions and returns transaction back in the
/// pool in case of status error
pub async fn worker_signature_checker(bridge: Arc<EvmBridge>) {
    info!("Running signature checker task...");

    loop {
        info!("Worker checks signatures");

        for (hash, generated) in bridge.pool.get_scheduled_for_check_transactions() {
            debug!("Checking scheduled transaction {}", &hash);

            let now = bridge.pool.clock.now();

            match bridge.is_transaction_landed(&hash).await {
                Some(true) => {
                    info!("Transaction {} finalized.", &hash);
                    bridge.pool.drop_from_cache(&hash);
                }
                Some(false) | None => {
                    if now - generated > TX_REIMPORT_THRESHOLD.as_millis() as u64 {
                        info!("Transaction {} needs to redeploy", &hash);
                        let evm_tx = bridge.pool.transaction_for_redeploy(&hash);
                        match evm_tx {
                            Some(cached) => {
                                warn!("Redeploying transaction {}", &hash);
                                if let Ok(pooled_tx) =
                                    PooledTransaction::reimported(cached.evm_tx, cached.meta_keys)
                                {
                                    match bridge.pool.import(pooled_tx) {
                                        Ok(tx) => {
                                            bridge.pool.drop_from_cache(&hash);
                                            info!(
                                                "Transaction reimported to the pool. New tx hash: {}",
                                                tx.hash
                                            )
                                        }
                                        Err(err) => {
                                            warn!(
                                                "Transaction can not be reimported to the pool: {}",
                                                err
                                            )
                                        }
                                    }
                                }
                            }
                            None => {
                                error!("Bug: transaction {} should be present in cache", &hash)
                            }
                        }
                    } else {
                        debug!(
                            "Transaction {} has not passed redeploy threshold yet",
                            &hash
                        )
                    }
                }
            }
        }

        tokio::time::sleep(SIG_CHECK_WORKER_PAUSE).await;
    }
}

#[instrument]
async fn process_tx(
    bridge: Arc<EvmBridge>,
    tx: evm_state::Transaction,
    hash: H256,
    sender: H160,
    mut meta_keys: HashSet<Pubkey>,
) -> EvmResult<H256> {
    let mut bytes = vec![];
    BorshSerialize::serialize(&tx, &mut bytes).unwrap();

    let rpc_tx = RPCTransaction::from_transaction(tx.clone().into())?;

    if bridge.simulate {
        // Try simulate transaction execution
        bridge
            .rpc_client
            .send::<Bytes>(RpcRequest::EthCall, json!([rpc_tx, "latest"]))
            .await
            .map_err(from_client_error)?;
    }

    if bytes.len() > evm::TX_MTU {
        debug!("Sending tx = {}, by chunks", hash);
        match deploy_big_tx(&bridge, &bridge.key, &tx).await {
            Ok(_tx) => {
                return Ok(hash);
            }
            Err(e) => {
                error!("Error creating big tx = {}", e);
                return Err(e);
            }
        }
    }

    debug!(
        "Printing tx_info from = {:?}, to = {:?}, nonce = {}, chain_id = {:?}",
        sender,
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

    let instructions = bridge.make_send_tx_instructions(&tx, &meta_keys);
    let message = Message::new(&instructions, Some(&bridge.key.pubkey()));
    let mut send_raw_tx: solana::Transaction = solana::Transaction::new_unsigned(message);

    debug!("Getting block hash");
    let (blockhash, _height) = bridge
        .rpc_client
        .get_latest_blockhash_with_commitment(CommitmentConfig::processed())
        .await
        .map(|response| response.value)
        // NOTE: into_native_error?
        .map_err(|e| evm_rpc::Error::NativeRpcError {
            details: String::from("Failed to get recent blockhash"),
            source: e.into(),
            verbose: bridge.verbose_errors,
        })?;

    send_raw_tx.sign(&[&bridge.key], blockhash);
    debug!("Sending tx = {:?}", send_raw_tx);

    debug!(
        "Sending tx raw = {}",
        BASE64.encode(send_raw_tx.message_data())
    );

    let signature = bridge
        .rpc_client
        .send_transaction_with_config(
            &send_raw_tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(CommitmentLevel::Processed),
                skip_preflight: !bridge.simulate,
                ..Default::default()
            },
        )
        .await
        .map_err(from_client_error)?;

    bridge
        .pool
        .schedule_after_deploy_check(hash, signature, meta_keys, tx);

    Ok(hash)
}

#[instrument]
async fn deploy_big_tx(
    bridge: &EvmBridge,
    payer: &solana_sdk::signature::Keypair,
    tx: &evm::Transaction,
) -> EvmResult<()> {
    let payer_pubkey = payer.pubkey();

    let storage = solana_sdk::signature::Keypair::new();
    let storage_pubkey = storage.pubkey();

    let signers = [payer, &storage];

    debug!("Create new storage {} for EVM tx {:?}", storage_pubkey, tx);

    let tx_bytes = if bridge.borsh_encoding {
        let mut tx_bytes = vec![];
        BorshSerialize::serialize(&tx, &mut tx_bytes)
            .map_err(|e| into_native_error(e, bridge.verbose_errors))?;
        tx_bytes
    } else {
        bincode::serialize(&tx).map_err(|e| into_native_error(e, bridge.verbose_errors))?
    };

    debug!(
        "Storage {} : tx bytes size = {}, chunks crc = {:#x}",
        storage_pubkey,
        tx_bytes.len(),
        TxChunks::new(tx_bytes.as_slice()).crc(),
    );

    let balance = bridge
        .rpc_client
        .get_minimum_balance_for_rent_exemption(tx_bytes.len())
        .await
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?;

    let (blockhash, _height) = bridge
        .rpc_client
        .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())
        .await
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?
        .value;

    let create_storage_ix = system_instruction::create_account(
        &payer_pubkey,
        &storage_pubkey,
        balance,
        tx_bytes.len() as u64,
        &solana_evm_loader_program::ID,
    );

    let allocate_storage_ix = if bridge.borsh_encoding {
        solana_evm_loader_program::big_tx_allocate(storage_pubkey, tx_bytes.len())
    } else {
        solana_evm_loader_program::big_tx_allocate_old(storage_pubkey, tx_bytes.len())
    };

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
    let rpc_send_cfg = RpcSendTransactionConfig {
        skip_preflight: !bridge.simulate,
        preflight_commitment: Some(CommitmentLevel::Processed),
        ..Default::default()
    };

    match bridge
        .rpc_client
        .send_and_confirm_transaction_with_config(&create_and_allocate_tx, rpc_send_cfg)
        .await
    {
        Ok(signature) => {
            debug!(
                "Create and allocate {} tx was done, signature = {:?}",
                storage_pubkey, signature
            )
        }
        Err(e) if e.already_exist_error() => {
            warn!(
                "Create and allocate tx processing return AlreadyExist error, trying to continue"
            );
        }
        Err(e) => {
            error!("Error create and allocate {} tx: {}", storage_pubkey, e);
            return Err(into_native_error(e, bridge.verbose_errors));
        }
    }

    let blockhash = bridge
        .rpc_client
        .get_new_blockhash(&blockhash)
        .await
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?;

    let write_data_txs: Vec<solana::Transaction> = tx_bytes
        // TODO: encapsulate
        .chunks(evm_state::TX_MTU)
        .enumerate()
        .map(|(i, chunk)| {
            if bridge.borsh_encoding {
                solana_evm_loader_program::big_tx_write(
                    storage_pubkey,
                    (i * evm_state::TX_MTU) as u64,
                    chunk.to_vec(),
                )
            } else {
                solana_evm_loader_program::big_tx_write_old(
                    storage_pubkey,
                    (i * evm_state::TX_MTU) as u64,
                    chunk.to_vec(),
                )
            }
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

    send_and_confirm_transactions(&bridge.rpc_client, write_data_txs, &signers)
        .await
        .map(|_| debug!("All write txs for storage {} was done", storage_pubkey))
        .map_err(|e| {
            error!("Error on write data to storage {}: {}", storage_pubkey, e);
            into_native_error(e, bridge.verbose_errors)
        })?;

    let (blockhash, _height) = bridge
        .rpc_client
        .get_latest_blockhash_with_commitment(CommitmentConfig::processed())
        .await
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?
        .value;

    let instructions = bridge.make_send_big_tx_instructions(tx, storage_pubkey, payer_pubkey);
    let execute_tx = solana::Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer_pubkey),
        &signers,
        blockhash,
    );

    debug!("Execute EVM transaction at storage {} ...", storage_pubkey);

    match bridge
        .rpc_client
        .send_transaction_with_config(&execute_tx, rpc_send_cfg)
        .await
    {
        Ok(signature) => {
            debug!(
                "Execute EVM tx at {} was done, signature = {:?}",
                storage_pubkey, signature
            )
        }
        Err(e) if e.already_exist_error() => {
            warn!("Executing EVM tx return AlreadyExist error, handle as executed.");
        }
        Err(e) => {
            error!("Execute EVM tx at {} failed: {}", storage_pubkey, e);
            return Err(from_client_error(e));
        }
    }

    Ok(())
}

/// Transactions, deployed with recoverable error result, can be deployed later
///
/// Example:
/// Error = ProxyRpcError {
///     source: Error {
///         code: ServerError(1002),
///         message: "Error in evm processing layer: Transaction nonce 1687 differs from nonce in state 1686",
///         data: Some(String("Transaction nonce 1687 differs from nonce in state 1686"))
///     }
/// }

fn is_recoverable_error(e: &evm_rpc::Error) -> bool {
    static RECOVERABLE_NONCE: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r#"Transaction nonce (?P<tx_nonce>\d+) differs from nonce in state (?P<state_nonce>\d+)"#).unwrap()
    });

    if let evm_rpc::Error::ProxyRpcError { source } = e {
        let caps = RECOVERABLE_NONCE.captures(&source.message);
        let caps = if let Some(caps) = caps {
            caps
        } else {
            return false;
        };
        let tx_nonce: U256 = caps.name("tx_nonce").unwrap().as_str().parse().unwrap();
        let state_nonce: U256 = caps.name("state_nonce").unwrap().as_str().parse().unwrap();
        if tx_nonce > state_nonce {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use txpool::Ready;

    type Pool = txpool::Pool<PooledTransaction, MyScoring, PoolListener>;

    use super::*;

    static SK1: [u8; 32] = [1u8; 32];
    static SK2: [u8; 32] = [2u8; 32];
    static SK3: [u8; 32] = [3u8; 32];

    /// Test clock used for unit-testing
    pub struct TestClock {
        now: u64,
    }

    impl Clock for Arc<Mutex<TestClock>> {
        fn now(&self) -> UnixTimeMs {
            self.lock().unwrap().now
        }
    }

    #[test]
    fn test_recoverable_nonce() {
        fn create_proxy_error(message: impl AsRef<str>) -> evm_rpc::Error {
            evm_rpc::Error::ProxyRpcError {
                source: jsonrpc_core::Error::invalid_params(message.as_ref().to_string()),
            }
        }

        let e = create_proxy_error("Transaction nonce 1687 differs from nonce in state 1686");
        assert!(is_recoverable_error(&e));

        let e = create_proxy_error("Transaction nonce 1 differs from nonce in state 0");
        assert!(is_recoverable_error(&e));

        let e = create_proxy_error(
            "HasPrefix:Transaction nonce 1687 differs from nonce in state 1686. And sufix",
        );
        assert!(is_recoverable_error(&e));

        let e = create_proxy_error("Any other text");
        assert!(!is_recoverable_error(&e));

        // outdated transaction
        let e = create_proxy_error("Transaction nonce 1685 differs from nonce in state 1686");
        assert!(!is_recoverable_error(&e));
    }

    #[test]
    fn test_pending_queuing() {
        let mut pool = Pool::new(PoolListener, MyScoring, Default::default());

        import(&mut pool, test_tx(100, 1000, "foo", &SK1));
        import(&mut pool, test_tx(100, 1600, "foo", &SK1));

        assert_eq!(pool.light_status().transaction_count, 1);

        assert_eq!(
            pool.pending(AlwaysReady, H256::zero())
                .next()
                .unwrap()
                .gas_price,
            1600.into()
        );

        import(&mut pool, test_tx(10, 1010, "bar1", &SK2));
        import(&mut pool, test_tx(12, 1012, "last_one", &SK2));
        import(&mut pool, test_tx(11, 1011, "bar2", &SK2));

        assert_eq!(
            pending_msgs(&pool, AlwaysReady),
            vec!["foo", "bar1", "bar2", "last_one"]
        );
    }

    #[test]
    fn test_readiness() {
        let mut pool = Pool::new(PoolListener, MyScoring, Default::default());

        import(&mut pool, test_tx(1, 1, "11", &SK1));
        import(&mut pool, test_tx(1, 100, "22", &SK2));
        import(&mut pool, test_tx(2, 100, "33", &SK1));
        import(&mut pool, test_tx(2, 1, "44", &SK2));

        fn only_high_price(tx: &PooledTransaction) -> Readiness {
            if tx.gas_price > 1.into() {
                Readiness::Ready
            } else {
                Readiness::Stale
            }
        }

        assert_eq!(pending_msgs(&pool, only_high_price), vec!["22", "33"])
    }

    #[test]
    fn test_delay_transaction_from_same_sender() {
        const TICK: Duration = std::time::Duration::from_millis(100);

        let test_clock = Arc::new(Mutex::new(TestClock { now: 0 }));

        let pool = EthPool::new(test_clock.clone());

        pool.import(test_tx(1, 100, "11", &SK1)).unwrap();
        pool.import(test_tx(2, 100, "22", &SK1)).unwrap();
        pool.import(test_tx(1, 100, "33", &SK2)).unwrap();
        pool.import(test_tx(2, 100, "44", &SK2)).unwrap();
        pool.import(test_tx(1, 100, "55", &SK3)).unwrap();

        let next = pool.pending().unwrap();
        assert_eq!(next.input, "11".as_bytes());
        assert_eq!(pool.strip_outdated(), (0, 0));

        pool.pause_processing(&next.sender, TICK);
        pool.remove(&next.hash);
        assert_eq!(pool.strip_outdated(), (1, 1));

        let next = pool.pending().unwrap();
        assert_eq!(next.input, "33".as_bytes());

        pool.pause_processing(&next.sender, TICK);
        pool.remove(&next.hash);
        assert_eq!(pool.strip_outdated(), (2, 2));

        let next = pool.pending().unwrap();
        assert_eq!(next.input, "55".as_bytes());

        pool.pause_processing(&next.sender, TICK);
        pool.remove(&next.hash);
        assert_eq!(pool.strip_outdated(), (3, 3));

        assert!(pool.pending().is_none());

        test_clock.lock().unwrap().now += TICK.as_millis() as u64;

        assert!(pool.pending().is_some());

        let next = pool.pending().unwrap();
        assert_eq!(next.input, "22".as_bytes());
        assert_eq!(pool.strip_outdated(), (3, 0));
    }

    #[test]
    fn test_removing_replaced_transaction() {
        let pool = EthPool::new(SystemClock);

        pool.import(test_tx(1, 100, "11", &SK1)).unwrap();

        assert_eq!(
            pool.pool.lock().unwrap().light_status().transaction_count,
            1
        );

        let next = pool.pending().unwrap();

        pool.import(test_tx(1, 9000, "11", &SK1)).unwrap();

        assert_eq!(
            pool.pool.lock().unwrap().light_status().transaction_count,
            1
        );
        assert!(pool.remove(&next.hash).is_none());

        let removed = pool.remove_by_nonce(&next.sender, next.nonce);

        assert!(removed.is_some());
        assert_eq!(
            pool.pool.lock().unwrap().light_status().transaction_count,
            0
        );
    }

    fn test_tx(nonce: u32, gas_price: u32, msg: &str, secret_key: &[u8; 32]) -> PooledTransaction {
        let tx_create = evm::UnsignedTransaction {
            nonce: nonce.into(),
            gas_price: gas_price.into(),
            gas_limit: 30000000.into(),
            action: evm::TransactionAction::Create,
            value: 0.into(),
            input: msg.as_bytes().to_vec(),
        };

        let secret_key: evm_state::SecretKey = evm::SecretKey::from_slice(secret_key).unwrap();

        let (tx, _) = mpsc::channel(1);
        PooledTransaction::new(tx_create.sign(&secret_key, Some(111)), HashSet::new(), tx).unwrap()
    }

    fn import(pool: &mut Pool, tx: PooledTransaction) {
        pool.import(tx, &MyScoring).unwrap();
    }

    fn pending_msgs<R>(pool: &Pool, ready: R) -> Vec<String>
    where
        R: Ready<PooledTransaction>,
    {
        pool.pending(ready, H256::zero())
            .map(|tx| String::from_utf8(tx.input.clone()).unwrap())
            .collect()
    }
}
