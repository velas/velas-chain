use std::{collections::HashSet, sync::Arc, thread::JoinHandle};

use evm_rpc::{error::into_native_error, Bytes, Error, Hex, RPCTransaction};
use evm_state::{Address, TransactionAction, H256};
use log::*;
use serde_json::json;
use solana_client::{rpc_config::RpcSendTransactionConfig, rpc_request::RpcRequest};
use solana_evm_loader_program::{
    scope::{evm, solana},
    tx_chunks::TxChunks,
};
use solana_sdk::{
    commitment_config::{CommitmentConfig, CommitmentLevel},
    instruction::AccountMeta,
    message::Message,
    pubkey::Pubkey,
    signer::Signer,
    system_instruction,
};
use txpool::{NoopListener, Pool, Readiness, Scoring, ShouldReplace, VerifiedTransaction};

use crate::{from_client_error, send_and_confirm_transactions, EvmBridge, EvmResult};

pub type EthPool = Pool<PooledTransaction, MyScoring, NoopListener>;

#[derive(Debug, Clone)]
pub struct PooledTransaction {
    pub inner: evm::Transaction,
    pub meta_keys: HashSet<Pubkey>,
    sender: Address,
    hash: H256,
}

impl PooledTransaction {
    pub fn new(
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
        })
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

#[derive(Debug)]
pub struct MyScoring;

impl Scoring<PooledTransaction> for MyScoring {
    type Score = H256;

    type Event = ();

    fn compare(&self, old: &PooledTransaction, other: &PooledTransaction) -> std::cmp::Ordering {
        old.inner.cmp(&other.inner) // TODO: implement
    }

    fn choose(
        &self,
        _old: &PooledTransaction,
        _new: &PooledTransaction,
    ) -> txpool::scoring::Choice {
        txpool::scoring::Choice::RejectNew // TODO: implement
    }

    fn update_scores(
        &self,
        _txs: &[txpool::Transaction<PooledTransaction>],
        _scores: &mut [Self::Score],
        _change: txpool::scoring::Change<Self::Event>,
    ) {
        () // TODO: implement
    }
}

impl ShouldReplace<PooledTransaction> for MyScoring {
    fn should_replace(
        &self,
        _old: &txpool::ReplaceTransaction<PooledTransaction>,
        _new: &txpool::ReplaceTransaction<PooledTransaction>,
    ) -> txpool::scoring::Choice {
        txpool::scoring::Choice::RejectNew // TODO: implement
    }
}

pub fn create_pool_worker(bridge: Arc<EvmBridge>) -> JoinHandle<()> {
    std::thread::spawn(move || loop {
        let tx = {
            let pool = bridge.pool.lock().unwrap();
            pool.pending(|_tx: &PooledTransaction| Readiness::Ready, H256::zero())
                .next()
        };

        if let Some(tx) = tx {
            let tx = (*tx).clone();
            let hash = tx.hash;
            info!("pool worker is doing some work: tx.hash = {:?}", &hash);
            match process_tx(bridge.clone(), tx) {
                Ok(hash) => {
                    bridge.pool.lock().unwrap().remove(&hash.0, false).unwrap();
                }
                Err(_e) => warn!(
                    "Something went wrong in tx pricessing with hash = {:?}",
                    &hash
                ),
            }
        } else {
            trace!("pool worker is idling...");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })
}

fn process_tx(bridge: Arc<EvmBridge>, tx: PooledTransaction) -> EvmResult<Hex<H256>> {
    let PooledTransaction {
        inner,
        mut meta_keys,
        sender,
        hash,
    } = tx;
    let tx = inner;

    let bytes = bincode::serialize(&tx).unwrap();

    let rpc_tx = RPCTransaction::from_transaction(tx.clone().into())?;

    if bridge.simulate {
        // Try simulate transaction execution
        bridge
            .rpc_client
            .send::<Bytes>(RpcRequest::EthCall, json!([rpc_tx, "latest"]))
            .map_err(from_client_error)?;
    }

    if bytes.len() > evm::TX_MTU {
        warn!("BIG TX DETECTED");
        debug!("Sending tx = {}, by chunks", hash);
        match deploy_big_tx(&bridge, &bridge.key, &tx) {
            Ok(_tx) => {
                warn!("BIG TX DEPLOYED");
                return Ok(Hex(hash));
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

    let mut ix =
        solana_evm_loader_program::send_raw_tx(bridge.key.pubkey(), tx, Some(bridge.key.pubkey()));

    // Add meta accounts as additional arguments
    for account in meta_keys {
        ix.accounts.push(AccountMeta::new(account, false))
    }

    let message = Message::new(&[ix], Some(&bridge.key.pubkey()));
    let mut send_raw_tx: solana::Transaction = solana::Transaction::new_unsigned(message);

    debug!("Getting block hash");
    let (blockhash, _fee_calculator, _) = bridge
        .rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
        .map(|response| response.value)
        .map_err(|e| Error::NativeRpcError {
            details: String::from("Failed to get recent blockhash"),
            source: e.into(),
            verbose: bridge.verbose_errors,
        })?;

    send_raw_tx.sign(&[&bridge.key], blockhash);
    debug!("Sending tx = {:?}", send_raw_tx);

    bridge
        .rpc_client
        .send_transaction_with_config(
            &send_raw_tx,
            RpcSendTransactionConfig {
                preflight_commitment: Some(CommitmentLevel::Processed),
                skip_preflight: !bridge.simulate,
                ..Default::default()
            },
        )
        .map(|_| Hex(hash))
        .map_err(from_client_error)
}

fn deploy_big_tx(
    bridge: &EvmBridge,
    payer: &solana_sdk::signature::Keypair,
    tx: &evm::Transaction,
) -> EvmResult<()> {
    let payer_pubkey = payer.pubkey();

    let storage = solana_sdk::signature::Keypair::new();
    let storage_pubkey = storage.pubkey();

    let signers = [payer, &storage];

    debug!("Create new storage {} for EVM tx {:?}", storage_pubkey, tx);

    let tx_bytes =
        bincode::serialize(&tx).map_err(|e| into_native_error(e, bridge.verbose_errors))?;

    debug!(
        "Storage {} : tx bytes size = {}, chunks crc = {:#x}",
        storage_pubkey,
        tx_bytes.len(),
        TxChunks::new(tx_bytes.as_slice()).crc(),
    );

    let balance = bridge
        .rpc_client
        .get_minimum_balance_for_rent_exemption(tx_bytes.len())
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?;

    let (blockhash, _, _) = bridge
        .rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::finalized())
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?
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

    bridge
        .rpc_client
        .send_and_confirm_transaction(&create_and_allocate_tx)
        .map(|signature| {
            debug!(
                "Create and allocate {} tx was done, signature = {:?}",
                storage_pubkey, signature
            )
        })
        .map_err(|e| {
            error!("Error create and allocate {} tx: {:?}", storage_pubkey, e);
            into_native_error(e, bridge.verbose_errors)
        })?;

    let (blockhash, _) = bridge
        .rpc_client
        .get_new_blockhash(&blockhash)
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?;

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

    send_and_confirm_transactions(&bridge.rpc_client, write_data_txs, &signers)
        .map(|_| debug!("All write txs for storage {} was done", storage_pubkey))
        .map_err(|e| {
            error!("Error on write data to storage {}: {:?}", storage_pubkey, e);
            into_native_error(e, bridge.verbose_errors)
        })?;

    let (blockhash, _, _) = bridge
        .rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::processed())
        .map_err(|e| into_native_error(e, bridge.verbose_errors))?
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

    bridge
        .rpc_client
        .send_transaction_with_config(&execute_tx, rpc_send_cfg)
        .map(|signature| {
            debug!(
                "Execute EVM tx at {} was done, signature = {:?}",
                storage_pubkey, signature
            )
        })
        .map_err(|e| {
            error!("Execute EVM tx at {} failed: {:?}", storage_pubkey, e);
            from_client_error(e)
        })?;

    // TODO: here we can transfer back lamports and delete storage

    Ok(())
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn test_pool() {
//         let mut pool = EthPool::new(MyListener, MyScoring, Options::default());

//         let evm_tx = evm::Transaction {
//             nonce: 1.into(),
//             gas_price: 222.into(),
//             gas_limit: 333.into(),
//             action: evm::TransactionAction::Create,
//             value: 123.into(),
//             signature: evm::TransactionSignature {
//                 r: H256::zero(),
//                 s: H256::zero(),
//                 v: 0u64
//             },
//             input: vec![1, 2, 3],
//         };

//         let pooled_tx = PooledTransaction::from(evm_tx);

//         pool.import(pooled_tx, &mut MyScoring).unwrap();
//     }
// }
