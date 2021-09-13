use std::{sync::Arc, thread::JoinHandle};

use evm_state::{Address, H256};
use log::*;
use txpool::{Listener, Pool, Readiness, Scoring, ShouldReplace, VerifiedTransaction};
use solana_evm_loader_program::scope::evm;

use crate::EvmBridge;

pub type EthPool = Pool<PooledTransaction, MyScoring, MyListener>;

#[derive(Debug)]
pub struct PooledTransaction {
    inner: evm::Transaction,
    sender: Address,
    hash: H256
}

impl From<evm::Transaction> for PooledTransaction {
    fn from(transaction: evm::Transaction) -> Self {
        let hash = transaction.tx_id_hash();
        let sender = transaction.caller().unwrap_or_default(); // TODO: we need to know sender's address

        Self {
            inner: transaction,
            sender,
            hash
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

#[derive(Debug)]
pub struct MyScoring;

impl Scoring<PooledTransaction> for MyScoring {
    type Score = H256;

    type Event = ();

    fn compare(&self, old: &PooledTransaction, other: &PooledTransaction) -> std::cmp::Ordering {
        old.inner.cmp(&other.inner) // TODO: implement
    }

    fn choose(&self, _old: &PooledTransaction, _new: &PooledTransaction) -> txpool::scoring::Choice {
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

pub struct MyListener;
impl<T> Listener<T> for MyListener {
    fn added(&mut self, _tx: &std::sync::Arc<T>, _old: Option<&std::sync::Arc<T>>) {
        println!("MyListener::added")
    }

    fn rejected<H: std::fmt::Debug + std::fmt::LowerHex>(&mut self, _tx: &std::sync::Arc<T>, _reason: &txpool::Error<H>) {
        println!("MyListener::rejected")
    }

    fn dropped(&mut self, _tx: &std::sync::Arc<T>, _by: Option<&T>) {
        println!("MyListener::dropped")
    }

    fn invalid(&mut self, _tx: &std::sync::Arc<T>) {
        println!("MyListener::invalid")
    }

    fn canceled(&mut self, _tx: &std::sync::Arc<T>) {
        println!("MyListener::canceled")
    }

    fn culled(&mut self, _tx: &std::sync::Arc<T>) {
        println!("MyListener::culled")
    }
}

impl ShouldReplace<PooledTransaction> for MyScoring {
    fn should_replace(
        &self,
        _old: &txpool::ReplaceTransaction<PooledTransaction>,
        _new: &txpool::ReplaceTransaction<PooledTransaction>
    ) -> txpool::scoring::Choice {
        txpool::scoring::Choice::RejectNew // TODO: implement
    }
}

pub fn create_pool_worker(bridge: Arc<EvmBridge>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            let mut data = bridge.pool.lock().unwrap();
            let tx = data.pending(|tx: &PooledTransaction| Readiness::Ready, H256::zero()).next();

            std::mem::drop(data);

            if let Some(tx) = tx {
                info!("pool worker is doing some work: tx.hash = {:?}", &tx.hash);
                
                let successfully_processed = true;
            
                if (successfully_processed) {
                    bridge.pool.lock().unwrap().remove(tx.hash(), false).unwrap();
                }
            } else {
                info!("pool worker is idling...")
            }

            std::thread::sleep(std::time::Duration::from_millis(3500));
        }
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pool() {
        let mut pool = EthPool::new(MyListener, MyScoring, Options::default());
    
        let evm_tx = evm::Transaction {
            nonce: 1.into(),
            gas_price: 222.into(),
            gas_limit: 333.into(),
            action: evm::TransactionAction::Create,
            value: 123.into(),
            signature: evm::TransactionSignature { 
                r: H256::zero(),
                s: H256::zero(),
                v: 0u64
            },
            input: vec![1, 2, 3],
        };
    
        let pooled_tx = PooledTransaction::from(evm_tx);
    
        pool.import(pooled_tx, &mut MyScoring).unwrap();
    }
}