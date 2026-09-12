use {
    super::PooledTransaction,
    log::*,
    std::{
        fmt::{Debug, LowerHex},
        sync::Arc,
    },
    tokio::runtime::Handle,
    txpool::Listener,
};

#[derive(Debug)]
pub struct PoolListener;
impl PoolListener {
    fn notify_tx_removed(&self, tx: &Arc<PooledTransaction>) {
        if let Ok(handle) = Handle::try_current() {
            let tx = tx.clone();
            handle.spawn(async move {
                if let Err(e) = tx.send(Err(evm_rpc::Error::TransactionRemoved {})).await {
                    warn!(
                        "PoolListener failed to async notify tx sender about transaction, error: {}",
                        e
                    )
                }
            });
        } else if let Err(e) = tx.blocking_send(Err(evm_rpc::Error::TransactionRemoved {})) {
            warn!(
                "PoolListener failed to sync notify tx sender about transaction, error: {}",
                e
            )
        }
    }
}

impl Listener<PooledTransaction> for PoolListener {
    fn added(&mut self, tx: &Arc<PooledTransaction>, old: Option<&Arc<PooledTransaction>>) {
        debug!("PoolListener::added: tx = {:?}, old = {:?}", tx, old);

        if let Some(old) = old {
            info!(
                "Transaction {} replaced with transaction {}",
                old.hash, tx.hash
            );
            self.notify_tx_removed(old)
        }
    }

    fn rejected<H: Debug + LowerHex>(
        &mut self,
        tx: &Arc<PooledTransaction>,
        reason: &txpool::Error<H>,
    ) {
        debug!("PoolListener::rejected: tx = {:?}, reason = {}", tx, reason);
        self.notify_tx_removed(tx)
    }

    fn dropped(&mut self, tx: &Arc<PooledTransaction>, by: Option<&PooledTransaction>) {
        debug!("PoolListener::dropped: tx = {:?}, by = {:?}", tx, by);
        self.notify_tx_removed(tx)
    }

    fn invalid(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::invalid: tx = {:?}", tx);
        self.notify_tx_removed(tx)
    }

    fn canceled(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::canceled: tx = {:?}", tx);
        self.notify_tx_removed(tx)
    }

    fn culled(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::culled: tx = {:?}", tx);
        self.notify_tx_removed(tx)
    }
}
