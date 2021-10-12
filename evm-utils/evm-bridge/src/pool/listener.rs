use std::fmt::{Debug, LowerHex};
use std::sync::Arc;

use log::debug;
use txpool::Listener;

use super::PooledTransaction;

pub struct PoolListener;

impl Listener<PooledTransaction> for PoolListener {
    fn added(&mut self, tx: &Arc<PooledTransaction>, old: Option<&Arc<PooledTransaction>>) {
        debug!("PoolListener::added: tx = {:?}, old = {:?}", tx, old);
    }

    fn rejected<H: Debug + LowerHex>(
        &mut self,
        tx: &Arc<PooledTransaction>,
        reason: &txpool::Error<H>,
    ) {
        debug!(
            "PoolListener::rejected: tx = {:?}, reason = {:?}",
            tx, reason
        );
    }

    fn dropped(&mut self, tx: &Arc<PooledTransaction>, by: Option<&PooledTransaction>) {
        debug!("PoolListener::dropped: tx = {:?}, by = {:?}", tx, by);
    }

    fn invalid(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::invalid: tx = {:?}", tx);
    }

    fn canceled(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::canceled: tx = {:?}", tx);
    }

    fn culled(&mut self, tx: &Arc<PooledTransaction>) {
        debug!("PoolListener::culled: tx = {:?}", tx);
    }
}
