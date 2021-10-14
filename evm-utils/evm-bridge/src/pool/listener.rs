use std::fmt::{Debug, LowerHex};
use std::sync::Arc;

use log::*;
use txpool::Listener;

use super::PooledTransaction;

pub struct PoolListener;

impl Listener<PooledTransaction> for PoolListener {
    fn added(&mut self, tx: &Arc<PooledTransaction>, old: Option<&Arc<PooledTransaction>>) {
        trace!("PoolListener::added: tx = {:?}, old = {:?}", tx, old);

        if let Some(old) = old {
            info!(
                "Transaction {} replaced with transaction {}",
                old.hash, tx.hash
            );
            old.hash_sender
                .blocking_send(Err(evm_rpc::Error::TransactionReplaced {}))
                .unwrap();
        }
    }

    fn rejected<H: Debug + LowerHex>(
        &mut self,
        tx: &Arc<PooledTransaction>,
        reason: &txpool::Error<H>,
    ) {
        trace!(
            "PoolListener::rejected: tx = {:?}, reason = {:?}",
            tx,
            reason
        );
    }

    fn dropped(&mut self, tx: &Arc<PooledTransaction>, by: Option<&PooledTransaction>) {
        trace!("PoolListener::dropped: tx = {:?}, by = {:?}", tx, by);
    }

    fn invalid(&mut self, tx: &Arc<PooledTransaction>) {
        trace!("PoolListener::invalid: tx = {:?}", tx);
    }

    fn canceled(&mut self, tx: &Arc<PooledTransaction>) {
        trace!("PoolListener::canceled: tx = {:?}", tx);
    }

    fn culled(&mut self, tx: &Arc<PooledTransaction>) {
        trace!("PoolListener::culled: tx = {:?}", tx);
    }
}

// pool.import(test_tx(1, 42, "11", &SK1)).unwrap();
// pool.import(test_tx(1, 9000, "11", &SK1)).unwrap();

// PoolListener::added:
//   tx = PooledTransaction {
//     inner: Transaction {
//       nonce: 1,
//       gas_price: 42,
//       gas_limit: 30000000,
//       action: Create,
//       value: 0,
//       signature: TransactionSignature {
//         v: 257,
//         r: 0x2e677f66ca9da7276c9c22419daacec43bef4e09d6e0c7a52618823f9cc36fe1,
//         s: 0x76e5d225aa8855a095daa5e0d4b24ac3912ca7f73e83a6d9adb5989e5b5229af
//       },
//       input: [49, 49]
//     },
//     meta_keys: {},
//     sender: 0x1a642f0e3c3af545e7acbd38b07251b3990914f1,
//     hash: 0x3c44e9dff342d80ba6cfed312772e21cc655eecbfbf0fc438e094745325e4c81,
//     hash_sender: Sender {
//       chan: Tx {
//         inner: Chan {
//           tx: Tx {
//             block_tail: 0x7ff24703d000,
//             tail_position: 0
//           },
//           semaphore: (Semaphore { permits: 1 }, 1),
//           rx_waker: AtomicWaker,
//           tx_count: 1,
//           rx_fields: "..."
//         }
//       }
//     }
//   },
//   old = None
//
// PoolListener::added:
//   tx = PooledTransaction {
//     inner: Transaction {
//       nonce: 1,
//       gas_price: 9000,
//       gas_limit: 30000000,
//       action: Create,
//       value: 0,
//       signature: TransactionSignature {
//         v: 257,
//         r: 0x5f0e66124325cf61419ec0c3eb7bb7889c13de3f8c04fd20ef0ad2655961bb1b,
//         s: 0x2290a1d90070b84a4a4961d4756967250574cd584fd3f2308311a88442a5bc1f
//       },
//       input: [49, 49]
//     },
//     meta_keys: {},
//     sender: 0x1a642f0e3c3af545e7acbd38b07251b3990914f1,
//     hash: 0x17f17989730b26bba8486a78da69e834fe0a881a1e0eda4e452f83742e8b5555,
//     hash_sender: Sender {
//       chan: Tx {
//         inner: Chan {
//           tx: Tx {
//             block_tail: 0x7ff24703e000,
//             tail_position: 0
//           },
//           semaphore: (Semaphore { permits: 1 }, 1),
//           rx_waker: AtomicWaker,
//           tx_count: 1,
//           rx_fields: "..."
//         }
//       }
//     }
//   },
//   old = Some(
//     PooledTransaction {
//       inner: Transaction {
//         nonce: 1,
//         gas_price: 42,
//         gas_limit: 30000000,
//         action: Create,
//         value: 0,
//         signature: TransactionSignature {
//           v: 257,
//           r: 0x2e677f66ca9da7276c9c22419daacec43bef4e09d6e0c7a52618823f9cc36fe1,
//           s: 0x76e5d225aa8855a095daa5e0d4b24ac3912ca7f73e83a6d9adb5989e5b5229af
//         },
//         input: [49, 49]
//       },
//       meta_keys: {},
//       sender: 0x1a642f0e3c3af545e7acbd38b07251b3990914f1,
//       hash: 0x3c44e9dff342d80ba6cfed312772e21cc655eecbfbf0fc438e094745325e4c81,
//       hash_sender: Sender {
//         chan: Tx {
//           inner: Chan {
//             tx: Tx {
//               block_tail: 0x7ff24703d000,
//               tail_position: 0
//             },
//             semaphore: (Semaphore { permits: 1 }, 1),
//             rx_waker: AtomicWaker,
//             tx_count: 1,
//             rx_fields: "..."
//           }
//         }
//       }
//     }
//   )
