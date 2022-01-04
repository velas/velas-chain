use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, Builder, JoinHandle},
    time::Duration,
};

use evm_state::{ChangedState, Storage, H256};

pub type EvmStateRecorderReceiver = Receiver<(H256, ChangedState)>;
pub type EvmStateRecorderSender = Sender<(H256, ChangedState)>;

pub struct EvmStateRecorderService {
    thread_hdl: JoinHandle<()>,
}

impl EvmStateRecorderService {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        evm_recorder_receiver: EvmStateRecorderReceiver,
        archive: Storage,
        exit: &Arc<AtomicBool>,
    ) -> Self {
        let exit = exit.clone();
        let thread_hdl = Builder::new()
            .name("evm-block-writer".to_string())
            .spawn(move || loop {
                if exit.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(RecvTimeoutError::Disconnected) =
                    Self::write_evm_record(&archive, &evm_recorder_receiver)
                {
                    break;
                }
            })
            .unwrap();
        Self { thread_hdl }
    }

    fn write_evm_record(
        storage: &Storage,
        evm_records_receiver: &EvmStateRecorderReceiver,
    ) -> Result<(), RecvTimeoutError> {
        // TODO: use changed nodes as state_updates, instead of changed accounts (to avoid recalculation of hashes)

        let (state_root, state_updates) =
            evm_records_receiver.recv_timeout(Duration::from_secs(1))?;
        if !storage.check_root_exist(state_root) {
            warn!(
                "Root not found in archive, skip writing root:{} , updates_len:{:?}",
                state_root,
                state_updates.len()
            );
            return Ok(());
        }
        storage.flush_changes(state_root, state_updates);

        Ok(())
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
