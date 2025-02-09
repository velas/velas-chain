use {
    super::EvmArchive,
    crossbeam_channel::{Receiver, RecvTimeoutError, Sender},
    evm_state::{Block, ChangedState, Storage, H256},
    solana_program_runtime::evm_executor_context::ChainID,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self, Builder, JoinHandle},
        time::Duration,
    },
};

pub struct RecorderEntry {
    pub chain: Option<ChainID>,
    pub state_root: H256,
    pub state_updates: ChangedState,
    pub block: Block,
}

pub enum EvmArchiveManagerRequest {
    RecordEntry(RecorderEntry),
    // TODO: rewrite to avoid sending storage between threads and outside of archive.
    SystemRequestArchiveStorage(Sender<Storage>),
}

pub type EvmArchiveManagerReceiver = Receiver<EvmArchiveManagerRequest>;
pub type EvmArchiveManagerSender = Sender<EvmArchiveManagerRequest>;

pub struct EvmArchiveManagerService {
    thread_hdl: JoinHandle<()>,
}

impl EvmArchiveManagerService {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        evm_recorder_receiver: EvmArchiveManagerReceiver,
        archive: EvmArchive,
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
        archive: &EvmArchive,
        evm_records_receiver: &EvmArchiveManagerReceiver,
    ) -> Result<(), RecvTimeoutError> {
        // TODO: use changed nodes as state_updates, instead of changed accounts (to avoid recalculation of hashes)

        let entry = evm_records_receiver.recv_timeout(Duration::from_secs(1))?;
        match entry {
            EvmArchiveManagerRequest::RecordEntry(entry) => {
                archive.write_evm_record(entry);
            }
            EvmArchiveManagerRequest::SystemRequestArchiveStorage(sender) => {
                sender.send(archive.get_storage()).unwrap();
            }
        };

        Ok(())
    }

    pub fn join(self) -> thread::Result<()> {
        self.thread_hdl.join()
    }
}
