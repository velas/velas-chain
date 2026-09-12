use {
    super::{Error, Storage as Primary, StorageSecondary, H256},
    std::path::PathBuf,
};

#[derive(Clone)]
pub enum Storage {
    Primary(Primary),
    Secondary(StorageSecondary),
}
impl Storage {
    pub fn new(evm_state_path: &PathBuf, secondary: bool, gc: bool) -> Result<Storage, Error> {
        let storage = if secondary {
            let storage = StorageSecondary::open_secondary_persistent(
                evm_state_path,
                gc, // enable gc
            )?;
            Storage::Secondary(storage)
        } else {
            let storage = Primary::open_persistent(
                evm_state_path,
                gc, // enable gc
            )?;
            Storage::Primary(storage)
        };

        Ok(storage)
    }

    pub fn check_node(&self, key: H256) -> Result<bool, Error> {
        let maybe_bytes = match self {
            Self::Primary(ref storage) => storage.db().get(key),

            Self::Secondary(ref storage) => storage.db().get(key),
        };

        let bytes = maybe_bytes?.is_some();
        Ok(bytes)
    }
}
