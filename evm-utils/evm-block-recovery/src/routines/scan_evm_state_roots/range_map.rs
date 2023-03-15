use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use evm_state::BlockNum;
use rangemap::RangeMap;

#[derive(Debug, Clone)]
pub struct MasterRange {
    file_path: PathBuf,
    inner: Arc<Mutex<RangeMap<BlockNum, String>>>,
}

impl MasterRange {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let ser = std::fs::read_to_string(file_path.as_ref())?;
        let i: RangeMap<BlockNum, String> = serde_json::from_str(&ser)?;
        log::info!("MasterRange::new {:#?}", i);
        Ok(Self {
            inner: Arc::new(Mutex::new(i)),
            file_path: file_path.as_ref().to_owned(),
        })
    }
    
    pub fn update(&self, index: BlockNum, value: String) -> std::io::Result<()> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.insert(index..index+1, value);
        Self::persist(inner, self.file_path.clone())?;
        Ok(())
    }
    fn persist(inner: MutexGuard<RangeMap<BlockNum, String>>, file_path: PathBuf) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&*inner).unwrap();
        std::fs::write(file_path, content.as_bytes())?;
        drop(inner);
        Ok(())
    }
}