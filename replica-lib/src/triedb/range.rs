use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use evm_state::BlockNum;
use serde::{Deserialize, Serialize};

use super::error::RangeInitError;

/// Empty:
/// {
///   "range": {
///     "start": 0,
///     "end": 0
///   }
/// }
///
/// Non-empty:
/// {
///   "range": {
///     "start": 3197919,
///     "end": 3197932
///   }
/// }
#[derive(Debug, Serialize, Deserialize)]
struct Inner {
    range: std::ops::Range<BlockNum>,
}

impl Inner {
    fn update(&mut self, index: BlockNum) -> bool {
        
        if self.range.is_empty() {
            self.range = index..index+1;
            true
        } else if index == self.range.start - 1  {
            self.range = (self.range.start-1)..self.range.end;
            true
        } else  if index == self.range.end  {
            self.range = self.range.start..(self.range.end + 1);
            true
        } else {
            false
        }
    }

}

#[derive(Debug, Clone)]
pub struct RangeJSON {
    update_count: usize,
    file_path: PathBuf,
    inner: Arc<Mutex<Inner>>,
}



impl RangeJSON {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, RangeInitError> {
        let ser = std::fs::read_to_string(file_path.as_ref())?;
        let i: Inner = serde_json::from_str(&ser)?;
        log::info!("MasterRange::new {:#?}", i);
        Ok(Self {
            inner: Arc::new(Mutex::new(i)),
            file_path: file_path.as_ref().to_owned(),
            update_count: 0,
        })
    }
    pub fn get(&self) -> std::ops::Range<BlockNum> {
        let res = self.inner.lock().expect("lock poisoned").range.clone();
        res
    }
    

    pub fn update(&self, index: BlockNum) -> std::io::Result<()> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let changed = inner.update(index);
        if changed {
            Self::persist(inner, self.file_path.clone())?;
            
        }
        Ok(())
    }
    fn persist(inner: MutexGuard<Inner>, file_path: PathBuf) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&*inner).unwrap();
        std::fs::write(file_path, content.as_bytes())?;
        drop(inner);
        Ok(())
    }
}
