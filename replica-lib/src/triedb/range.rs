use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use evm_state::BlockNum;
use rangemap::RangeSet;

use super::{
    error::{evm_height, RangeJsonInitError},
    ReadRange, WriteRange,
};
use async_trait::async_trait;
mod diff;

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
#[derive(Debug, Clone)]
struct Inner {
    update_count: usize,
    coarse: std::ops::Range<BlockNum>,
    fine: Option<RangeSet<BlockNum>>,
}

impl Inner {
    fn deserialize_self(coarse: &str, fine: Option<&str>) -> Result<Self, serde_json::Error> {
        let coarse: std::ops::Range<BlockNum> = serde_json::from_str(coarse)?;
        let fine: Option<RangeSet<BlockNum>> = match fine {
            None => None,
            Some(fine) => Some(serde_json::from_str(fine)?),
        };
        Ok(Self {
            update_count: 0,
            coarse,
            fine,
        })
    }

    fn serialize_self(&self) -> Result<(String, Option<String>), serde_json::Error> {
        let coarse_str = serde_json::to_string_pretty(&self.coarse)?;
        let fine_str = match self.fine {
            None => None,
            Some(ref fine) => Some(serde_json::to_string_pretty(fine)?),
        };
        Ok((coarse_str, fine_str))
    }

    fn update_coarse(&mut self, index: BlockNum) {
        if self.coarse.is_empty() {
            self.coarse = index..index + 1;
            return;
        }
        if self.coarse.contains(&index) {
            return;
        }
        if index >= self.coarse.end {
            self.coarse.end = index + 1;
        } else {
            self.coarse.start = index;
        }
    }
    fn update_fine(&mut self, index: BlockNum) {
        if let Some(ref mut fine) = self.fine {
            fine.insert(index..index + 1);
        }
    }

    fn update(&mut self, index: BlockNum) {
        self.update_coarse(index);
        self.update_fine(index);
    }
}

#[derive(Debug, Clone)]
pub struct RangeJSON {
    coarse_file_path: PathBuf,
    fine_file_path: Option<PathBuf>,
    inner: Arc<Mutex<Inner>>,
}

const FLUSH_EVERY: usize = 100;

impl RangeJSON {
    pub fn new<P: AsRef<Path>>(
        coarse_file_path: P,
        fine_file_path: Option<P>,
    ) -> Result<Self, RangeJsonInitError> {
        let coarse_str = std::fs::read_to_string(coarse_file_path.as_ref())?;
        let fine_str = match fine_file_path {
            Some(ref fine_file_path) => Some(std::fs::read_to_string(fine_file_path.as_ref())?),
            None => None,
        };
        let ranges: Inner = Inner::deserialize_self(&coarse_str, fine_str.as_deref())?;
        log::info!("RangeJSON::new {:#?}", ranges);
        Ok(Self {
            inner: Arc::new(Mutex::new(ranges)),
            coarse_file_path: coarse_file_path.as_ref().to_owned(),
            fine_file_path: fine_file_path.map(|path| path.as_ref().to_owned()),
        })
    }

    fn flush_internal(&self, inner: MutexGuard<Inner>) -> std::io::Result<()> {
        let (coarse, fine) = inner
            .serialize_self()
            .expect("serialization of a struct can never fail, can it");
        std::fs::write(&self.coarse_file_path, coarse.as_bytes())?;
        if let Some(ref fine_file_path) = self.fine_file_path {
            std::fs::write(
                fine_file_path,
                fine.expect("invariant broken: non null if fine_file_path is non-null")
                    .as_bytes(),
            )?;
        }
        Ok(())
    }
}

#[async_trait]
impl ReadRange for RangeJSON {
    async fn get(&self) -> Result<std::ops::Range<BlockNum>, evm_height::Error> {
        let res = self.inner.lock().expect("lock poisoned").coarse.clone();
        Ok(res)
    }
}
#[async_trait]
impl WriteRange for RangeJSON {
    fn update(&self, index: BlockNum) -> std::io::Result<()> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.update(index);
        inner.update_count += 1;
        if inner.update_count % FLUSH_EVERY == 0 {
            self.flush_internal(inner)?;
        }
        Ok(())
    }

    fn flush(&self) -> std::io::Result<()> {
        let inner = self.inner.lock().expect("lock poisoned");
        self.flush_internal(inner)?;
        Ok(())
    }
}
