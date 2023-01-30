use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use evm_state::BlockNum;
use serde::{Deserialize, Serialize};

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
struct MasterRangeInner {
    range: std::ops::Range<BlockNum>,
}

impl MasterRangeInner {
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
pub struct MasterRange {
    file_path: PathBuf,
    inner: Arc<Mutex<MasterRangeInner>>,
}

#[derive(Debug, Clone)]
pub struct Advance {
    pub start: BlockNum,
    added_range: std::ops::Range<BlockNum>,
    backwards: bool,
}

impl Advance {
    pub fn next_biderectional(&mut self) -> Option<BlockNum> {
        if !self.backwards {
            self.added_range.next()
        } else {
            self.added_range.next_back()
        }
        
    }
    pub fn is_empty(&self) -> bool {
        self.added_range.is_empty()
    }
    
}

impl MasterRange {
    pub fn new(file_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let ser = std::fs::read_to_string(file_path.as_ref())?;
        let i: MasterRangeInner = serde_json::from_str(&ser)?;
        log::info!("MasterRange::new {:#?}", i);
        Ok(Self {
            inner: Arc::new(Mutex::new(i)),
            file_path: file_path.as_ref().to_owned(),
        })
    }
    pub fn get(&self) -> std::ops::Range<BlockNum> {
        let res = self.inner.lock().expect("lock poisoned").range.clone();
        res
    }
    pub fn compute_advance(&self, max_chunk: u64, offer: std::ops::Range<BlockNum>) -> Advance {
        let r = self.get();
        if r.is_empty() {

            let end = std::cmp::min(offer.start + max_chunk, offer.end);
            return Advance {
                start: 0,
                added_range: offer.start..end,
                backwards: false,
            };
        }
        let next = r.end;
        // if client range is non-empty, to ensure, that server can advance client's
        // range forward, server's range must contain both last element and the one after
        // it; otherwise the possible gapless advance is empty

        if offer.contains(&(next - 1)) && offer.contains(&next) {
            let end = std::cmp::min(next + max_chunk, offer.end);
            return Advance {
                start: next - 1,
                added_range: next..end,
                backwards: false,
            };
        }
        if offer.start < r.start {
            let prev = r.start - 1;
            let start = std::cmp::max(prev - max_chunk, offer.start);
            if offer.contains(&r.start) && offer.contains(&prev) {
                return Advance {
                    start: r.start,
                    added_range: start..r.start,
                    backwards: true,
                };
            }
            
        }
        Advance {
            start: 0,
            added_range: 0..0,
            backwards: false,
        }
    }

    pub fn update(&self, index: BlockNum) -> std::io::Result<()> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let changed = inner.update(index);
        if changed {
            Self::persist(inner, self.file_path.clone())?;
            
        }
        Ok(())
    }
    fn persist(inner: MutexGuard<MasterRangeInner>, file_path: PathBuf) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&*inner).unwrap();
        std::fs::write(file_path, content.as_bytes())?;
        drop(inner);
        Ok(())
    }
}
