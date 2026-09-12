use std::sync::{Arc, Mutex};

use evm_state::{BlockNum, H256};

#[derive(Clone)]
pub struct KickStartPoint {
    data: Arc<Mutex<Entry>>,
}

#[derive(Clone, Copy)]
pub struct Entry {
    pub height: BlockNum,
    pub hash: H256,
}

impl KickStartPoint {
    pub fn new(height: BlockNum, hash: H256) -> Self {
        let entry = Entry { height, hash };

        Self {
            data: Arc::new(Mutex::new(entry)),
        }
    }

    pub fn get(&self) -> Entry {
        *self.data.lock().expect("poison")
    }

    pub fn update(&self, height: BlockNum, hash: H256) {
        let mut lock = self.data.lock().expect("poison");
        if height > lock.height {
            lock.height = height;
            lock.hash = hash;
        }
    }
}
