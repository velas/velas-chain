use std::borrow::{Borrow, BorrowMut};

use snafu::{ensure, Snafu};

pub struct TxChunks<T>(T);

#[derive(Debug, Snafu)]
#[snafu(context(suffix(false)))]
pub enum Error {
    #[snafu(display("Expected storage size {}, but available {}", expected, actual))]
    MismatchedSizes { actual: usize, expected: usize },
    #[snafu(display("Storage out of bound: index {} > data size {}", attempt, data_size))]
    OutOfBound { data_size: usize, attempt: usize },
}

type Result<T> = std::result::Result<T, Error>;

impl<T> TxChunks<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }
}

impl<T: Borrow<[u8]>> TxChunks<T> {
    pub fn crc(&self) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(self.0.borrow());
        hasher.finalize()
    }
}

impl<T: BorrowMut<[u8]>> TxChunks<T> {
    pub fn init(&mut self, size: usize) -> Result<()> {
        let bytes = self.0.borrow_mut();

        ensure!(
            size == bytes.len(),
            MismatchedSizes {
                actual: bytes.len(),
                expected: size,
            }
        );

        for elem in bytes.iter_mut() {
            *elem = 0;
        }

        Ok(())
    }

    pub fn push(&mut self, offset: usize, data: impl AsRef<[u8]>) -> Result<()> {
        let bytes = self.0.borrow_mut();
        let data = data.as_ref();

        ensure!(
            (offset.saturating_add(data.len())) <= bytes.len(),
            OutOfBound {
                data_size: bytes.len(),
                attempt: offset + data.len()
            }
        );

        bytes[offset..(offset + data.len())].copy_from_slice(data);

        Ok(())
    }

    pub fn take(self) -> Vec<u8> {
        self.0.borrow().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[quickcheck]
    fn it_handles_enumerated_chunks_as_expected(data: Vec<u8>) {
        const BATCH_SIZE: usize = 42;
        let origin = TxChunks::new(data.as_slice());

        let data_size = data.len();
        let mut chunks = TxChunks::new(vec![0; data_size]);
        chunks.init(data_size).unwrap();
        data.chunks(BATCH_SIZE)
            .enumerate()
            .for_each(|(i, chunk)| chunks.push(i * BATCH_SIZE, chunk).unwrap());

        assert_eq!(origin.crc(), chunks.crc());
        assert_eq!(data, chunks.take());
    }
}
