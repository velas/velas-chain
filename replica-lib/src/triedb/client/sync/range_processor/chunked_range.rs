use evm_state::BlockNum;

pub(super) struct ChunkedRange {
    pub range: std::ops::Range<BlockNum>,
    pub chunk_size: BlockNum,
}

impl Iterator for ChunkedRange {
    type Item = std::ops::Range<BlockNum>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }

        let start = self.range.start;
        let next = std::cmp::min(self.range.start + self.chunk_size, self.range.end);

        self.range.start = next;
        Some(start..next)
    }
}
