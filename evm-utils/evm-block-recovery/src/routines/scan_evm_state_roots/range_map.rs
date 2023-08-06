use {
    evm_state::BlockNum,
    rangemap::RangeMap,
    std::path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct MasterRange {
    file_path: PathBuf,
    inner: RangeMap<BlockNum, String>,
}

impl MasterRange {
    pub fn new(file_path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let ser = std::fs::read_to_string(file_path.as_ref())?;
        let i: RangeMap<BlockNum, String> = serde_json::from_str(&ser)?;
        log::info!("MasterRange::new {:#?}", i);
        Ok(Self {
            inner: i,
            file_path: file_path.as_ref().to_owned(),
        })
    }

    pub fn update(&mut self, index: BlockNum, value: String) -> std::io::Result<()> {
        self.inner.insert(index..index + 1, value);
        self.persist(self.file_path.clone())?;
        Ok(())
    }
    fn persist(&self, file_path: PathBuf) -> std::io::Result<()> {
        let content = serde_json::to_string_pretty(&self.inner).unwrap();
        std::fs::write(file_path, content.as_bytes())?;
        Ok(())
    }
}
