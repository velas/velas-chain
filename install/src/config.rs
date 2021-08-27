use {
    serde::{Deserialize, Serialize},
    solana_sdk::{hash::Hash, pubkey::Pubkey},
    std::fs::{create_dir_all, File},
    std::io::{self, Write},
    std::path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ExplicitRelease {
    Semver(String),
    Channel(String),
}

/// Information required to download and apply a given update
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct UpdateManifest {
    pub timestamp_secs: u64, // When the release was deployed in seconds since UNIX EPOCH
    pub download_url: String, // Download URL to the release tar.bz2
    pub download_sha256: Hash, // SHA256 digest of the release tar.bz2 file
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
pub struct Config {
    pub json_rpc_url: String,
    pub update_manifest_pubkey: Pubkey,
    pub current_update_manifest: Option<UpdateManifest>,
    pub update_poll_secs: u64,
    pub explicit_release: Option<ExplicitRelease>,
    pub releases_dir: PathBuf,
    active_release_dir: PathBuf,
}

impl Config {
    pub fn new(
        data_dir: &str,
        json_rpc_url: &str,
        update_manifest_pubkey: &Pubkey,
        explicit_release: Option<ExplicitRelease>,
    ) -> Self {
        Self {
            json_rpc_url: json_rpc_url.to_string(),
            update_manifest_pubkey: *update_manifest_pubkey,
            current_update_manifest: None,
            update_poll_secs: 60 * 60, // check for updates once an hour
            explicit_release,
            releases_dir: PathBuf::from(data_dir).join("releases"),
            active_release_dir: PathBuf::from(data_dir).join("active_release"),
        }
    }

    fn _load(config_path: &str) -> Result<Self, io::Error> {
        let file = File::open(config_path.to_string())?;
        let config = serde_yaml::from_reader(file)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{:?}", err)))?;
        Ok(config)
    }

    pub fn load(config_path: &str) -> Result<Self, String> {
        Self::_load(config_path).map_err(|err| format!("Unable to load {}: {:?}", config_path, err))
    }

    fn _save(&self, config_path: &str) -> Result<(), io::Error> {
        let serialized = serde_yaml::to_string(self)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{:?}", err)))?;

        if let Some(outdir) = Path::new(&config_path).parent() {
            create_dir_all(outdir)?;
        }
        let mut file = File::create(config_path)?;
        file.write_all(&serialized.into_bytes())?;

        Ok(())
    }

    pub fn save(&self, config_path: &str) -> Result<(), String> {
        self._save(config_path)
            .map_err(|err| format!("Unable to save {}: {:?}", config_path, err))
    }

    pub fn active_release_dir(&self) -> &PathBuf {
        &self.active_release_dir
    }

    pub fn active_release_bin_dir(&self) -> PathBuf {
        self.active_release_dir.join("bin")
    }

    pub fn release_dir(&self, release_id: &str) -> PathBuf {
        self.releases_dir.join(release_id)
    }
}
