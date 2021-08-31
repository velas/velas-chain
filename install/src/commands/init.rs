use super::*;
use crate::{
    build_env,
    config::{Config, ExplicitRelease},
    defaults,
    github::{GithubReleases, Version},
};
use reqwest::Url;
use serde::Deserialize;
use solana_sdk::{
    hash::{Hash, Hasher},
    pubkey::Pubkey,
};
use std::{
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};
use tempfile::TempDir;

#[derive(Debug, Clone, Copy)]
pub enum Mode {
    Init,
    Update,
}

#[derive(Deserialize, Debug)]
pub struct ReleaseVersion {
    pub target: String,
    pub commit: String,
    channel: String,
}

// TODO: simplify this
fn config_bloat(matches: &clap::ArgMatches, mode: Mode) -> Result<Config, String> {
    let config_file = matches.value_of("config_file").unwrap();

    match mode {
        Mode::Init => {
            let data_dir = matches.value_of("data_dir").unwrap();
            let explicit_release = matches
                .value_of("explicit_release")
                .map(|release| match release {
                    "stable" => ExplicitRelease::Channel("stable".to_string()),
                    "edge" => ExplicitRelease::Channel("edge".to_string()),
                    semver => ExplicitRelease::Semver(semver.to_string()),
                })
                .ok_or(format!(
                    "Please specify the release to install for {}. See --help for more",
                    build_env::TARGET
                ))?;

            // Write new config file only if different, so that running |solana-install init|
            // repeatedly doesn't unnecessarily re-download
            let mut current_config = Config::load(config_file).unwrap_or_default();
            current_config.current_update_manifest = None;
            let config = Config::new(
                data_dir,
                defaults::JSON_RPC_URL,
                &Pubkey::default(),
                Some(explicit_release),
            );
            if current_config != config {
                config.save(config_file)?;
            }

            Ok(config)
        }
        Mode::Update => Ok(Config::load(config_file).unwrap_or_default()),
    }
}

pub fn command_init(matches: &clap::ArgMatches, mode: Mode) -> Result<(), String> {
    let config_file = matches.value_of("config_file").unwrap();
    let no_modify_path = matches.is_present("no_modify_path");
    let is_exact_version = matches.is_present("exact");

    let mut config = config_bloat(matches, mode)?;

    let wanted_version = match config.explicit_release {
        Some(ExplicitRelease::Semver(ref ver)) => match (mode, is_exact_version) {
            (Mode::Init, true) => Version::Semver(format!("={}", ver)),
            (Mode::Init, false) => Version::Semver(format!("^{}", ver)),
            (Mode::Update, _) => Version::Semver(format!("~{}", ver)),
        },
        Some(ExplicitRelease::Channel(ref chan)) if chan == "edge" => Version::LatestEdge,
        Some(ExplicitRelease::Channel(ref chan)) if chan == "stable" => Version::LatestStable,
        Some(ExplicitRelease::Channel(ref chan)) => {
            return Err(format!("Unknown channel: {}", chan))
        }
        None => Version::LatestStable, // TODO: match arm used for initialization by rpc in original tool
    };

    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(&format!("{}Checking for updates...", LOOKING_GLASS));

    let releases = GithubReleases::load_from_github().map_err(|e| e.to_string())?;

    let target_release = releases.find_version(&wanted_version).ok_or(format!(
        "Unable to find requested release: {:?}",
        config.explicit_release
    ))?;

    let updated_version = target_release.semver.to_string();

    progress_bar.finish_and_clear();

    config.explicit_release = Some(ExplicitRelease::Semver(updated_version.clone()));

    let release_dir = config.release_dir(&updated_version);
    let download_url_and_sha256 = if release_dir.exists() {
        // Release already present in the cache
        None
    } else {
        Some((target_release.download_url(build_env::TARGET), None))
    };

    // ==========================
    // load stuff begin
    // ==========================
    if let Some((download_url, archive_sha256)) = download_url_and_sha256 {
        let (_temp_dir, temp_archive, _temp_archive_sha256) =
            download_to_temp(&download_url, archive_sha256.as_ref())
                .map_err(|err| format!("Unable to download {}: {}", download_url, err))?;
        extract_release_archive(&temp_archive, &release_dir).map_err(|err| {
            format!(
                "Unable to extract {:?} to {:?}: {}",
                temp_archive, release_dir, err
            )
        })?;
    }

    let release_target = load_release_target(&release_dir).map_err(|err| {
        format!(
            "Unable to load release target from {:?}: {}",
            release_dir, err
        )
    })?;

    if release_target != build_env::TARGET {
        return Err(format!("Incompatible update target: {}", release_target));
    }

    // Trigger an update to the modification time for `release_dir`
    {
        let path = &release_dir.join(".touch");
        let _ = fs::OpenOptions::new().create(true).write(true).open(path);
        let _ = fs::remove_file(path);
    }

    let _ = fs::remove_dir_all(config.active_release_dir());
    symlink_dir(
        release_dir.join("velas-release"),
        config.active_release_dir(),
    )
    .map_err(|err| {
        format!(
            "Unable to symlink {:?} to {:?}: {}",
            release_dir,
            config.active_release_dir(),
            err
        )
    })?;

    config.save(config_file)?;
    gc(config_file)?;

    match mode {
        Mode::Init => println!(
            "  {}{}",
            SPARKLE,
            style(format!("{} initialized", updated_version)).bold()
        ),
        Mode::Update => println!(
            "  {}{}",
            SPARKLE,
            style(format!("Update successful to {}", updated_version)).bold()
        ),
    }
    // ==========================
    // load stuff end
    // ==========================

    // ==========================
    // $PATH routines begin
    // ==========================
    let path_modified = if !no_modify_path {
        add_to_path(config.active_release_bin_dir().to_str().unwrap())
    } else {
        false
    };

    if !path_modified && !no_modify_path {
        check_env_path_for_bin_dir(&config);
    }
    // ==========================
    // $PATH routines end
    // ==========================

    Ok(())
}

#[cfg(windows)]
fn add_to_path(new_path: &str) -> bool {
    use std::ptr;
    use winapi::shared::minwindef::*;
    use winapi::um::winuser::{
        SendMessageTimeoutA, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::{RegKey, RegValue};

    let old_path = if let Some(s) =
        get_windows_path_var().unwrap_or_else(|err| panic!("Unable to get PATH: {}", err))
    {
        s
    } else {
        return false;
    };

    if !old_path.contains(&new_path) {
        let mut new_path = new_path.to_string();
        if !old_path.is_empty() {
            new_path.push_str(";");
            new_path.push_str(&old_path);
        }

        let root = RegKey::predef(HKEY_CURRENT_USER);
        let environment = root
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            .unwrap_or_else(|err| panic!("Unable to open HKEY_CURRENT_USER\\Environment: {}", err));

        let reg_value = RegValue {
            bytes: string_to_winreg_bytes(&new_path),
            vtype: RegType::REG_EXPAND_SZ,
        };

        environment
            .set_raw_value("PATH", &reg_value)
            .unwrap_or_else(|err| {
                panic!("Unable set HKEY_CURRENT_USER\\Environment\\PATH: {}", err)
            });

        // Tell other processes to update their environment
        unsafe {
            SendMessageTimeoutA(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0 as WPARAM,
                "Environment\0".as_ptr() as LPARAM,
                SMTO_ABORTIFHUNG,
                5000,
                ptr::null_mut(),
            );
        }
    }

    println!(
        "\n{}\n  {}\n\n{}",
        style("The HKEY_CURRENT_USER/Environment/PATH registry key has been modified to include:").bold(),
        new_path,
        style("Future applications will automatically have the correct environment, but you may need to restart your current shell.").bold()
    );
    true
}

#[cfg(unix)]
fn add_to_path(new_path: &str) -> bool {
    let shell_export_string = format!(r#"export PATH="{}:$PATH""#, new_path);
    let mut modified_rcfiles = false;

    // Look for sh, bash, and zsh rc files
    let mut rcfiles = vec![dirs_next::home_dir().map(|p| p.join(".profile"))];
    if let Ok(shell) = std::env::var("SHELL") {
        if shell.contains("zsh") {
            let zdotdir = std::env::var("ZDOTDIR")
                .ok()
                .map(PathBuf::from)
                .or_else(dirs_next::home_dir);
            let zprofile = zdotdir.map(|p| p.join(".zprofile"));
            rcfiles.push(zprofile);
        }
    }

    if let Some(bash_profile) = dirs_next::home_dir().map(|p| p.join(".bash_profile")) {
        // Only update .bash_profile if it exists because creating .bash_profile
        // will cause .profile to not be read
        if bash_profile.exists() {
            rcfiles.push(Some(bash_profile));
        }
    }
    let rcfiles = rcfiles.into_iter().filter_map(|f| f.filter(|f| f.exists()));

    // For each rc file, append a PATH entry if not already present
    for rcfile in rcfiles {
        if !rcfile.exists() {
            continue;
        }

        fn read_file(path: &Path) -> io::Result<String> {
            let mut file = fs::OpenOptions::new().read(true).open(path)?;
            let mut contents = String::new();
            io::Read::read_to_string(&mut file, &mut contents)?;
            Ok(contents)
        }

        match read_file(&rcfile) {
            Err(err) => {
                println!("Unable to read {:?}: {}", rcfile, err);
            }
            Ok(contents) => {
                if !contents.contains(&shell_export_string) {
                    println!(
                        "Adding {} to {}",
                        style(&shell_export_string).italic(),
                        style(rcfile.to_str().unwrap()).bold()
                    );

                    fn append_file(dest: &Path, line: &str) -> io::Result<()> {
                        use std::io::Write;
                        let mut dest_file = fs::OpenOptions::new()
                            .write(true)
                            .append(true)
                            .create(true)
                            .open(dest)?;

                        writeln!(&mut dest_file, "{}", line)?;

                        dest_file.sync_data()?;

                        Ok(())
                    }
                    append_file(&rcfile, &shell_export_string).unwrap_or_else(|err| {
                        format!("Unable to append to {:?}: {}", rcfile, err);
                    });
                    modified_rcfiles = true;
                }
            }
        }
    }

    if modified_rcfiles {
        println!(
            "\n{}\n  {}\n",
            style("Close and reopen your terminal to apply the PATH changes or run the following in your existing shell:").bold().blue(),
            shell_export_string
       );
    }

    modified_rcfiles
}

#[cfg(windows)]
fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    std::os::windows::fs::symlink_dir(src, dst)
}

#[cfg(not(windows))]
fn symlink_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> std::io::Result<()> {
    std::os::unix::fs::symlink(src, dst)
}

/// Bug the user if active_release_bin_dir is not in their PATH
fn check_env_path_for_bin_dir(config: &Config) {
    use std::env;

    let bin_dir = config
        .active_release_bin_dir()
        .canonicalize()
        .unwrap_or_default();
    let found = match env::var_os("PATH") {
        Some(paths) => env::split_paths(&paths).any(|path| {
            if let Ok(path) = path.canonicalize() {
                if path == bin_dir {
                    return true;
                }
            }
            false
        }),
        None => false,
    };

    if !found {
        println!(
            "\nPlease update your PATH environment variable to include the solana programs:\n    PATH=\"{}:$PATH\"\n",
            config.active_release_bin_dir().to_str().unwrap()
        );
    }
}

// Get the windows PATH variable out of the registry as a String. If
// this returns None then the PATH variable is not Unicode and we
// should not mess with it.
#[cfg(windows)]
fn get_windows_path_var() -> Result<Option<String>, String> {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    let root = RegKey::predef(HKEY_CURRENT_USER);
    let environment = root
        .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
        .map_err(|err| format!("Unable to open HKEY_CURRENT_USER\\Environment: {}", err))?;

    let reg_value = environment.get_raw_value("PATH");
    match reg_value {
        Ok(val) => {
            if let Some(s) = string_from_winreg_value(&val) {
                Ok(Some(s))
            } else {
                println!("the registry key HKEY_CURRENT_USER\\Environment\\PATH does not contain valid Unicode. Not modifying the PATH variable");
                return Ok(None);
            }
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Ok(Some(String::new())),
        Err(e) => Err(e.to_string()),
    }
}

/// Encodes a UTF-8 string as a null-terminated UCS-2 string in bytes
#[cfg(windows)]
pub fn string_to_winreg_bytes(s: &str) -> Vec<u8> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStrExt;
    let v: Vec<_> = OsString::from(format!("{}\x00", s)).encode_wide().collect();
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2).to_vec() }
}

// This is used to decode the value of HKCU\Environment\PATH. If that
// key is not Unicode (or not REG_SZ | REG_EXPAND_SZ) then this
// returns null.  The winreg library itself does a lossy unicode
// conversion.
#[cfg(windows)]
pub fn string_from_winreg_value(val: &winreg::RegValue) -> Option<String> {
    use std::slice;
    use winreg::enums::RegType;

    match val.vtype {
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => {
            // Copied from winreg
            let words = unsafe {
                slice::from_raw_parts(val.bytes.as_ptr() as *const u16, val.bytes.len() / 2)
            };
            let mut s = if let Ok(s) = String::from_utf16(words) {
                s
            } else {
                return None;
            };
            while s.ends_with('\u{0}') {
                s.pop();
            }
            Some(s)
        }
        _ => None,
    }
}

/// Downloads a file at `url` to a temporary location.  If `expected_sha256` is
/// Some(_), produce an error if the SHA256 of the file contents doesn't match.
///
/// Returns a tuple consisting of:
/// * TempDir - drop this value to clean up the temporary location
/// * PathBuf - path to the downloaded file (within `TempDir`)
/// * String  - SHA256 of the release
///
fn download_to_temp(
    url: &str,
    expected_sha256: Option<&Hash>,
) -> Result<(TempDir, PathBuf, Hash), Box<dyn std::error::Error>> {
    fn sha256_file_digest<P: AsRef<Path>>(path: P) -> Result<Hash, Box<dyn std::error::Error>> {
        let input = File::open(path)?;
        let mut reader = BufReader::new(input);
        let mut hasher = Hasher::default();

        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.hash(&buffer[..count]);
        }
        Ok(hasher.result())
    }

    let url = Url::parse(url).map_err(|err| format!("Unable to parse {}: {}", url, err))?;

    let temp_dir = TempDir::new()?;
    let temp_file = temp_dir.path().join("download");

    let client = reqwest::blocking::Client::new();

    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(&format!("{}Downloading...", TRUCK));

    let response = client.get(url.as_str()).send()?;
    let download_size = {
        response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|content_length| content_length.to_str().ok())
            .and_then(|content_length| content_length.parse().ok())
            .unwrap_or(0)
    };

    progress_bar.set_length(download_size);
    progress_bar.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green}{wide_msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .progress_chars("=> "),
    );
    progress_bar.set_message(&format!("{}Downloading", TRUCK));

    struct DownloadProgress<R> {
        progress_bar: ProgressBar,
        response: R,
    }

    impl<R: Read> Read for DownloadProgress<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.response.read(buf).map(|n| {
                self.progress_bar.inc(n as u64);
                n
            })
        }
    }

    let mut source = DownloadProgress {
        progress_bar,
        response,
    };

    let mut file = File::create(&temp_file)?;
    std::io::copy(&mut source, &mut file)?;

    let temp_file_sha256 = sha256_file_digest(&temp_file)
        .map_err(|err| format!("Unable to hash {:?}: {}", temp_file, err))?;

    if expected_sha256.is_some() && expected_sha256 != Some(&temp_file_sha256) {
        return Err(io::Error::new(io::ErrorKind::Other, "Incorrect hash").into());
    }

    source.progress_bar.finish_and_clear();
    Ok((temp_dir, temp_file, temp_file_sha256))
}

/// Extracts the release archive into the specified directory
fn extract_release_archive(
    archive: &Path,
    extract_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use bzip2::bufread::BzDecoder;
    use tar::Archive;

    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(&format!("{}Extracting...", PACKAGE));

    if extract_dir.exists() {
        let _ = fs::remove_dir_all(&extract_dir);
    }

    let tmp_extract_dir = extract_dir.with_file_name("tmp-extract");
    if tmp_extract_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
    }
    fs::create_dir_all(&tmp_extract_dir)?;

    let tar_bz2 = File::open(archive)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let mut release = Archive::new(tar);
    release.unpack(&tmp_extract_dir)?;

    fs::rename(&tmp_extract_dir, extract_dir)?;

    progress_bar.finish_and_clear();
    Ok(())
}

/// Reads the supported TARGET triple for the given release
fn load_release_target(release_dir: &Path) -> Result<String, String> {
    let mut version_yml = PathBuf::from(release_dir);
    version_yml.push("velas-release");
    version_yml.push("version.yml");

    let version = load_release_version(&version_yml)?;
    Ok(version.target)
}

fn load_release_version(version_yml: &Path) -> Result<ReleaseVersion, String> {
    let file = File::open(&version_yml)
        .map_err(|err| format!("Unable to open {:?}: {:?}", version_yml, err))?;
    let version: ReleaseVersion = serde_yaml::from_reader(file)
        .map_err(|err| format!("Unable to parse {:?}: {:?}", version_yml, err))?;
    Ok(version)
}

pub fn gc(config_file: &str) -> Result<(), String> {
    let config = Config::load(config_file)?;

    let entries = fs::read_dir(&config.releases_dir)
        .map_err(|err| format!("Unable to read {}: {}", config.releases_dir.display(), err))?;

    let mut releases = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .metadata()
                .ok()
                .map(|metadata| (entry.path(), metadata))
        })
        .filter(|(_release_path, metadata)| metadata.is_dir())
        .filter_map(|(release_path, metadata)| {
            metadata
                .modified()
                .ok()
                .map(|modified_time| (release_path, modified_time))
        })
        .collect::<Vec<_>>();
    releases.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap()); // order by newest releases

    const MAX_CACHE_LEN: usize = 5;
    if releases.len() > MAX_CACHE_LEN {
        let old_releases = releases.split_off(MAX_CACHE_LEN);

        if !old_releases.is_empty() {
            let progress_bar = new_spinner_progress_bar();
            progress_bar.set_length(old_releases.len() as u64);
            progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green}{wide_msg} [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .progress_chars("=> "),
            );
            progress_bar.set_message(&format!("{}Removing old releases", RECYCLING));
            for (release, _modified_type) in old_releases {
                progress_bar.inc(1);
                let _ = fs::remove_dir_all(&release);
            }
            progress_bar.finish_and_clear();
        }
    }

    Ok(())
}
