#![allow(clippy::integer_arithmetic)]
#[macro_use]
extern crate lazy_static;

use clap::{crate_description, crate_name, App, AppSettings, Arg, SubCommand};

use crate::commands::{init, versions};

mod build_env;
mod commands;
mod config;
mod defaults;
mod github;

pub fn main() -> Result<(), String> {
    solana_logger::setup();

    let matches = App::new(crate_name!())
        .about(crate_description!())
        .version(solana_version::version!())
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg({
            let arg = Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("Configuration file to use");
            match *defaults::CONFIG_PATH {
                Some(ref config_file) => arg.default_value(&config_file),
                None => arg.required(true),
            }
        })
        .subcommand(
            SubCommand::with_name("init")
                .about("Initializes a new installation")
                .setting(AppSettings::DisableVersion)
                .arg({
                    let arg = Arg::with_name("data_dir")
                        .short("d")
                        .long("data-dir")
                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("Directory to store install data");
                    match *defaults::DATA_DIR {
                        Some(ref data_dir) => arg.default_value(&data_dir),
                        None => arg,
                    }
                })
                .arg(
                    Arg::with_name("no_modify_path")
                        .long("no-modify-path")
                        .help("Don't configure the PATH environment variable"),
                )
                .arg(
                    Arg::with_name("explicit_release")
                        .value_name("release")
                        .index(1)
                        .validator(release_validator)
                        .help(r#"The release version or channel to install (e.g., "stable", "edge", "1.0.5")"#),
                )
                .arg(
                    Arg::with_name("exact")
                        .value_name("exact")
                        .short("e")
                        .long("exact")
                        .takes_value(false)
                        .help("Don't search for the most recent compatible version")
                ),
        )
        .subcommand(
            SubCommand::with_name("update")
                .about("Checks for an update, and if available downloads and applies it")
                .setting(AppSettings::DisableVersion),
        )
        .subcommand(
            SubCommand::with_name("versions")
                .about("Shows available versions of velas software")
                .setting(AppSettings::DisableVersion),
        )
        .get_matches();

    match matches.subcommand() {
        ("init", Some(matches)) => init::command_init(&matches, init::Mode::Init),
        ("update", Some(matches)) => init::command_init(&matches, init::Mode::Update),
        ("versions", Some(_matches)) => versions::command_versions(),
        _ => unreachable!(),
    }
}

pub fn main_init() -> Result<(), String> {
    let matches = App::new("velas-install-init")
        .about("Initializes a new installation")
        .version(solana_version::version!())
        .arg({
            let arg = Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("PATH")
                .takes_value(true)
                .help("Configuration file to use");
            match *defaults::CONFIG_PATH {
                Some(ref config_file) => arg.default_value(&config_file),
                None => arg.required(true),
            }
        })
        .arg({
            let arg = Arg::with_name("data_dir")
                .short("d")
                .long("data-dir")
                .value_name("PATH")
                .takes_value(true)
                .required(true)
                .help("Directory to store install data");
            match *defaults::DATA_DIR {
                Some(ref data_dir) => arg.default_value(&data_dir),
                None => arg,
            }
        })
        .arg(
            Arg::with_name("no_modify_path")
                .long("no-modify-path")
                .help("Don't configure the PATH environment variable"),
        )
        .arg(
            Arg::with_name("explicit_release")
                .value_name("release")
                .index(1)
                .validator(release_validator)
                .help("The release version or channel to install"),
        )
        .get_matches();

    commands::init::command_init(&matches, init::Mode::Init)
}

fn release_validator(release: String) -> Result<(), String> {
    match release.as_str() {
        "stable" => Ok(()),
        "edge" => Ok(()),
        semver if semver::Version::parse(semver).is_ok() => Ok(()),
        unknown => Err(unknown.to_string()),
    }
}
