use std::num::ParseIntError;

use clap::ArgMatches;
use evm_state::BlockNum;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum RangeSource {
    JSON { file: Option<String> },
    SolanaBlockstore,
    BigtableBlockstore,
}

#[derive(Debug, Clone)]
pub enum HeightIndexSource {
    SolanaBlockstore,
    BigtableBlockstore,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub range_source: RangeSource,
    pub height_index_source: HeightIndexSource,
    pub bigtable_length_hint: BlockNum,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("no range source specified")]
    NoRangeSource,
    #[error("no evm height index source specified")]
    NoHeightIndex,
    #[error("parse int error {0}")]
    ParseInt(#[from] ParseIntError),
    #[error("invalid option {0}, class {1}")]
    InvalidOption(String, String),
}
const MAINNET_HINT_DEFAULT: &str = "62800000";

impl TryFrom<(&str, Option<&str>)> for RangeSource {
    type Error = ParseError;
    fn try_from(value: (&str, Option<&str>)) -> Result<Self, Self::Error> {
        match value.0 {
            "json" => Ok(RangeSource::JSON {
                file: value.1.map(|str| str.to_string()),
            }),
            "bigtable" => Ok(RangeSource::BigtableBlockstore),
            "solana_blockstore" => Ok(RangeSource::SolanaBlockstore),
            _ => Err(ParseError::InvalidOption(
                value.0.to_string(),
                "range".to_string(),
            )),
        }
    }
}

impl TryFrom<&str> for HeightIndexSource {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "bigtable" => Ok(HeightIndexSource::BigtableBlockstore),
            "solana_blockstore" => Ok(HeightIndexSource::SolanaBlockstore),
            _ => Err(ParseError::InvalidOption(
                value.to_string(),
                "height_index".to_string(),
            )),
        }
    }
}

impl Config {
    pub fn parse_standalone(matches: &ArgMatches) -> Result<Self, ParseError> {
        let range_source = matches
            .value_of("range_source")
            .ok_or(ParseError::NoRangeSource)?;
        let range_file = matches.value_of("range_file");
        let height_index_source = matches
            .value_of("height_index_source")
            .ok_or(ParseError::NoRangeSource)?;
        let bigtable_length_hint: BlockNum = matches
            .value_of("bigtable_length_hint")
            .unwrap_or(MAINNET_HINT_DEFAULT)
            .parse()?;

        let res = Self {
            range_source: (range_source, range_file).try_into()?,
            height_index_source: height_index_source.try_into()?,
            bigtable_length_hint,
        };
        Ok(res)
    }

    pub fn parse_validator(matches: &ArgMatches) -> Result<Self, ParseError> {
        let range_source = matches
            .value_of("evm_height_index_source")
            .ok_or(ParseError::NoRangeSource)?;
        let range_file = None;
        let height_index_source = matches
            .value_of("evm_height_index_source")
            .ok_or(ParseError::NoRangeSource)?;
        let bigtable_length_hint: BlockNum = matches
            .value_of("bigtable_evm_blockstore_length_hint")
            .unwrap_or(MAINNET_HINT_DEFAULT)
            .parse()?;

        let res = Self {
            range_source: (range_source, range_file).try_into()?,
            height_index_source: height_index_source.try_into()?,
            bigtable_length_hint,
        };
        Ok(res)
    }
}
