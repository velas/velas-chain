use {
    crate::Hardfork,
    evm_rpc::{Bytes, Hex},
    evm_state::{H160, H256, U256},
    serde::{Deserialize, Serialize},
    solana_sdk::pubkey::Pubkey,
    std::{
        collections::{BTreeMap, BTreeSet},
        fmt::Display,
        str::FromStr,
        u64,
    },
};
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    #[serde(default)]
    pub code: Bytes,
    #[serde(default)]
    pub storage: BTreeMap<H256, H256>,
    #[serde(
        deserialize_with = "HexOrNum::deserialize_with",
        serialize_with = "HexOrNum::seralize_with"
    )]
    pub balance: U256,
    #[serde(default)]
    pub nonce: Hex<u64>,
}

// Genesis config used in geth.
// Order preserved.
// Commented out fields that is not used in the current implementation.
// Added fields that are used in the current implementation.
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub config: ChainConfig,
    // These fields are represents block header, which currently not used.
    // pub nonce: u64,
    // pub timestamp: u64,
    // pub extra_data: Vec<u8>,
    // pub gas_limit: u64,
    // pub difficulty: U256,
    // pub mix_hash: H256,
    // pub coinbase: H256,
    pub alloc: GenesisAlloc,
    #[serde(default)]
    pub auxiliary: OptionalConfig,
    // These fields are used for consensus tests.
    // pub number: u64,
    // pub gas_used: u64,
    // pub parent_hash: H256,
    // pub base_fee: U256,
    // pub excess_blob_gas: u64,
    // pub blob_gas_used: u64,
}
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAlloc(pub BTreeMap<H160, Account>);

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainConfig {
    pub chain_id: ChainID,

    #[serde(default)]
    pub start_hardfork: Hardfork,

    #[serde(default)]
    pub network_name: String,

    #[serde(default)]
    pub token_name: String,

    #[serde(default)]
    pub gas_price: U256, // TODO: min_gas_price?

    #[serde(default)]
    pub whitelisted: BTreeSet<Pubkey>,
    // Subchain administrator is only abble to configure evm-runtime.
    // Most of consensus fields irrelevant to evm bytecode implementation.
    // So commented out.

    // pub homestead_block: u64,
    // pub dao_fork_block: u64,
    // pub dao_fork_support: bool,
    // pub eip150_block: u64,
    // pub eip155_block: u64,
    // pub eip158_block: u64,
    // pub byzantium_block: u64,
    // pub constantinople_block: u64,
    // pub petersburg_block: u64,
    // pub istanbul_block: u64,

    // pub muir_glacier_block: u64,
    // pub berlin_block: u64,
    // pub london_block: u64,
    // pub arrow_glacier_block: u64,
    // pub gray_glacier_block: u64,
    // pub merge_netsplit_block: u64,
    // pub shanghai_time: u64,
    // pub cancun_time: u64,
    // pub prague_time: u64,
    // pub verkle_time: u64,
}
#[derive(Default, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionalConfig {
    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token_symbol: String,

    #[serde(default)]
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rpc_url: String,
}

#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub struct ChainID(u64);
impl ChainID {
    pub fn new(value: u64) -> Self {
        ChainID(value)
    }
}

impl From<u64> for ChainID {
    fn from(value: u64) -> Self {
        ChainID(value)
    }
}

impl From<ChainID> for u64 {
    fn from(value: ChainID) -> Self {
        value.0
    }
}

impl Serialize for ChainID {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        format!("{:#x}", self.0).serialize(serializer)
    }
}
impl Display for ChainID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
impl FromStr for ChainID {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = u64::from_str_radix(s, 16)?;
        Ok(ChainID(value))
    }
}

impl<'de> Deserialize<'de> for ChainID {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::String(s) => {
                let s = s.trim_start_matches("0x");
                let val = u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
                Ok(ChainID(val))
            }
            serde_json::Value::Number(n) => {
                if let Some(val) = n.as_u64() {
                    Ok(ChainID(val))
                } else {
                    Err(serde::de::Error::custom("expected u64"))
                }
            }
            _ => Err(serde::de::Error::custom("expected string")),
        }
    }
}

pub struct HexOrNum(U256);
impl HexOrNum {
    pub fn seralize_with<S: serde::Serializer>(
        val: &U256,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        HexOrNum(*val).serialize(serializer)
    }
    pub fn deserialize_with<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<U256, D::Error> {
        HexOrNum::deserialize(deserializer).map(|v| v.0)
    }
}
impl Serialize for HexOrNum {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        format!("{}", self.0).serialize(serializer) // serialize as number in string
    }
}
impl<'de> Deserialize<'de> for HexOrNum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val: &str = serde::Deserialize::deserialize(deserializer)?;
        let val = if val.starts_with("0x") {
            U256::from_str_radix(&val[2..], 16).map_err(serde::de::Error::custom)?
        } else {
            U256::from_dec_str(val).map_err(serde::de::Error::custom)?
        };
        Ok(HexOrNum(val))
    }
}

#[cfg(test)]
mod tests {
    use {super::*, hex_literal::hex, serde_json::json, std::collections::BTreeMap};

    #[test]
    fn test_hex_or_num() {
        let hex = "0x1234567890abcdef1234567890";
        let num = "1234567890";
        let u256 = U256::from_dec_str(num).unwrap();
        let from_json = serde_json::from_str::<HexOrNum>(&format!("\"{}\"", num)).unwrap();
        assert_eq!(from_json.0, u256);
        let u256 = U256::from_str_radix(&hex[2..], 16).unwrap();
        let from_json = serde_json::from_str::<HexOrNum>(&format!("\"{}\"", hex)).unwrap();
        assert_eq!(from_json.0, u256);
    }

    #[test]
    fn test_genesis_config_serde() {
        let genesis_config = GenesisConfig {
            config: ChainConfig {
                chain_id: ChainID(1),
                start_hardfork: Hardfork::Istanbul,
                network_name: "testnet".to_string(),
                token_name: "test".to_string(),
                whitelisted: [Pubkey::new_from_array([15; 32])].into(),
                gas_price: 15.into(),
            },
            auxiliary: OptionalConfig {
                token_symbol: "".to_string(),
                rpc_url: "".to_string(),
            },
            alloc: GenesisAlloc(BTreeMap::new()),
        };

        let json = json!({
            "config": {
                "chainId": "0x1",
                "startHardfork": "Istanbul",
                "networkName": "testnet",
                "tokenName": "test",
                "gasPrice": "0xf",
                "whitelisted": [[15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]],
            },
            "alloc": {},
            "auxiliary": {},
        });

        assert_eq!(serde_json::to_value(&genesis_config).unwrap(), json);
        assert_eq!(
            serde_json::from_value::<GenesisConfig>(json).unwrap(),
            genesis_config
        );
    }

    #[test]
    fn test_geth_genesis() {
        let conf = r#"{
            "config": {
                "chainId": 1,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "muirGlacierBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "arrowGlacierBlock": 0,
                "grayGlacierBlock": 0,
                "mergeNetsplitBlock": 0,
                "terminalTotalDifficulty": null,
                "withdrawals": {
                "enabled": true
                }
            },
            "difficulty": "20000000000",
            "gasLimit": "8000000",
            "alloc": {
                "0x3333333333333333333333333333333333333333": {
                    "balance": "1000000000000000000000000",
                    "code": "0x60606040",
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000000000000000000003"
                    }
                },
                "0x2222222222222222222222222222222222222222": {
                    "balance": "500000000000000000000000",
                    "code": "0x60606040",
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000000000000000001"
                    }
                }
            },
            "extraData": "",
            "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "timestamp": "0",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000"
        }"#;
        let genesis_config: GenesisConfig = serde_json::from_str(conf).unwrap();
        let expected = GenesisConfig {
            config: ChainConfig {
                chain_id: ChainID(1),
                start_hardfork: Hardfork::Istanbul,
                network_name: "".to_string(),
                token_name: "".to_string(),
                gas_price: 0.into(),
                whitelisted: [].into()
            },
            alloc: GenesisAlloc(
                vec![
                    (
                        H160::repeat_byte(0x33),
                        Account {
                            code: Bytes(vec![0x60, 0x60, 0x60, 0x40]),
                            storage: vec![(H256::from(hex!("0000000000000000000000000000000000000000000000000000000000000002")),
                            H256::from(hex!("0000000000000000000000000000000000000000000000000000000000000003")))].into_iter().collect(),
                            balance: U256::from_dec_str("1000000000000000000000000").unwrap(),
                            nonce: 0.into(),
                        },
                    ),
                    (
                        H160::repeat_byte(0x22),
                        Account {
                            code: Bytes(vec![0x60, 0x60, 0x60, 0x40]),
                            storage: vec![(H256::from(hex!("0000000000000000000000000000000000000000000000000000000000000001")),
                            H256::from(hex!("0000000000000000000000000000000000000000000000000000000000000001")))].into_iter().collect(),
                            balance: U256::from_dec_str("500000000000000000000000").unwrap(),
                            nonce: 0.into(),
                        },
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            auxiliary: OptionalConfig {
                token_symbol: "".to_string(),
                rpc_url: "".to_string(),
            },
        };
        assert_eq!(genesis_config, expected);

        let normalized = r#"{
            "config": {
                "chainId": "0x1",
                "startHardfork": "Istanbul",
                "networkName": "",
                "tokenName": "",
                "gasPrice": "0x0",
                "whitelisted": []
            },
            "alloc": {
                "0x2222222222222222222222222222222222222222": {
                    "code": "0x60606040",
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000001": "0x0000000000000000000000000000000000000000000000000000000000000001"
                    },
                    "balance": "500000000000000000000000",
                    "nonce": "0x0"
                },
                "0x3333333333333333333333333333333333333333": {
                    "code": "0x60606040",
                    "storage": {
                        "0x0000000000000000000000000000000000000000000000000000000000000002": "0x0000000000000000000000000000000000000000000000000000000000000003"
                    },
                    "balance": "1000000000000000000000000",
                    "nonce": "0x0"
                }
            },
            "auxiliary":{}
        }"#;
        let normalized = normalized.replace(" ", "").replace("\n", "");
        let expected_normalized = serde_json::to_string(&genesis_config).unwrap();

        assert_eq!(expected_normalized, normalized);
    }
}
