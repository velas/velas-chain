use super::{BuiltinEval, CallResult, PrecompileContext, PrecompileOk, Result};
use evm_state::{TransactionSignature, H160, H256};

use std::collections::HashMap;
use std::str::FromStr;
const WORD_LEN: usize = 32;

#[derive(Debug)]
pub struct Identity;

#[derive(Debug)]
pub struct Sha256;

#[derive(Debug)]
pub struct Ripemd160;

#[derive(Debug)]
pub struct EcRecover;

#[derive(Debug)]
pub struct Modexp;

#[derive(Debug)]
pub struct Bn128Add;

#[derive(Debug)]
pub struct Bn128Mul;

#[derive(Debug)]
pub struct Bn128Pairing;

#[derive(Debug)]
pub struct Blake2F;

trait Precompile {
    fn address() -> H160;
    fn pricer() -> Pricer;

    fn implementation(source: &[u8], cx: PrecompileContext) -> Result<Vec<u8>>;

    fn insert_to_map(map: &mut HashMap<H160, BuiltinEval>)
    where
        Self: Sized,
    {
        assert!(map
            .insert(Self::address(), &|source, cx| execute_precompile::<Self>(
                source, cx
            ))
            .is_none());
    }
}

impl Precompile for EcRecover {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000001")
            .expect("Serialization of static data should be determenistic and never fail.")
    }
    fn pricer() -> Pricer {
        Pricer::Linear { base: 60, word: 12 }
    }
    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        use evm_state::secp256k1::{Message, SECP256K1};
        use evm_state::transactions::addr_from_public_key;
        let len = std::cmp::min(source.len(), 128);
        let mut input = [0; 128];
        input[..len].copy_from_slice(&source[..len]);

        let hash = &input[0..32];
        let v = H256::from_slice(&input[32..64]);
        let r = H256::from_slice(&input[64..96]);
        let s = H256::from_slice(&input[96..128]);
        if v.0[..31] != [0; 31] {
            return Ok(vec![]);
        }
        let v = v[31];

        let signature = TransactionSignature { v: v as u64, r, s };

        if !signature.is_valid() {
            return Ok(vec![]);
        }
        let signature = if let Ok(s) = signature.to_recoverable_signature() {
            s
        } else {
            return Ok(vec![]);
        };

        let public_key =
            if let Ok(p) = SECP256K1.recover(&Message::from_slice(hash).unwrap(), &signature) {
                p
            } else {
                return Ok(vec![]);
            };
        let addr = addr_from_public_key(&public_key);
        let mut result = vec![0; 32];
        result[12..].copy_from_slice(addr.as_bytes());
        Ok(result)
    }
}

impl Precompile for Sha256 {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000002")
            .expect("Serialization of static data should be determenistic and never fail.")
    }
    fn pricer() -> Pricer {
        Pricer::Linear { base: 60, word: 12 }
    }
    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        // write input message
        hasher.update(source);

        // read hash digest and consume hasher
        let result = hasher.finalize();
        Ok(result.to_vec())
    }
}

impl Precompile for Ripemd160 {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000003")
            .expect("Serialization of static data should be determenistic and never fail.")
    }
    fn pricer() -> Pricer {
        Pricer::Linear { base: 60, word: 12 }
    }
    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        use ripemd160::{Digest, Ripemd160};
        let mut hasher = Ripemd160::new();

        // write input message
        hasher.update(source);

        // read hash digest and consume hasher
        let array = hasher.finalize();
        let mut result = vec![0; 32];
        result[12..].copy_from_slice(array.as_slice());
        Ok(result)
    }
}

impl Precompile for Identity {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000004")
            .expect("Serialization of static data should be determenistic and never fail.")
    }
    fn pricer() -> Pricer {
        Pricer::Linear { base: 15, word: 3 }
    }
    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        Ok(source.to_vec())
    }
}

enum Pricer {
    Linear { base: u64, word: u64 },
}
impl Pricer {
    fn calculate_price(&self, source: &[u8]) -> u64 {
        match self {
            Pricer::Linear { base, word } => {
                let num_words = (source.len() / WORD_LEN) as u64;
                base + word * num_words
            }
        }
    }
}

pub fn extend_precompile_map(map: &mut HashMap<H160, BuiltinEval>) {
    Identity::insert_to_map(map);
    Sha256::insert_to_map(map);
    Ripemd160::insert_to_map(map);
    EcRecover::insert_to_map(map);
}

fn execute_precompile<T: Precompile>(source: &[u8], cx: PrecompileContext) -> CallResult {
    let gas_used = T::pricer().calculate_price(source);
    let bytes = T::implementation(source, cx)?;
    Ok(PrecompileOk::new(
        evm_state::ExitSucceed::Returned,
        bytes,
        gas_used,
    ))
}

//TODO:
// "0000000000000000000000000000000000000005": { "builtin": { "name": "modexp", "activate_at": "0x00", "pricing": { "modexp": { "divisor": 20 } } } },
// "0000000000000000000000000000000000000006": {
// 	"builtin": {
// 		"name": "alt_bn128_add",
// 		"pricing": {
// 			"0": {
// 				"price": { "alt_bn128_const_operations": { "price": 500 }}
// 			},
// 			"0": {
// 				"info": "EIP 1108 transition",
// 				"price": { "alt_bn128_const_operations": { "price": 150 }}
// 			}
// 		}
// 	}
// },
// "0000000000000000000000000000000000000007": {
// 	"builtin": {
// 		"name": "alt_bn128_mul",
// 		"pricing": {
// 			"0": {
// 				"price": { "alt_bn128_const_operations": { "price": 40000 }}
// 			},
// 			"0": {
// 				"info": "EIP 1108 transition",
// 				"price": { "alt_bn128_const_operations": { "price": 6000 }}
// 			}
// 		}
// 	}
// },
// "0000000000000000000000000000000000000008": {
// 	"builtin": {
// 		"name": "alt_bn128_pairing",
// 		"pricing": {
// 			"0": {
// 				"price": { "alt_bn128_pairing": { "base": 100000, "pair": 80000 }}
// 			},
// 			"0": {
// 				"info": "EIP 1108 transition",
// 				"price": { "alt_bn128_pairing": { "base": 45000, "pair": 34000 }}
// 			}
// 		}
// 	}
// },
// "0000000000000000000000000000000000000009": {
// 	"builtin": {
// 		"name": "blake2_f",
// 		"activate_at": "0x00",
// 		"pricing": {
// 			"blake2_f": {
// 				"gas_per_round": 1
// 			}
// 		}
// 	}
// }
