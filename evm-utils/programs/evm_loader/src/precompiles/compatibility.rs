use super::{BuiltinEval, CallResult, PrecompileContext, Result};
use crate::precompiles::PrecompileErrors;
use evm_state::{executor::PrecompileOutput, TransactionSignature, H160, H256, U256};

use std::cmp::{max, min};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, Cursor, Read};
use std::str::FromStr;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use num::{BigUint, One, Zero};

// Deprecated precompiles differ in price calculations
mod deprecated {
    use super::*;

    #[derive(Debug)]
    pub struct Ripemd160;

    #[derive(Debug)]
    pub struct EcRecover;

    impl Precompile for EcRecover {
        fn address() -> H160 {
            H160::from_str("0000000000000000000000000000000000000001")
                .expect("Serialization of static data should be determenistic and never fail.")
        }

        fn price(source: &[u8]) -> u64 {
            60 + 12 * words(source, 32)
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

    impl Precompile for Ripemd160 {
        fn address() -> H160 {
            H160::from_str("0000000000000000000000000000000000000003")
                .expect("Serialization of static data should be determenistic and never fail.")
        }

        fn price(source: &[u8]) -> u64 {
            60 + 12 * words(source, 32)
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
}

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

    fn price(source: &[u8]) -> u64;

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

    fn price(_source: &[u8]) -> u64 {
        3000
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

    fn price(source: &[u8]) -> u64 {
        60 + 12 * words(source, 32)
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

    fn price(source: &[u8]) -> u64 {
        600 + 120 * words(source, 32)
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

    fn price(source: &[u8]) -> u64 {
        15 + 3 * words(source, 32)
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        Ok(source.to_vec())
    }
}

impl Precompile for Modexp {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000005")
            .expect("Serialization of static data should be determenistic and never fail.")
    }

    fn price(source: &[u8]) -> u64 {
        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-198.md
        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2565.md
        const DIVISOR: u64 = 20;

        fn parse_input(input: &[u8]) -> (U256, U256, U256, U256) {
            let mut reader = input.chain(io::repeat(0));
            let mut buf = [0; 32];

            // read lengths as U256 here for accurate gas calculation.
            let mut read_len = || {
                reader
                    .read_exact(&mut buf[..])
                    .expect("reading from zero-extended memory cannot fail; qed");
                U256::from_big_endian(&buf[..])
            };
            let base_len_u256 = read_len();
            let exp_len_u256 = read_len();
            let mod_len_u256 = read_len();

            let (base_len, exp_len) = (base_len_u256.low_u64(), exp_len_u256.low_u64());

            // read fist 32-byte word of the exponent.
            let exp_low = if base_len + 96 >= input.len() as u64 {
                U256::zero()
            } else {
                buf.iter_mut().for_each(|b| *b = 0);
                let mut reader = input[(96 + base_len as usize)..].chain(io::repeat(0));
                let len = min(exp_len, 32) as usize;
                reader
                    .read_exact(&mut buf[(32 - len)..])
                    .expect("reading from zero-extended memory cannot fail; qed");
                U256::from_big_endian(&buf[..])
            };

            (base_len_u256, exp_len_u256, exp_low, mod_len_u256)
        }

        fn check_input_boundaries(base_len: &U256, exp_len: &U256, mod_len: &U256) -> Option<u64> {
            if mod_len.is_zero() && base_len.is_zero() {
                return Some(0);
            }

            let max_len = U256::from(u32::max_value() / 2);
            if base_len > &max_len || mod_len > &max_len || exp_len > &max_len {
                return Some(u64::max_value());
            }
            None
        }

        fn adjusted_exp_len(len: u64, exp_low: U256) -> u64 {
            let bit_index = if exp_low.is_zero() {
                0
            } else {
                (255 - exp_low.leading_zeros()) as u64
            };
            if len <= 32 {
                bit_index
            } else {
                8 * (len - 32) + bit_index
            }
        }

        fn mult_complexity(x: u64) -> u64 {
            match x {
                x if x <= 64 => x * x,
                x if x <= 1024 => (x * x) / 4 + 96 * x - 3072,
                x => (x * x) / 16 + 480 * x - 199_680,
            }
        }

        let (base_len, exp_len, exp_low, mod_len) = parse_input(source);

        if let Some(cost) = check_input_boundaries(&base_len, &exp_len, &mod_len) {
            return cost;
        }

        let (base_len, exp_len, mod_len) =
            (base_len.low_u64(), exp_len.low_u64(), mod_len.low_u64());

        let adjusted_exp_len = adjusted_exp_len(exp_len, exp_low);

        let m = max(mod_len, base_len);
        let (gas, overflow) = mult_complexity(m).overflowing_mul(max(adjusted_exp_len, 1));
        if overflow {
            return u64::max_value();
        }

        gas / DIVISOR
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        // calculate modexp: left-to-right binary exponentiation to keep multiplicands lower
        fn modexp(mut base: BigUint, exp: Vec<u8>, modulus: BigUint) -> BigUint {
            const BITS_PER_DIGIT: usize = 8;

            // n^m % 0 || n^m % 1
            if modulus <= BigUint::one() {
                return BigUint::zero();
            }

            // normalize exponent
            let mut exp = exp.into_iter().skip_while(|d| *d == 0).peekable();

            // n^0 % m
            if exp.peek().is_none() {
                return BigUint::one();
            }

            // 0^n % m, n > 0
            if base.is_zero() {
                return BigUint::zero();
            }

            base %= &modulus;

            // Fast path for base divisible by modulus.
            if base.is_zero() {
                return BigUint::zero();
            }

            // Left-to-right binary exponentiation (Handbook of Applied Cryptography - Algorithm 14.79).
            // http://www.cacr.math.uwaterloo.ca/hac/about/chap14.pdf
            let mut result = BigUint::one();

            for digit in exp {
                let mut mask = 1 << (BITS_PER_DIGIT - 1);

                for _ in 0..BITS_PER_DIGIT {
                    result = &result * &result % &modulus;

                    if digit & mask > 0 {
                        result = result * &base % &modulus;
                    }

                    mask >>= 1;
                }
            }

            result
        }

        let mut reader = source.chain(io::repeat(0));
        let mut buf = [0; 32];

        // read lengths as usize.
        // ignoring the first 24 bytes might technically lead us to fall out of consensus,
        // but so would running out of addressable memory!
        let mut read_len = |reader: &mut io::Chain<&[u8], io::Repeat>| {
            reader
                .read_exact(&mut buf[..])
                .expect("reading from zero-extended memory cannot fail; qed");
            let mut len_bytes = [0u8; 8];
            len_bytes.copy_from_slice(&buf[24..]);
            u64::from_be_bytes(len_bytes) as usize
        };

        let base_len = read_len(&mut reader);
        let exp_len = read_len(&mut reader);
        let mod_len = read_len(&mut reader);

        // Gas formula allows arbitrary large exp_len when base and modulus are empty, so we need to handle empty base first.
        let r = if base_len == 0 && mod_len == 0 {
            BigUint::zero()
        } else {
            // read the numbers themselves.
            let mut buf = vec![0; max(mod_len, max(base_len, exp_len))];
            let mut read_num = |reader: &mut io::Chain<&[u8], io::Repeat>, len: usize| {
                reader
                    .read_exact(&mut buf[..len])
                    .expect("reading from zero-extended memory cannot fail; qed");
                BigUint::from_bytes_be(&buf[..len])
            };

            let base = read_num(&mut reader, base_len);

            let mut exp_buf = vec![0; exp_len];
            reader
                .read_exact(&mut exp_buf[..exp_len])
                .expect("reading from zero-extended memory cannot fail; qed");

            let modulus = read_num(&mut reader, mod_len);

            modexp(base, exp_buf, modulus)
        };

        // write output to given memory, left padded and same length as the modulus.
        let bytes = r.to_bytes_be();

        let mut output = vec![0u8; mod_len];

        // always true except in the case of zero-length modulus, which leads to
        // output of length and value 1.
        if bytes.len() <= mod_len {
            let res_start = mod_len - bytes.len();
            output.resize(res_start, 0);
            output.extend_from_slice(&bytes);
        }

        Ok(output)
    }
}

impl Precompile for Bn128Add {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000006")
            .expect("Serialization of static data should be determenistic and never fail.")
    }

    fn price(_source: &[u8]) -> u64 {
        150
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        use substrate_bn::AffineG1;

        let mut padded_input = source.chain(io::repeat(0));
        let p1 = read_point(&mut padded_input)?;
        let p2 = read_point(&mut padded_input)?;

        let mut output = Vec::from([0u8; 64]);
        if let Some(sum) = AffineG1::from_jacobian(p1 + p2) {
            // point not at infinity
            sum.x()
                .to_big_endian(&mut output[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            sum.y()
                .to_big_endian(&mut output[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }
        Ok(output)
    }
}

impl Precompile for Bn128Mul {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000007")
            .expect("Serialization of static data should be determenistic and never fail.")
    }

    fn price(_source: &[u8]) -> u64 {
        6_000
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        use substrate_bn::AffineG1;

        let mut padded_input = source.chain(io::repeat(0));
        let p = read_point(&mut padded_input)?;
        let fr = read_fr(&mut padded_input)?;

        let mut write_buf = Vec::from([0u8; 64]);
        if let Some(sum) = AffineG1::from_jacobian(p * fr) {
            // point not at infinity
            sum.x()
                .to_big_endian(&mut write_buf[0..32])
                .expect("Cannot fail since 0..32 is 32-byte length");
            sum.y()
                .to_big_endian(&mut write_buf[32..64])
                .expect("Cannot fail since 32..64 is 32-byte length");
        }

        Ok(write_buf)
    }
}

impl Precompile for Bn128Pairing {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000008")
            .expect("Serialization of static data should be determenistic and never fail.")
    }

    fn price(source: &[u8]) -> u64 {
        45_000 + 34_000 * words(source, 192)
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        fn execute_with_error(source: &[u8]) -> Result<Vec<u8>> {
            use substrate_bn::{pairing, AffineG1, AffineG2, Fq, Fq2, Group, Gt, G1, G2};

            let ret_val =
                if source.is_empty() {
                    U256::one()
                } else {
                    // (a, b_a, b_b - each 64-byte affine coordinates)
                    let elements = source.len() / 192;
                    let mut vals = Vec::new();
                    for idx in 0..elements {
                        let a_x =
                            Fq::from_slice(&source[idx * 192..idx * 192 + 32]).map_err(|_| {
                                PrecompileErrors::ParseCoordinateError {
                                    message: "Invalid a argument x coordinate".into(),
                                }
                            })?;

                        let a_y = Fq::from_slice(&source[idx * 192 + 32..idx * 192 + 64]).map_err(
                            |_| PrecompileErrors::ParseCoordinateError {
                                message: "Invalid a argument y coordinate".into(),
                            },
                        )?;

                        let b_a_y = Fq::from_slice(&source[idx * 192 + 64..idx * 192 + 96])
                            .map_err(|_| PrecompileErrors::ParseCoordinateError {
                                message: "Invalid b argument imaginary coeff x coordinate".into(),
                            })?;

                        let b_a_x = Fq::from_slice(&source[idx * 192 + 96..idx * 192 + 128])
                            .map_err(|_| PrecompileErrors::ParseCoordinateError {
                                message: "Invalid b argument imaginary coeff y coordinate".into(),
                            })?;

                        let b_b_y = Fq::from_slice(&source[idx * 192 + 128..idx * 192 + 160])
                            .map_err(|_| PrecompileErrors::ParseCoordinateError {
                                message: "Invalid b argument real coeff x coordinate".into(),
                            })?;

                        let b_b_x = Fq::from_slice(&source[idx * 192 + 160..idx * 192 + 192])
                            .map_err(|_| PrecompileErrors::ParseCoordinateError {
                                message: "Invalid b argument real coeff y coordinate".into(),
                            })?;

                        let b_a = Fq2::new(b_a_x, b_a_y);
                        let b_b = Fq2::new(b_b_x, b_b_y);
                        let b = if b_a.is_zero() && b_b.is_zero() {
                            G2::zero()
                        } else {
                            G2::from(AffineG2::new(b_a, b_b).map_err(|_| {
                                PrecompileErrors::ParseCoordinateError {
                                    message: "Invalid b argument - not on curve".into(),
                                }
                            })?)
                        };
                        let a = if a_x.is_zero() && a_y.is_zero() {
                            G1::zero()
                        } else {
                            G1::from(AffineG1::new(a_x, a_y).map_err(|_| {
                                PrecompileErrors::ParseCoordinateError {
                                    message: "Invalid a argument - not on curve".into(),
                                }
                            })?)
                        };
                        vals.push((a, b));
                    }

                    let mul = vals
                        .into_iter()
                        .fold(Gt::one(), |s, (a, b)| s * pairing(a, b));

                    if mul == Gt::one() {
                        U256::one()
                    } else {
                        U256::zero()
                    }
                };

            let mut result = vec![0u8; 32];

            ret_val.to_big_endian(&mut result);

            let max = min(result.len(), source.len());

            result[0..max].copy_from_slice(&source[..max]);

            Ok(result)
        }

        if source.len() % 192 != 0 {
            return Err(PrecompileErrors::ParsePointError {
                message: "Invalid input length, must be multiple of 192 (3 * (32*2))".into(),
            });
        }

        execute_with_error(source)
    }
}

impl Precompile for Blake2F {
    fn address() -> H160 {
        H160::from_str("0000000000000000000000000000000000000009")
            .expect("Serialization of static data should be determenistic and never fail.")
    }

    fn price(source: &[u8]) -> u64 {
        // FIXME: set correct value
        const GAS_PER_ROUND: u64 = 1;

        const FOUR: usize = std::mem::size_of::<u32>();

        if source.len() < FOUR {
            return 0;
        }

        let (rounds, _) = source.split_at(FOUR);
        let rounds = u32::from_be_bytes(rounds.try_into().unwrap_or([0u8; 4]));
        GAS_PER_ROUND * rounds as u64
    }

    fn implementation(source: &[u8], _cx: PrecompileContext) -> Result<Vec<u8>> {
        const BLAKE2_F_ARG_LEN: usize = 213;
        const PROOF: &str = "Checked the length of the input above; qed";

        if source.len() != BLAKE2_F_ARG_LEN {
            return Err(PrecompileErrors::BadInputLength {
                length: source.len(),
            });
        }

        let mut cursor = Cursor::new(source);
        let rounds = cursor.read_u32::<BigEndian>().expect(PROOF);

        // state vector, h
        let mut h = [0u64; 8];
        for state_word in &mut h {
            *state_word = cursor.read_u64::<LittleEndian>().expect(PROOF);
        }

        // message block vector, m
        let mut m = [0u64; 16];
        for msg_word in &mut m {
            *msg_word = cursor.read_u64::<LittleEndian>().expect(PROOF);
        }

        // 2w-bit offset counter, t
        let t = [
            cursor.read_u64::<LittleEndian>().expect(PROOF),
            cursor.read_u64::<LittleEndian>().expect(PROOF),
        ];

        // final block indicator flag, "f"
        let f = match source.last() {
            Some(1) => true,
            Some(0) => false,
            _ => {
                return Err(PrecompileErrors::IncorrectBlockIndicator);
            }
        };

        eip_152::compress(&mut h, m, t, f, rounds as usize);

        let mut output = vec![0u8; 64];

        let mut output_buf = [0u8; 8 * std::mem::size_of::<u64>()];
        for (i, state_word) in h.iter().enumerate() {
            output_buf[i * 8..(i + 1) * 8].copy_from_slice(&state_word.to_le_bytes());
        }

        let max = min(output.len(), output_buf.len());
        output[0..max].copy_from_slice(&output_buf[..max]);

        Ok(output)
    }
}

fn words(source: &[u8], word_len: usize) -> u64 {
    (source.len() / word_len) as u64
}

fn read_fr(
    reader: &mut io::Chain<&[u8], io::Repeat>,
) -> Result<substrate_bn::Fr, PrecompileErrors> {
    let mut buf = [0u8; 32];

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    substrate_bn::Fr::from_slice(&buf[0..32]).map_err(|_| PrecompileErrors::ParsePointError {
        message: "Invalid field element".into(),
    })
}

fn read_point(
    reader: &mut io::Chain<&[u8], io::Repeat>,
) -> Result<substrate_bn::G1, PrecompileErrors> {
    use substrate_bn::{AffineG1, Fq, Group, G1};

    let mut buf = [0u8; 32];

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    let px = Fq::from_slice(&buf[0..32]).map_err(|_| PrecompileErrors::ParsePointError {
        message: "Invalid point x coordinate".into(),
    })?;

    reader
        .read_exact(&mut buf[..])
        .expect("reading from zero-extended memory cannot fail; qed");
    let py = Fq::from_slice(&buf[0..32]).map_err(|_| PrecompileErrors::ParsePointError {
        message: "Invalid point y coordinate".into(),
    })?;
    Ok(if px == Fq::zero() && py == Fq::zero() {
        G1::zero()
    } else {
        AffineG1::new(px, py)
            .map_err(|_| PrecompileErrors::ParsePointError {
                message: "Invalid curve point".into(),
            })?
            .into()
    })
}

pub fn build_precompile_map(new_precompiles: bool) -> HashMap<H160, BuiltinEval> {
    let mut map: HashMap<H160, BuiltinEval> = HashMap::new();

    Identity::insert_to_map(&mut map);
    Sha256::insert_to_map(&mut map);

    if new_precompiles {
        Ripemd160::insert_to_map(&mut map);
        EcRecover::insert_to_map(&mut map);
        Modexp::insert_to_map(&mut map);
        Bn128Add::insert_to_map(&mut map);
        Bn128Mul::insert_to_map(&mut map);
        Bn128Pairing::insert_to_map(&mut map);
        Blake2F::insert_to_map(&mut map);
    } else {
        deprecated::Ripemd160::insert_to_map(&mut map);
        deprecated::EcRecover::insert_to_map(&mut map);
    }

    map
}

fn execute_precompile<T: Precompile>(source: &[u8], cx: PrecompileContext) -> CallResult {
    let gas_used = T::price(source);
    let bytes = T::implementation(source, cx)?;
    Ok((
        PrecompileOutput {
            exit_status: evm_state::ExitSucceed::Returned,
            output: bytes,
        },
        gas_used,
        vec![],
    ))
}
