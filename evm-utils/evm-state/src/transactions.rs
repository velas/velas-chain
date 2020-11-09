use primitive_types::{H160, H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::str::FromStr;

use secp256k1::{
    recovery::{RecoverableSignature, RecoveryId},
    Error, Message,
};

pub use secp256k1::{PublicKey, SecretKey, SECP256K1};
pub type Address = H160;
pub type Gas = U256;

/// Etherium transaction.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: Gas,
    pub gas_limit: Gas,
    pub action: TransactionAction,
    pub value: U256,
    pub signature: TransactionSignature,
    pub input: Vec<u8>,
}

impl Transaction {
    pub fn caller(&self) -> Result<Address, Error> {
        let unsigned = UnsignedTransaction::from((*self).clone());
        let hash = unsigned.signing_hash(self.signature.chain_id());
        let sig = self.signature.to_recoverable_signature()?;
        let public_key =
            { SECP256K1.recover(&Message::from_slice(&hash.as_bytes()).unwrap(), &sig)? };
        let hash = H256::from_slice(Keccak256::digest(&public_key.serialize()[1..]).as_slice());
        Ok(Address::from(hash))
    }

    pub fn address(&self) -> Result<Address, Error> {
        Ok(self.action.address(self.caller()?, self.nonce))
    }
}

pub struct UnsignedTransaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub action: TransactionAction,
    pub value: U256,
    pub input: Vec<u8>,
}

impl UnsignedTransaction {
    fn signing_rlp_append(&self, s: &mut RlpStream, chain_id: Option<u64>) {
        s.begin_list(if chain_id.is_some() { 9 } else { 6 });
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.input);

        if let Some(chain_id) = chain_id {
            s.append(&chain_id);
            s.append(&0u8);
            s.append(&0u8);
        }
    }

    pub fn signing_hash(&self, chain_id: Option<u64>) -> H256 {
        let mut stream = RlpStream::new();
        self.signing_rlp_append(&mut stream, chain_id);
        H256::from_slice(Keccak256::digest(&stream.drain()).as_slice())
    }

    pub fn sign(self, key: &SecretKey, chain_id: Option<u64>) -> Transaction {
        let hash = self.signing_hash(chain_id);
        // hash is always MESSAGE_SIZE bytes.
        let msg = { Message::from_slice(hash.as_bytes()).unwrap() };

        // SecretKey and Message are always valid.
        let s = { SECP256K1.sign_recoverable(&msg, key) };
        let (rid, sig) = { s.serialize_compact() };

        let sig = TransactionSignature {
            v: ({ rid.to_i32() }
                + if let Some(n) = chain_id {
                    (35 + n * 2) as i32
                } else {
                    27
                }) as u64,
            r: H256::from_slice(&sig[0..32]),
            s: H256::from_slice(&sig[32..64]),
        };

        Transaction {
            nonce: self.nonce,
            gas_price: self.gas_price,
            gas_limit: self.gas_limit,
            action: self.action,
            value: self.value,
            input: self.input,
            signature: sig,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum TransactionAction {
    Call(Address),
    Create,
}

impl TransactionAction {
    pub fn address(&self, caller: Address, nonce: U256) -> Address {
        match self {
            &TransactionAction::Call(address) => address,
            &TransactionAction::Create => {
                let mut rlp = RlpStream::new_list(2);
                rlp.append(&caller);
                rlp.append(&nonce);

                Address::from(H256::from_slice(
                    Keccak256::digest(rlp.out().as_slice()).as_slice(),
                ))
            }
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct TransactionSignature {
    pub v: u64,
    pub r: H256,
    pub s: H256,
}

impl TransactionSignature {
    pub fn standard_v(&self) -> u8 {
        let v = self.v;
        if v == 27 || v == 28 || v > 36 {
            ((v - 1) % 2) as u8
        } else {
            4
        }
    }

    pub fn is_low_s(&self) -> bool {
        self.s
            <= H256::from_str("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
                .unwrap()
    }

    pub fn is_valid(&self) -> bool {
        self.standard_v() <= 1
            && self.r
                < H256::from_str(
                    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                )
                .unwrap()
            && self.r > H256::zero()
            && self.s
                < H256::from_str(
                    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                )
                .unwrap()
            && self.s > H256::zero()
    }

    pub fn chain_id(&self) -> Option<u64> {
        if self.v > 36 {
            Some((self.v - 35) / 2)
        } else {
            None
        }
    }

    pub fn to_recoverable_signature(&self) -> Result<RecoverableSignature, Error> {
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(self.r.as_bytes());
        sig[32..64].copy_from_slice(self.s.as_bytes());

        RecoverableSignature::from_compact(&sig, RecoveryId::from_i32(self.standard_v() as i32)?)
    }
}

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &TransactionAction::Call(address) => {
                s.append(&address);
            }
            &TransactionAction::Create => {
                s.append(&"");
            }
        }
    }
}

impl Decodable for TransactionAction {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        Ok(if rlp.is_empty() {
            if rlp.is_data() {
                TransactionAction::Create
            } else {
                return Err(rlp::DecoderError::RlpExpectedToBeData);
            }
        } else {
            TransactionAction::Call(rlp.as_val()?)
        })
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.nonce);
        s.append(&self.gas_price);
        s.append(&self.gas_limit);
        s.append(&self.action);
        s.append(&self.value);
        s.append(&self.input);
        s.append(&self.signature.v);
        s.append(&self.signature.r);
        s.append(&self.signature.s);
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(0)?,
            gas_price: rlp.val_at(1)?,
            gas_limit: rlp.val_at(2)?,
            action: rlp.val_at(3)?,
            value: rlp.val_at(4)?,
            input: rlp.val_at(5)?,
            signature: TransactionSignature {
                v: rlp.val_at(6)?,
                r: rlp.val_at(7)?,
                s: rlp.val_at(8)?,
            },
        })
    }
}

impl From<Transaction> for UnsignedTransaction {
    fn from(val: Transaction) -> UnsignedTransaction {
        UnsignedTransaction {
            nonce: val.nonce,
            gas_price: val.gas_price,
            gas_limit: val.gas_limit,
            action: val.action,
            value: val.value,
            input: val.input,
        }
    }
}
