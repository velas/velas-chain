use primitive_types::{H256, H160, U256};
use rlp::{Decodable, Encodable, Rlp, RlpStream, DecoderError};
/// Etherium transaction.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Transaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub action: TransactionAction,
    pub value: U256,
    pub signature: TransactionSignature,
    pub input: Vec<u8>,
}


#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TransactionAction {
    Call(H160),
    Create,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TransactionSignature {
    pub v: u64,
    pub r: H256,
    pub s: H256,
}

impl Encodable for TransactionAction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            &TransactionAction::Call(address) => {
                s.append(&address);
            },
            &TransactionAction::Create => {
                s.append(&"");
            },
        }
    }
}

impl Decodable for TransactionAction {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        Ok(if rlp.is_empty() {
            if rlp.is_data() {
                TransactionAction::Create
            } else {
                return Err(rlp::DecoderError::RlpExpectedToBeData)
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