use crate::{transaction_roots::EthereumReceipt, TransactionAction, UnsignedTransaction, UnsignedTransactionWithCaller};

use super::types::Account;

use ethbloom::Bloom;
use evm::backend::Log;
use keccak_hash::H256;
use primitive_types::{U256, H160};
use rlp::{Decodable as DecodableOld, DecoderError as OldDecoderError, Rlp};

use triedb::rlp::{Encodable, Decodable, DecoderError};

fn decode_old<T: DecodableOld>(bytes: &[u8]) -> Result<T, OldDecoderError> {

    <T as DecodableOld>::decode(&Rlp::new(bytes))
}

 pub fn decode<'a, T: Decodable<'a>>(mut val: &'a [u8]) -> Result<T, DecoderError> {
    Decodable::decode(&mut val)
}

pub use rlp::encode as encode_old;

pub fn encode<V: Encodable>(val: &V) -> Vec<u8> {
    let mut vec_buffer = Vec::with_capacity(val.length());
    val.encode(&mut vec_buffer);
    vec_buffer
}

macro_rules! check_roundtrip {
    ($v: expr => $type: ty) => {{
        let old_rlp_raw: Vec<u8>;
        let rlp_raw;
        {
            old_rlp_raw = encode_old(&$v).to_vec();
            dbg!(hexutil::to_hex(&old_rlp_raw));
            let decoded_node: $type = decode_old(&old_rlp_raw).unwrap();
            assert_eq!(decoded_node, $v);
        }
        {
            rlp_raw = encode(&$v);
            dbg!(hexutil::to_hex(&rlp_raw));
            let decoded_node: $type = decode(&rlp_raw).unwrap();
            assert_eq!(decoded_node, $v);
        }

        {
            assert_eq!(old_rlp_raw, rlp_raw);
        }
    }};
}

#[test]
fn test_check_account_roundtrip() {
    let acc = Account {
        nonce: U256([27;4]),
        balance: U256([24;4]),
        storage_root: H256([7; 32]),
        code_hash: H256([2; 32]),
        
    };

    check_roundtrip!(acc => Account);
    let acc = Account {
        nonce: U256([21;4]),
        balance: U256([23;4]),
        storage_root: H256([8; 32]),
        code_hash: H256([123; 32]),
        
    };

    check_roundtrip!(acc => Account);
    
}

#[test]
fn test_check_log_roundtrip() {
    let acc = Log {
        address: H160([23; 20]),
        topics: vec![H256([37; 32]), H256([173;32]), H256([21; 32])],
        data: vec![0, 123, 12, 17, 19, 244],
        
    };

    check_roundtrip!(acc => Log);
    let acc = Log {
        address: H160([23; 20]),
        topics: vec![],
        data: vec![],
        
    };

    check_roundtrip!(acc => Log);
    
}
#[test]
fn test_check_bloom_roundtrip() {
    let mut acc = [10; 256];
    for i in 0..256 {
        acc[i] = i as u8;
    }
    let bloomy = Bloom(acc);

    check_roundtrip!(bloomy => Bloom);
}

#[test]
fn test_check_ethereum_receipt_roundtrip() {
    let mut acc = [10; 256];
    for i in 0..256 {
        acc[i] = i as u8;
    }
    let bloomy = Bloom(acc);
    let mut h160_special = [0; 20];
    for i in 0..20 {
        h160_special[i] = i as u8;
    }
    let log1 = Log {
        address: H160(h160_special),
        topics: vec![H256([37; 32]), H256([173;32]), H256([21; 32])],
        data: vec![0, 123, 12, 17, 19, 244],
        
    };
    let log2 = Log {
        address: H160([38; 20]),
        topics: vec![H256([27; 32]), H256([173;32]), H256([24; 32])],
        data: vec![0, 123, 12, 17, 111, 244],
        
    };

    let receipt = EthereumReceipt {
        log_bloom: bloomy,        
        logs: vec![log1, log2],
        status: 7,
        gas_used: U256([23;4]),

    };

    check_roundtrip!(receipt => EthereumReceipt);
}

#[test]
fn test_check_tranaaction_action_roundtrip() {
    let ta1 = TransactionAction::Create;


    check_roundtrip!(ta1 => TransactionAction);

    let ta2 = TransactionAction::Call(H160([56; 20]));

    check_roundtrip!(ta2 => TransactionAction);

}

#[test]
fn test_check_unsigned_transaction_roundtrip() {
    let ta2 = TransactionAction::Call(H160([56; 20]));

    let ut2 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta2,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };
 
    check_roundtrip!(ut2 => UnsignedTransaction);
    let ta1 = TransactionAction::Create;

    let ut1 = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta1,
        value: U256([23000;4]),
        input: vec![34, 45, 12, 123, 243],
    };
    check_roundtrip!(ut1 => UnsignedTransaction);

}

#[test]
fn test_check_unsigned_transaction_with_caller_roundtrip1() {
    let ta = TransactionAction::Call(H160([56; 20]));

    let ut = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta,
        value: U256([20000; 4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c = UnsignedTransactionWithCaller {
        unsigned_tx: ut,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: true,
        
    }; 
    let old_rlp_raw: Vec<u8>;
    let rlp_raw;
    {
        old_rlp_raw = encode_old(&ut_c).to_vec();
        dbg!(hexutil::to_hex(&old_rlp_raw));
        let rlp = Rlp::new(&old_rlp_raw);
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode_old(&rlp, true).unwrap();
        assert_eq!(decoded_node, ut_c);
    }
    {
        rlp_raw = encode(&ut_c);
        dbg!(hexutil::to_hex(&rlp_raw));
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode(&mut rlp_raw.as_ref(), true).unwrap();
        assert_eq!(decoded_node, ut_c);
    }

    {
        assert_eq!(old_rlp_raw, rlp_raw);
    }
}

#[test]
fn test_check_unsigned_transaction_with_caller_roundtrip2() {
    let ta = TransactionAction::Create;

    let ut = UnsignedTransaction {
        nonce: U256([46;4]),
        gas_price: U256([543; 4]),
        gas_limit: U256([342;4]),
        action: ta,
        value: U256([23000;4]),
        input: vec![34, 45, 12, 123, 243],
    };

    let ut_c = UnsignedTransactionWithCaller {
        unsigned_tx: ut,
        caller: H160([23; 20]),
        chain_id: 24,
        signed_compatible: false,
        
    }; 
    let old_rlp_raw: Vec<u8>;
    let rlp_raw;
    {
        old_rlp_raw = encode_old(&ut_c).to_vec();
        dbg!(hexutil::to_hex(&old_rlp_raw));
        let rlp = Rlp::new(&old_rlp_raw);
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode_old(&rlp, false).unwrap();
        assert_eq!(decoded_node, ut_c);
    }
    {
        rlp_raw = encode(&ut_c);
        dbg!(hexutil::to_hex(&rlp_raw));
        let decoded_node: UnsignedTransactionWithCaller = UnsignedTransactionWithCaller::decode(&mut rlp_raw.as_ref(), false).unwrap();
        assert_eq!(decoded_node, ut_c);
    }

    {
        assert_eq!(old_rlp_raw, rlp_raw);
    }
}