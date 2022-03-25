use super::old_instructions::{OldEvmBigTransaction, OldEvmInstruction};
use super::scope::*;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use serde::{Deserialize, Serialize};

pub const EVM_INSTRUCTION_BORSH_PREFIX: u8 = 255u8;

#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub enum FeePayerType {
    Evm,
    Native,
}

impl FeePayerType {
    pub fn is_evm(&self) -> bool {
        *self == FeePayerType::Evm
    }
    pub fn is_native(&self) -> bool {
        *self == FeePayerType::Native
    }
}

/// Solana blockchain limit amount of data that transaction can have.
/// To get around this limitation, we use design that is similar to LoaderInstruction in sdk.

#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(from = "OldEvmBigTransaction")]
#[serde(into = "OldEvmBigTransaction")]
pub enum EvmBigTransaction {
    /// Allocate data in storage, pay fee should be taken from EVM.
    EvmTransactionAllocate { size: u64 },

    /// Store part of EVM transaction into temporary storage, in order to execute it later.
    EvmTransactionWrite { offset: u64, data: Vec<u8> },

    /// Execute merged transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecute { fee_type: FeePayerType },

    /// Execute merged unsigned transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecuteUnsigned {
        from: evm::Address,
        fee_type: FeePayerType,
    },
}

impl From<OldEvmBigTransaction> for EvmBigTransaction {
    fn from(other: OldEvmBigTransaction) -> Self {
        match other {
            OldEvmBigTransaction::EvmTransactionAllocate { size } => {
                Self::EvmTransactionAllocate { size }
            }
            OldEvmBigTransaction::EvmTransactionWrite { offset, data } => {
                Self::EvmTransactionWrite { offset, data }
            }
            OldEvmBigTransaction::EvmTransactionExecute {} => Self::EvmTransactionExecute {
                fee_type: FeePayerType::Evm,
            },
            OldEvmBigTransaction::EvmTransactionExecuteUnsigned { from } => {
                Self::EvmTransactionExecuteUnsigned {
                    from,
                    fee_type: FeePayerType::Evm,
                }
            }
        }
    }
}

impl Into<OldEvmBigTransaction> for EvmBigTransaction {
    fn into(self) -> OldEvmBigTransaction {
        match self {
            Self::EvmTransactionAllocate { size } => {
                OldEvmBigTransaction::EvmTransactionAllocate { size }
            }
            Self::EvmTransactionWrite { offset, data } => {
                OldEvmBigTransaction::EvmTransactionWrite { offset, data }
            }
            Self::EvmTransactionExecute { .. } => OldEvmBigTransaction::EvmTransactionExecute {},
            Self::EvmTransactionExecuteUnsigned { from, .. } => {
                OldEvmBigTransaction::EvmTransactionExecuteUnsigned { from }
            }
        }
    }
}

#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(from = "OldEvmInstruction")]
#[serde(into = "OldEvmInstruction")]
pub enum EvmInstruction {
    /// Execute native EVM transaction.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[readable]`. Optional argument, used in case tokens swaps from EVM back to native.
    ///
    EvmTransaction {
        evm_tx: evm::Transaction,
        fee_type: FeePayerType,
    },

    /// Transfer native lamports to ethereum.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    /// Inner args:
    /// amount - count of lamports to be transfered.
    /// ether_key - recevier etherium address.
    ///
    SwapNativeToEther {
        lamports: u64,
        evm_address: evm::Address,
    },

    /// Transfer user account ownership back to system program.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Owner account that's allowed to manage withdrawal of his account by transfering ownership.
    ///
    FreeOwnership {},

    /// Allocate / push data / execute Big Transaction
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account. used for lock.
    /// account_key[1] - `[writable]`. Big Transaction data storage.
    EvmBigTransaction(EvmBigTransaction),

    /// Execute native EVM transaction.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[writable, signer]`. Co.
    ///
    /// Inner args:
    /// from - is an address calculated using `program_evm_address`.
    /// unsigned_tx - is an evm transaction, that should be called, without EVM signature verification,
    ///   instead solana signature verification should be called.
    EvmAuthorizedTransaction {
        from: evm::Address,
        unsigned_tx: evm::UnsignedTransaction,
        fee_type: FeePayerType,
    },
}

impl From<OldEvmInstruction> for EvmInstruction {
    fn from(other: OldEvmInstruction) -> Self {
        match other {
            OldEvmInstruction::EvmTransaction { evm_tx } => Self::EvmTransaction {
                evm_tx,
                fee_type: FeePayerType::Evm,
            },
            OldEvmInstruction::SwapNativeToEther {
                lamports,
                evm_address,
            } => Self::SwapNativeToEther {
                lamports,
                evm_address,
            },
            OldEvmInstruction::FreeOwnership {} => Self::FreeOwnership {},
            OldEvmInstruction::EvmBigTransaction(big_tx) => {
                Self::EvmBigTransaction(EvmBigTransaction::from(big_tx))
            }
            OldEvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx } => {
                Self::EvmAuthorizedTransaction {
                    from,
                    unsigned_tx,
                    fee_type: FeePayerType::Evm,
                }
            }
        }
    }
}

impl Into<OldEvmInstruction> for EvmInstruction {
    fn into(self) -> OldEvmInstruction {
        match self {
            Self::EvmTransaction { evm_tx, .. } => OldEvmInstruction::EvmTransaction { evm_tx },
            Self::SwapNativeToEther {
                lamports,
                evm_address,
            } => OldEvmInstruction::SwapNativeToEther {
                lamports,
                evm_address,
            },
            Self::FreeOwnership {} => OldEvmInstruction::FreeOwnership {},
            Self::EvmBigTransaction(big_tx) => OldEvmInstruction::EvmBigTransaction(big_tx.into()),
            Self::EvmAuthorizedTransaction {
                from, unsigned_tx, ..
            } => OldEvmInstruction::EvmAuthorizedTransaction { from, unsigned_tx },
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use evm_state::{H160, H256};
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;
    use std::str::FromStr;

    #[derive(Clone, Debug)]
    struct Generator<T>(T);

    impl Arbitrary for Generator<evm::Address> {
        fn arbitrary(g: &mut Gen) -> Self {
            Generator(evm::Address::from_low_u64_ne(u64::arbitrary(g)))
        }
    }

    impl Arbitrary for Generator<evm::UnsignedTransaction> {
        fn arbitrary(g: &mut Gen) -> Self {
            let action = if bool::arbitrary(g) {
                evm::TransactionAction::Create
            } else {
                evm::TransactionAction::Call(evm::Address::from_low_u64_ne(u64::arbitrary(g)))
            };
            let tx = evm::UnsignedTransaction {
                nonce: evm::U256::from(u64::arbitrary(g)),
                gas_limit: evm::U256::from(u64::arbitrary(g)),
                gas_price: evm::U256::from(u64::arbitrary(g)),
                value: evm::U256::from(u64::arbitrary(g)),
                input: Vec::<u8>::arbitrary(g),
                action,
            };
            Generator(tx)
        }
    }

    impl Arbitrary for Generator<evm::Transaction> {
        fn arbitrary(g: &mut Gen) -> Self {
            let action = if bool::arbitrary(g) {
                evm::TransactionAction::Create
            } else {
                evm::TransactionAction::Call(evm::Address::from_low_u64_ne(u64::arbitrary(g)))
            };
            let tx = evm::Transaction {
                nonce: evm::U256::from(u64::arbitrary(g)),
                gas_limit: evm::U256::from(u64::arbitrary(g)),
                gas_price: evm::U256::from(u64::arbitrary(g)),
                value: evm::U256::from(u64::arbitrary(g)),
                input: Vec::<u8>::arbitrary(g),
                signature: evm::TransactionSignature {
                    v: 0,
                    r: H256::from_low_u64_ne(0),
                    s: H256::from_low_u64_ne(0),
                }, // signature is always invalid
                action,
            };
            Generator(tx)
        }
    }

    #[quickcheck]
    fn test_serialize_swap_native_to_ether_layout(lamports: u64, addr: Generator<evm::Address>) {
        fn custom_serialize(lamports: u64, addr: evm::Address) -> Vec<u8> {
            use byteorder::{LittleEndian, WriteBytesExt};

            let tag: [u8; 4] = [1, 0, 0, 0];
            let mut lamports_in_bytes: [u8; 8] = [0xff; 8];
            let array_len: [u8; 8] = [42, 0, 0, 0, 0, 0, 0, 0];
            let mut addr_in_hex_bytes: [u8; 42] = [0; 42];

            lamports_in_bytes
                .as_mut()
                .write_u64::<LittleEndian>(lamports)
                .unwrap();

            let addr_in_hex = format!("0x{:x}", addr);

            assert_eq!(addr_in_hex.len(), 42);

            addr_in_hex_bytes.copy_from_slice(addr_in_hex.as_bytes());

            let mut buffer = vec![];
            buffer.extend_from_slice(&tag);
            buffer.extend_from_slice(&lamports_in_bytes);
            buffer.extend_from_slice(&array_len);
            buffer.extend_from_slice(&addr_in_hex_bytes);
            buffer
        }

        let addr = addr.0;
        let data = EvmInstruction::SwapNativeToEther {
            lamports,
            evm_address: addr,
        };
        let data = bincode::serialize(&data).unwrap();

        let custom_data = custom_serialize(lamports, addr);
        assert_eq!(&*data, &*custom_data)
    }

    macro_rules! len_and_hex_buf {
        ($buffer: expr, $data: ident $(,$fixed_len: expr)?) => {
            {
                let mut array_len: [u8; 8] = [66, 0, 0, 0, 0, 0, 0, 0];
                let mut array_in_hex_bytes: [u8; 66] = [0; 66]; // max array len 2+32*2 = 0x + 2u8 for each byte

                let data_in_hex = format!("0x{:x}", $data);
                assert!(data_in_hex.len() <= 0xff);
                $(assert_eq!(data_in_hex.len(), $fixed_len * 2 + 2);)?

                array_in_hex_bytes[0..data_in_hex.len()].copy_from_slice(data_in_hex.as_bytes());
                // its not a valid number to little endian array encoding, but our len guaranted to be less < 255 bytes so its okay to write only first byte.
                assert!(data_in_hex.len() <= 255);
                array_len[0] = data_in_hex.len() as u8;

                $buffer.extend_from_slice(&array_len);
                $buffer.extend_from_slice(&array_in_hex_bytes[0..data_in_hex.len()]);
            }
        }
    }

    #[quickcheck]
    fn test_serialize_unsigned_transaction(
        addr: Generator<evm::Address>,
        tx: Generator<evm::UnsignedTransaction>,
    ) {
        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: addr.0,
            unsigned_tx: tx.0.clone(),
            fee_type: FeePayerType::Evm,
        };

        fn custom_serialize(
            from: evm::Address,
            nonce: evm::U256,
            gas_price: evm::U256,
            gas_limit: evm::U256,
            receiver: evm::TransactionAction,
            value: evm::U256,
            input: Vec<u8>,
        ) -> Vec<u8> {
            use byteorder::{LittleEndian, WriteBytesExt};

            let tag: [u8; 4] = [4, 0, 0, 0];

            let mut buffer = vec![];
            buffer.extend_from_slice(&tag);

            len_and_hex_buf!(buffer, from, 20);
            len_and_hex_buf!(buffer, nonce);
            len_and_hex_buf!(buffer, gas_price);
            len_and_hex_buf!(buffer, gas_limit);

            match receiver {
                evm::TransactionAction::Call(receiver) => {
                    let tag: [u8; 4] = [0, 0, 0, 0];
                    buffer.extend_from_slice(&tag);
                    len_and_hex_buf!(buffer, receiver, 20);
                }
                evm::TransactionAction::Create => {
                    let tag: [u8; 4] = [1, 0, 0, 0];
                    buffer.extend_from_slice(&tag);
                }
            }

            len_and_hex_buf!(buffer, value);

            let mut input_len: [u8; 8] = [0; 8];

            input_len
                .as_mut()
                .write_u64::<LittleEndian>(input.len() as u64)
                .unwrap();

            buffer.extend_from_slice(&input_len);
            buffer.extend_from_slice(&input);
            buffer
        }

        let custom_data = custom_serialize(
            addr.0,
            tx.0.nonce,
            tx.0.gas_price,
            tx.0.gas_limit,
            tx.0.action,
            tx.0.value,
            tx.0.input,
        );
        let data = bincode::serialize(&data).unwrap();
        assert_eq!(&*data, custom_data);
    }

    #[test]
    fn test_from_js_unsigned_tx() {
        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: evm_state::H160::zero(),
            unsigned_tx: evm_state::UnsignedTransaction {
                nonce: 1.into(),
                gas_price: 1.into(),
                gas_limit: 3000000.into(),

                action: evm_state::TransactionAction::Call(evm_state::H160::zero()),
                value: 100.into(),
                input: vec![],
            },
            fee_type: FeePayerType::Evm,
        };
        let result = hex::decode("040000002a0000000000000030783030303030303030303030303030303030\
        303030303030303030303030303030303030303030303003000000000000003078310300000000000000\
        30783108000000000000003078326463366330000000002a000000000000003078303030303030303030\
        303030303030303030303030303030303030303030303030303030303030300400000000000000307836340000000000000000").unwrap();
        assert_eq!(bincode::serialize(&data).unwrap(), result);

        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: evm_state::H160::repeat_byte(0x11),
            unsigned_tx: evm_state::UnsignedTransaction {
                nonce: 777.into(),
                gas_price: 33.into(),
                gas_limit: 3000000.into(),
                action: evm_state::TransactionAction::Call(evm_state::H160::repeat_byte(0xff)),
                value: 555.into(),
                input: b"test".to_vec(),
            },
            fee_type: FeePayerType::Evm,
        };
        let result = hex::decode("040000002a00000000000000307831313131313131313131313131313131313131\
        3131313131313131313131313131313131313131310500000000000000307833303904000000000000003078\
        323108000000000000003078326463366330000000002a000000000000003078666666666666666666666666\
        6666666666666666666666666666666666666666666666666666666605000000000000003078323262040000000000000074657374").unwrap();
        assert_eq!(bincode::serialize(&data).unwrap(), result);

        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: crate::evm_address_for_program(
                solana_sdk::pubkey::Pubkey::from_str(
                    "BTpMi82Q9SNKUJPmZjRg2TpAoGH26nLYPn6X1YhWRi1p",
                )
                .unwrap(),
            ),
            unsigned_tx: evm_state::UnsignedTransaction {
                nonce: 777.into(),
                gas_price: 33.into(),
                gas_limit: 3000000.into(),
                action: evm_state::TransactionAction::Call(evm_state::H160::repeat_byte(0xff)),
                value: 555.into(),
                input: b"test".to_vec(),
            },
            fee_type: FeePayerType::Evm,
        };
        let result = hex::decode("040000002a00000000000000307861636330366230313831626365363436653938353\
        4336562313534623165343063663538323762620500000000000000307833303904000000000000003078323108\
        000000000000003078326463366330000000002a000000000000003078666666666666666666666666666666666\
        6666666666666666666666666666666666666666666666605000000000000003078323262040000000000000074657374").unwrap();
        assert_eq!(bincode::serialize(&data).unwrap(), result);
    }

    #[test]
    fn test_serialize_big_allocate() {
        let size = 27;
        let ix =
            EvmInstruction::EvmBigTransaction(EvmBigTransaction::EvmTransactionAllocate { size });

        let data = bincode::serialize(&ix).unwrap();
        let big_tx_tag = [3, 0, 0, 0];

        let allocate_tag = [0, 0, 0, 0];
        let size_in_bytes = size.to_le_bytes();

        let result_data = [&big_tx_tag[..], &allocate_tag[..], &size_in_bytes[..]].concat();
        assert_eq!(data, result_data)
    }

    #[test]
    fn test_serialize_big_write() {
        let input = vec![1, 2, 3, 4];
        let offset = 27;
        let ix = EvmInstruction::EvmBigTransaction(EvmBigTransaction::EvmTransactionWrite {
            offset,
            data: input.clone(),
        });

        let data = bincode::serialize(&ix).unwrap();
        let big_tx_tag = [3, 0, 0, 0];

        let write_tag = [1, 0, 0, 0];
        let offset_in_bytes = offset.to_le_bytes();
        let input_size_in_bytes = (input.len() as u64).to_le_bytes();

        let result_data = [
            &big_tx_tag[..],
            &write_tag[..],
            &offset_in_bytes[..],
            &input_size_in_bytes[..],
            &input[..],
        ]
        .concat();
        assert_eq!(data, result_data)
    }

    #[test]
    fn test_serialize_big_execute_unsigned() {
        let from = H160::repeat_byte(0x1);
        let ix =
            EvmInstruction::EvmBigTransaction(EvmBigTransaction::EvmTransactionExecuteUnsigned {
                from,
                fee_type: FeePayerType::Evm,
            });

        let data = bincode::serialize(&ix).unwrap();
        let big_tx_tag = [3, 0, 0, 0];

        let execute_tag = [3, 0, 0, 0];
        let h160_len = (20u64 * 2 + 2).to_le_bytes();
        let from_str = format!("{:?}", from);
        let from_hex_bytes = from_str.as_bytes();

        let result_data = [
            &big_tx_tag[..],
            &execute_tag[..],
            &h160_len[..],
            from_hex_bytes,
        ]
        .concat();
        assert_eq!(data, result_data)
    }

    #[quickcheck]
    #[ignore]
    fn test_serialize_transaction(tx: Generator<evm::Transaction>) {
        let data = EvmInstruction::EvmTransaction {
            evm_tx: tx.0,
            fee_type: FeePayerType::Evm,
        };
        let data = bincode::serialize(&data).unwrap();
        assert_eq!(&*data, &[0, 1, 2, 3])
    }

    #[test]
    fn test_serialize_big_transaction_allocate_with_borsh() {
        let size = 27;
        let big_tx = EvmBigTransaction::EvmTransactionAllocate { size };
        let mut buf: Vec<u8> = vec![];
        BorshSerialize::serialize(&big_tx, &mut buf).unwrap();

        let tag = [0u8];
        let size_in_bytes = size.to_le_bytes();

        let result_data = [&tag[..], &size_in_bytes[..]].concat();
        assert_eq!(buf, result_data)
    }

    #[test]
    fn test_serialize_big_transaction_write_with_borsh() {
        let input = vec![1, 2, 3, 4];
        let offset = 27;
        let big_tx = EvmBigTransaction::EvmTransactionWrite {
            offset,
            data: input.clone(),
        };
        let mut buf: Vec<u8> = vec![];
        BorshSerialize::serialize(&big_tx, &mut buf).unwrap();

        let tag = [1u8];
        let offset_in_bytes = offset.to_le_bytes();
        let input_size_in_bytes = (input.len() as u32).to_le_bytes();

        let result_data = [
            &tag[..],
            &offset_in_bytes[..],
            &input_size_in_bytes[..],
            &input[..],
        ]
        .concat();
        assert_eq!(buf, result_data)
    }

    #[test]
    fn test_serialize_big_transaction_execute_with_borsh() {
        let big_tx = EvmBigTransaction::EvmTransactionExecute {
            fee_type: FeePayerType::Native,
        };
        let mut buf: Vec<u8> = vec![];
        BorshSerialize::serialize(&big_tx, &mut buf).unwrap();

        let tag = [2u8];
        let fee_type = [1];
        let result_data = [&tag[..], &fee_type[..]].concat();
        assert_eq!(buf, result_data);
    }

    #[test]
    fn test_serialize_big_transaction_execute_unsigned_with_borsh() {
        let from = H160::repeat_byte(0x1);
        let big_tx = EvmBigTransaction::EvmTransactionExecuteUnsigned {
            from,
            fee_type: FeePayerType::Evm,
        };
        let mut buf: Vec<u8> = vec![];
        BorshSerialize::serialize(&big_tx, &mut buf).unwrap();

        let tag = [3u8];
        let from_in_bytes = from.as_bytes();
        let fee_type = [0];

        let result_data = [&tag[..], &from_in_bytes[..], &fee_type[..]].concat();
        assert_eq!(buf, result_data)
    }

    #[test]
    fn test_deserialize_big_transaction_with_borsh() {
        let big_tx = hex::decode("000000000000000001").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &big_tx[..]).unwrap(),
            EvmBigTransaction::EvmTransactionAllocate {
                size: 72057594037927936
            }
        );

        let big_tx = hex::decode("01adde00000000000006000000424038030638").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &big_tx[..]).unwrap(),
            EvmBigTransaction::EvmTransactionWrite {
                offset: 57005,
                data: vec![66, 64, 56, 3, 6, 56]
            }
        );

        let big_tx = hex::decode("0200").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &big_tx[..]).unwrap(),
            EvmBigTransaction::EvmTransactionExecute {
                fee_type: FeePayerType::Evm
            }
        );

        let big_tx = hex::decode("03050505050505050505050505050505050505050500").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &big_tx[..]).unwrap(),
            EvmBigTransaction::EvmTransactionExecuteUnsigned {
                from: H160::repeat_byte(5),
                fee_type: FeePayerType::Evm
            }
        );
    }

    #[test]
    fn test_deserialize_big_transaction_from_invalid_data_should_fail() {
        let empty_instruction = vec![];
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &empty_instruction[..])
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );

        let invalid_instruction = hex::decode("03").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &invalid_instruction[..])
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );

        let invalid_instruction = hex::decode("04").unwrap();
        assert_eq!(
            <EvmBigTransaction as BorshDeserialize>::deserialize(&mut &invalid_instruction[..])
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );
    }

    #[test]
    fn test_serialize_evm_instruction_transaction_with_borsh() {
        let evm_tx = evm::Transaction {
            nonce: evm::U256::from(1),
            gas_price: evm::U256::from(10),
            gas_limit: evm::U256::from(100),
            action: evm::TransactionAction::Create,
            value: evm::U256::from(5),
            signature: evm::TransactionSignature {
                v: 20,
                r: H256::from_low_u64_be(6),
                s: H256::from_low_u64_be(6),
            },
            input: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        };
        let data = EvmInstruction::EvmTransaction {
            evm_tx,
            fee_type: FeePayerType::Evm,
        };
        let result = hex::decode("00\
        0100000000000000000000000000000000000000000000000000000000000000\
        0a00000000000000000000000000000000000000000000000000000000000000\
        6400000000000000000000000000000000000000000000000000000000000000\
        01\
        0500000000000000000000000000000000000000000000000000000000000000\
        140000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006\
        0a00000000010203040506070809\
        00").unwrap();
        let mut buf = vec![];
        BorshSerialize::serialize(&data, &mut buf).unwrap();
        assert_eq!(buf, result);
    }

    #[test]
    fn test_serialize_evm_instruction_swap_to_ether_with_borsh() {
        let data = EvmInstruction::SwapNativeToEther {
            lamports: 1000,
            evm_address: H160::repeat_byte(0x1),
        };
        let result = hex::decode(
            "01\
        e803000000000000\
        0101010101010101010101010101010101010101",
        )
        .unwrap();
        let mut buf = vec![];
        BorshSerialize::serialize(&data, &mut buf).unwrap();
        assert_eq!(buf, result);
    }

    #[test]
    fn test_serialize_evm_instruction_free_ownership_with_borsh() {
        let data = EvmInstruction::FreeOwnership {};
        let result = hex::decode("02").unwrap();
        let mut buf = vec![];
        BorshSerialize::serialize(&data, &mut buf).unwrap();
        assert_eq!(buf, result);
    }

    #[test]
    fn test_serialize_evm_instruction_evm_big_transaction_with_borsh() {
        let data = EvmInstruction::EvmBigTransaction(EvmBigTransaction::EvmTransactionWrite {
            offset: 16,
            data: vec![1, 2, 3, 4],
        });
        let result = hex::decode("030110000000000000000400000001020304").unwrap();
        let mut buf = vec![];
        BorshSerialize::serialize(&data, &mut buf).unwrap();
        assert_eq!(buf, result);
    }

    #[test]
    fn test_serialize_evm_instruction_evm_authorized_transaction_with_borsh() {
        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: H160::repeat_byte(0x1),
            unsigned_tx: evm::UnsignedTransaction {
                nonce: evm::U256::from(10),
                gas_price: evm::U256::from(20),
                gas_limit: evm::U256::from(30),
                action: evm::TransactionAction::Create,
                value: evm::U256::from(40),
                input: vec![10, 20, 30, 40],
            },
            fee_type: FeePayerType::Evm,
        };
        let result = hex::decode(
            "04\
        0101010101010101010101010101010101010101\
        0a00000000000000000000000000000000000000000000000000000000000000\
        1400000000000000000000000000000000000000000000000000000000000000\
        1e00000000000000000000000000000000000000000000000000000000000000\
        01\
        2800000000000000000000000000000000000000000000000000000000000000\
        040000000a141e28\
        00",
        )
        .unwrap();
        let mut buf = vec![];
        BorshSerialize::serialize(&data, &mut buf).unwrap();
        assert_eq!(buf, result);
    }

    #[test]
    fn test_deserialize_evm_instrtion_with_borsh() {
        let instruction = hex::decode("00\
        0100000000000000000000000000000000000000000000000000000000000000\
        0a00000000000000000000000000000000000000000000000000000000000000\
        6400000000000000000000000000000000000000000000000000000000000000\
        001111111111111111111111111111111111111111\
        0500000000000000000000000000000000000000000000000000000000000000\
        140000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006\
        0a000000534951394a0e250c1722\
        00").unwrap();
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &instruction[..]).unwrap(),
            EvmInstruction::EvmTransaction {
                evm_tx: evm::Transaction {
                    nonce: evm::U256::from(1),
                    gas_price: evm::U256::from(10),
                    gas_limit: evm::U256::from(100),
                    action: evm::TransactionAction::Call(H160::repeat_byte(0x11)),
                    value: evm::U256::from(5),
                    signature: evm::TransactionSignature {
                        v: 20,
                        r: H256::from_low_u64_be(6),
                        s: H256::from_low_u64_be(6),
                    },
                    input: vec![83, 73, 81, 57, 74, 14, 37, 12, 23, 34],
                },
                fee_type: FeePayerType::Evm,
            }
        );

        let instruction =
            hex::decode("01e803000000000000ffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &instruction[..]).unwrap(),
            EvmInstruction::SwapNativeToEther {
                lamports: 1000,
                evm_address: H160::repeat_byte(0xff),
            }
        );

        let instruction = hex::decode("02").unwrap();
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &instruction[..]).unwrap(),
            EvmInstruction::FreeOwnership {}
        );

        let instruction = hex::decode(
            "04\
        0101010101010101010101010101010101010101\
        0001000000000000000000000000000000000000000000000000000000000000\
        0001000000000000000000000000000000000000000000000000000000000000\
        0001000000000000000000000000000000000000000000000000000000000000\
        01\
        0001000000000000000000000000000000000000000000000000000000000000\
        040000000a141e28\
        00",
        )
        .unwrap();
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &instruction[..]).unwrap(),
            EvmInstruction::EvmAuthorizedTransaction {
                from: H160::repeat_byte(0x1),
                unsigned_tx: evm::UnsignedTransaction {
                    nonce: evm::U256::from(256),
                    gas_price: evm::U256::from(256),
                    gas_limit: evm::U256::from(256),
                    action: evm::TransactionAction::Create,
                    value: evm::U256::from(256),
                    input: vec![10, 20, 30, 40],
                },
                fee_type: FeePayerType::Evm,
            }
        );
    }

    #[test]
    fn test_deserialize_evm_instruction_from_invalid_data_should_fail() {
        let empty_instruction = vec![];
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &empty_instruction[..])
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );

        // data size is too small
        let invalid_instruction =
            hex::decode("01e803000000000000ffffffffffffffffffffffffffffffffffffff").unwrap();
        assert_eq!(
            <EvmInstruction as BorshDeserialize>::deserialize(&mut &invalid_instruction[..])
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );
    }
}
