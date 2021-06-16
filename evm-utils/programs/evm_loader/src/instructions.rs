use super::scope::*;
use serde::{Deserialize, Serialize};

/// Solana blockchain limit amount of data that transaction can have.
/// To get around this limitation, we use design that is similar to LoaderInstruction in sdk.

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmBigTransaction {
    /// Allocate data in storage, pay fee should be taken from EVM.
    EvmTransactionAllocate { size: u64 },

    /// Store part of EVM transaction into temporary storage, in order to execute it later.
    EvmTransactionWrite { offset: u64, data: Vec<u8> },

    /// Execute merged transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecute {},
}

#[derive(Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EvmInstruction {
    /// Execute native EVM transaction.
    ///
    /// Outer args:
    /// account_key[0] - `[writable]`. EVM state account, used for lock.
    /// account_key[1] - `[readable]`. Optional argument, used in case tokens swaps from EVM back to native.
    ///
    EvmTransaction { evm_tx: evm::Transaction },

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
    },
}

#[cfg(test)]
mod test {

    use super::*;

    use evm_state::H256;
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
        };
        let result = hex::decode("040000002a00000000000000307861636330366230313831626365363436653938353\
        4336562313534623165343063663538323762620500000000000000307833303904000000000000003078323108\
        000000000000003078326463366330000000002a000000000000003078666666666666666666666666666666666\
        6666666666666666666666666666666666666666666666605000000000000003078323262040000000000000074657374").unwrap();
        assert_eq!(bincode::serialize(&data).unwrap(), result);
    }

    #[quickcheck]
    #[ignore]
    fn test_serialize_transaction(tx: Generator<evm::Transaction>) {
        let data = EvmInstruction::EvmTransaction { evm_tx: tx.0 };
        let data = bincode::serialize(&data).unwrap();
        assert_eq!(&*data, &[0, 1, 2, 3])
    }
}
