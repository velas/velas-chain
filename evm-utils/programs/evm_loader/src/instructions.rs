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

    /// Execute merged unsigned transaction, in order to do this, user should make sure that transaction is successfully writed.
    EvmTransactionExecuteUnsigned { from: evm::Address },
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

    use evm_state::{H160, H256};
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

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

    #[quickcheck]
    #[ignore]
    fn test_serialize_unsigned_transaction(
        addr: Generator<evm::Address>,
        tx: Generator<evm::UnsignedTransaction>,
    ) {
        let data = EvmInstruction::EvmAuthorizedTransaction {
            from: addr.0,
            unsigned_tx: tx.0,
        };

        let data = bincode::serialize(&data).unwrap();
        assert_eq!(&*data, &[0, 1, 2, 3])
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
            &from_hex_bytes[..],
        ]
        .concat();
        assert_eq!(data, result_data)
    }

    #[quickcheck]
    #[ignore]
    fn test_serialize_transaction(tx: Generator<evm::Transaction>) {
        let data = EvmInstruction::EvmTransaction { evm_tx: tx.0 };
        let data = bincode::serialize(&data).unwrap();
        assert_eq!(&*data, &[0, 1, 2, 3])
    }
}
