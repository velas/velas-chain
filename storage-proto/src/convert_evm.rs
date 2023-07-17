use crate::convert::*;
use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};
//
// Evm compatibility layer
//

trait ConvertFromBytes {
    fn len_bytes() -> usize;

    fn from_slice(bytes: &[u8]) -> Self;

    fn into_vec(self) -> Vec<u8>;
}

impl ConvertFromBytes for evm_state::H256 {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }

    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ConvertFromBytes for evm_state::H160 {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }

    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ConvertFromBytes for evm_state::Bloom {
    fn len_bytes() -> usize {
        Self::len_bytes()
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
    fn into_vec(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// This function is consuming on purpose, it is used only in TryFrom, and consuming allows staticly check if all fields was taken.
fn convert_from_bytes<T: ConvertFromBytes>(slice: Vec<u8>) -> Result<T, &'static str> {
    if slice.len() != T::len_bytes() {
        return Err("Incorrect size of some field in protobuf structures");
    }
    Ok(T::from_slice(&slice))
}

impl From<evm_state::BlockHeader> for generated_evm::EvmBlockHeader {
    fn from(header: evm_state::BlockHeader) -> Self {
        let transactions: Vec<_> = header
            .transactions
            .into_iter()
            .map(ConvertFromBytes::into_vec)
            .collect();
        Self {
            parent_hash: header.parent_hash.into_vec(),
            state_root: header.state_root.into_vec(),
            native_chain_hash: header.native_chain_hash.into_vec(),
            transactions,
            transactions_root: header.transactions_root.into_vec(),
            receipts_root: header.receipts_root.into_vec(),
            logs_bloom: header.logs_bloom.into_vec(),
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            native_chain_slot: header.native_chain_slot,
            version: header.version.into(),
        }
    }
}

impl TryFrom<generated_evm::EvmBlockHeader> for evm_state::BlockHeader {
    type Error = &'static str;
    fn try_from(header: generated_evm::EvmBlockHeader) -> Result<Self, Self::Error> {
        let transactions: Result<Vec<_>, _> = header
            .transactions
            .into_iter()
            .map(convert_from_bytes)
            .collect();
        Ok(Self {
            parent_hash: convert_from_bytes(header.parent_hash)?,
            state_root: convert_from_bytes(header.state_root)?,
            native_chain_hash: convert_from_bytes(header.native_chain_hash)?,
            transactions: transactions?,
            transactions_root: convert_from_bytes(header.transactions_root)?,
            receipts_root: convert_from_bytes(header.receipts_root)?,
            logs_bloom: convert_from_bytes(header.logs_bloom)?,
            block_number: header.block_number,
            gas_limit: header.gas_limit,
            gas_used: header.gas_used,
            timestamp: header.timestamp,
            native_chain_slot: header.native_chain_slot,
            version: header.version.try_into()?,
        })
    }
}

impl From<evm_state::TransactionReceipt> for generated_evm::TransactionReceipt {
    fn from(tx: evm_state::TransactionReceipt) -> Self {
        Self {
            transaction: Some(tx.transaction.into()),
            status: Some(tx.status.into()),
            logs: tx.logs.into_iter().map(From::from).collect(),
            logs_bloom: tx.logs_bloom.into_vec(),

            used_gas: tx.used_gas,
            index: tx.index,
            block_number: tx.block_number,
        }
    }
}

impl TryFrom<generated_evm::TransactionReceipt> for evm_state::TransactionReceipt {
    type Error = &'static str;

    fn try_from(tx: generated_evm::TransactionReceipt) -> Result<Self, Self::Error> {
        let logs: Result<Vec<_>, _> = tx.logs.into_iter().map(TryFrom::try_from).collect();
        Ok(Self {
            transaction: tx
                .transaction
                .ok_or("Transaction body is missing")?
                .try_into()?,
            status: tx
                .status
                .ok_or("Transaction status is missing")?
                .try_into()?,
            logs: logs?,
            logs_bloom: convert_from_bytes(tx.logs_bloom)?,
            block_number: tx.block_number,
            used_gas: tx.used_gas,
            index: tx.index,
        })
    }
}

impl From<evm_state::TransactionInReceipt> for generated_evm::TransactionInReceipt {
    fn from(tx: evm_state::TransactionInReceipt) -> Self {
        generated_evm::TransactionInReceipt {
            transaction: Some(match tx {
                evm_state::TransactionInReceipt::Signed(tx) => {
                    generated_evm::transaction_in_receipt::Transaction::Signed(tx.into())
                }
                evm_state::TransactionInReceipt::Unsigned(unsigned) => {
                    generated_evm::transaction_in_receipt::Transaction::Unsigned(unsigned.into())
                }
            }),
        }
    }
}

impl TryFrom<generated_evm::TransactionInReceipt> for evm_state::TransactionInReceipt {
    type Error = &'static str;
    fn try_from(tx: generated_evm::TransactionInReceipt) -> Result<Self, Self::Error> {
        Ok(
            match tx
                .transaction
                .ok_or("Empty transaction body in transaction receipt")?
            {
                generated_evm::transaction_in_receipt::Transaction::Unsigned(unsigned) => {
                    evm_state::TransactionInReceipt::Unsigned(unsigned.try_into()?)
                }
                generated_evm::transaction_in_receipt::Transaction::Signed(tx) => {
                    evm_state::TransactionInReceipt::Signed(tx.try_into()?)
                }
            },
        )
    }
}

impl From<evm_state::Transaction> for generated_evm::Transaction {
    fn from(tx: evm_state::Transaction) -> Self {
        let bytes = rlp::encode(&tx);
        Self {
            rlp_encoded_body: bytes.to_vec(),
        }
    }
}

impl TryFrom<generated_evm::Transaction> for evm_state::Transaction {
    type Error = &'static str;
    fn try_from(tx: generated_evm::Transaction) -> Result<Self, Self::Error> {
        rlp::decode(&tx.rlp_encoded_body).map_err(|_| "Failed to deserialize rlp tx body")
    }
}

impl From<evm_state::UnsignedTransactionWithCaller>
    for generated_evm::UnsignedTransactionWithCaller
{
    fn from(unsigned: evm_state::UnsignedTransactionWithCaller) -> Self {
        let bytes = rlp::encode(&unsigned.unsigned_tx);
        Self {
            rlp_encoded_body: bytes.to_vec(),
            chain_id: unsigned.chain_id,
            caller: unsigned.caller.into_vec(),
            signed_compatible: unsigned.signed_compatible,
        }
    }
}

impl TryFrom<generated_evm::UnsignedTransactionWithCaller>
    for evm_state::UnsignedTransactionWithCaller
{
    type Error = &'static str;
    fn try_from(
        unsigned: generated_evm::UnsignedTransactionWithCaller,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: unsigned.chain_id,
            signed_compatible: unsigned.signed_compatible,
            caller: convert_from_bytes(unsigned.caller)?,
            unsigned_tx: rlp::decode(&unsigned.rlp_encoded_body)
                .map_err(|_| "Failed to deserialize rlp tx body")?,
        })
    }
}

impl From<evm_state::Log> for generated_evm::Log {
    fn from(logs: evm_state::Log) -> Self {
        let topics: Vec<_> = logs
            .topics
            .into_iter()
            .map(ConvertFromBytes::into_vec)
            .collect();
        Self {
            topics,
            address: logs.address.into_vec(),
            data: logs.data,
        }
    }
}

impl TryFrom<generated_evm::Log> for evm_state::Log {
    type Error = &'static str;
    fn try_from(logs: generated_evm::Log) -> Result<Self, Self::Error> {
        let topics: Result<Vec<_>, _> = logs.topics.into_iter().map(convert_from_bytes).collect();
        Ok(Self {
            data: logs.data,
            address: convert_from_bytes(logs.address)?,
            topics: topics?,
        })
    }
}

impl From<evm_state::ExitReason> for generated_evm::ExitReason {
    fn from(reason: evm_state::ExitReason) -> Self {
        use evm_state::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed};
        use generated_evm::exit_reason::ExitVariant;

        fn error_to_generated(error: ExitError) -> generated_evm::ExitReason {
            match error {
                ExitError::CallTooDeep => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CallTooDeep.into(),
                },
                ExitError::CreateCollision => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateCollision.into(),
                },
                ExitError::CreateContractLimit => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateContractLimit.into(),
                },
                ExitError::CreateEmpty => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::CreateEmpty.into(),
                },
                ExitError::DesignatedInvalid => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::DesignatedInvalid.into(),
                },
                ExitError::InvalidCode(opcode) => generated_evm::ExitReason {
                    fatal: false,
                    other: opcode.as_u8().to_string(),
                    variant: ExitVariant::InvalidCode.into(),
                },
                ExitError::InvalidJump => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::InvalidJump.into(),
                },
                ExitError::InvalidRange => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::InvalidRange.into(),
                },
                ExitError::OutOfFund => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfFund.into(),
                },
                ExitError::OutOfGas => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfGas.into(),
                },
                ExitError::OutOfOffset => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::OutOfOffset.into(),
                },
                ExitError::PCUnderflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::PcUnderflow.into(),
                },
                ExitError::StackOverflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::StackOverflow.into(),
                },
                ExitError::StackUnderflow => generated_evm::ExitReason {
                    fatal: false,
                    other: String::new(),
                    variant: ExitVariant::StackUnderflow.into(),
                },
                ExitError::Other(s) => generated_evm::ExitReason {
                    fatal: false,
                    other: String::from(&*s),
                    variant: ExitVariant::Other.into(),
                },
            }
        }
        match reason {
            ExitReason::Revert(ExitRevert::Reverted) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Reverted.into(),
            },
            ExitReason::Succeed(ExitSucceed::Returned) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Returned.into(),
            },
            ExitReason::Succeed(ExitSucceed::Stopped) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Stopped.into(),
            },
            ExitReason::Succeed(ExitSucceed::Suicided) => Self {
                fatal: false,
                other: String::new(),
                variant: ExitVariant::Suicided.into(),
            },
            ExitReason::Fatal(ExitFatal::NotSupported) => Self {
                fatal: true,
                other: String::new(),
                variant: ExitVariant::NotSupported.into(),
            },
            ExitReason::Fatal(ExitFatal::UnhandledInterrupt) => Self {
                fatal: true,
                other: String::new(),
                variant: ExitVariant::UnhandledInterrupt.into(),
            },
            ExitReason::Fatal(ExitFatal::Other(s)) => Self {
                fatal: true,
                other: String::from(&*s),
                variant: ExitVariant::OtherFatal.into(),
            },
            ExitReason::Error(e) => error_to_generated(e),
            ExitReason::Fatal(ExitFatal::CallErrorAsFatal(e)) => Self {
                fatal: true,
                ..error_to_generated(e)
            },
        }
    }
}

impl TryFrom<generated_evm::ExitReason> for evm_state::ExitReason {
    type Error = &'static str;
    fn try_from(
        header: generated_evm::ExitReason,
    ) -> Result<Self, <Self as TryFrom<generated_evm::ExitReason>>::Error> {
        use evm_state::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed, Opcode};
        use generated_evm::exit_reason::ExitVariant;
        let error_or_fatal = match ExitVariant::from_i32(header.variant)
            .ok_or("Enum error variant out of bounds")?
        {
            ExitVariant::Returned => return Ok(ExitReason::Succeed(ExitSucceed::Returned)),
            ExitVariant::Stopped => return Ok(ExitReason::Succeed(ExitSucceed::Stopped)),
            ExitVariant::Suicided => return Ok(ExitReason::Succeed(ExitSucceed::Suicided)),
            ExitVariant::Reverted => return Ok(ExitReason::Revert(ExitRevert::Reverted)),
            ExitVariant::NotSupported => return Ok(ExitReason::Fatal(ExitFatal::NotSupported)),
            ExitVariant::UnhandledInterrupt => {
                return Ok(ExitReason::Fatal(ExitFatal::UnhandledInterrupt))
            }
            ExitVariant::OtherFatal => {
                return Ok(ExitReason::Fatal(ExitFatal::Other(header.other.into())))
            }
            ExitVariant::Other => ExitError::Other(header.other.into()),
            ExitVariant::CallTooDeep => ExitError::CallTooDeep,
            ExitVariant::CreateCollision => ExitError::CreateCollision,
            ExitVariant::CreateContractLimit => ExitError::CreateContractLimit,
            ExitVariant::CreateEmpty => ExitError::CreateEmpty,
            ExitVariant::DesignatedInvalid => ExitError::DesignatedInvalid,
            ExitVariant::InvalidCode => ExitError::InvalidCode(Opcode(
                u8::from_str(&header.other).map_err(|_| "Failed to decode opcode")?,
            )),
            ExitVariant::InvalidJump => ExitError::InvalidJump,
            ExitVariant::InvalidRange => ExitError::InvalidRange,
            ExitVariant::StackOverflow => ExitError::StackOverflow,
            ExitVariant::StackUnderflow => ExitError::StackUnderflow,
            ExitVariant::OutOfFund => ExitError::OutOfFund,
            ExitVariant::OutOfGas => ExitError::OutOfGas,
            ExitVariant::OutOfOffset => ExitError::OutOfOffset,
            ExitVariant::PcUnderflow => ExitError::PCUnderflow,
        };
        if header.fatal {
            Ok(ExitReason::Fatal(ExitFatal::CallErrorAsFatal(
                error_or_fatal,
            )))
        } else {
            Ok(ExitReason::Error(error_or_fatal))
        }
    }
}

impl From<(evm_state::H256, evm_state::TransactionReceipt)> for generated_evm::ReceiptWithHash {
    fn from(tx_with_hash: (evm_state::H256, evm_state::TransactionReceipt)) -> Self {
        Self {
            hash: tx_with_hash.0.into_vec(),
            transaction: Some(tx_with_hash.1.into()),
        }
    }
}

impl TryFrom<generated_evm::ReceiptWithHash> for (evm_state::H256, evm_state::TransactionReceipt) {
    type Error = &'static str;
    fn try_from(tx_with_hash: generated_evm::ReceiptWithHash) -> Result<Self, Self::Error> {
        Ok((
            convert_from_bytes(tx_with_hash.hash)?,
            tx_with_hash
                .transaction
                .ok_or("Transaction is missing in receipt with hash")?
                .try_into()?,
        ))
    }
}

impl From<evm_state::Block> for generated_evm::EvmFullBlock {
    fn from(block: evm_state::Block) -> Self {
        let transactions: Vec<_> = block.transactions.into_iter().map(Into::into).collect();
        Self {
            transactions,
            header: Some(block.header.into()),
        }
    }
}

impl TryFrom<generated_evm::EvmFullBlock> for evm_state::Block {
    type Error = &'static str;
    fn try_from(block: generated_evm::EvmFullBlock) -> Result<Self, Self::Error> {
        let transactions: Result<Vec<_>, _> = block
            .transactions
            .into_iter()
            .map(TryInto::try_into)
            .collect();
        Ok(Self {
            transactions: transactions?,
            header: block
                .header
                .ok_or("Block header is missing in full block")?
                .try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_transaction() {
        let tx =
            evm_state::TransactionInReceipt::Unsigned(evm_state::UnsignedTransactionWithCaller {
                unsigned_tx: evm_state::UnsignedTransaction {
                    nonce: 1.into(),
                    gas_limit: 2.into(),
                    gas_price: 3.into(),
                    action: evm_state::TransactionAction::Call(evm_state::H160::random()),
                    value: 5.into(),
                    input: b"random bytes".to_vec(),
                },
                caller: evm_state::H160::random(),
                chain_id: 0xdead,
                signed_compatible: true,
            });
        let tx_serialized: generated_evm::TransactionInReceipt = tx.clone().into();
        assert_eq!(tx, tx_serialized.try_into().unwrap());
        let tx =
            evm_state::TransactionInReceipt::Unsigned(evm_state::UnsignedTransactionWithCaller {
                unsigned_tx: evm_state::UnsignedTransaction {
                    nonce: 5.into(),
                    gas_limit: 7.into(),
                    gas_price: 123123213.into(),
                    action: evm_state::TransactionAction::Create,
                    value: 432432.into(),
                    input: b"123random bytes".to_vec(),
                },
                caller: evm_state::H160::random(),
                chain_id: 0xde2d,
                signed_compatible: false,
            });
        let tx_serialized: generated_evm::TransactionInReceipt = tx.clone().into();
        assert_eq!(tx, tx_serialized.try_into().unwrap());

        let tx = evm_state::TransactionInReceipt::Signed(evm_state::Transaction {
            nonce: 1.into(),
            gas_limit: 4.into(),
            gas_price: 6.into(),
            action: evm_state::TransactionAction::Create,
            value: 23.into(),
            input: b"123random bytes".to_vec(),
            signature: evm_state::TransactionSignature {
                v: 120,
                r: evm_state::H256::random(),
                s: evm_state::H256::random(),
            },
        });
        let tx_serialized: generated_evm::TransactionInReceipt = tx.clone().into();
        assert_eq!(tx, tx_serialized.try_into().unwrap());
    }

    #[test]
    fn test_evm_tx_receipt() {
        let tx =
            evm_state::TransactionInReceipt::Unsigned(evm_state::UnsignedTransactionWithCaller {
                unsigned_tx: evm_state::UnsignedTransaction {
                    nonce: 1.into(),
                    gas_limit: 2.into(),
                    gas_price: 3.into(),
                    action: evm_state::TransactionAction::Call(evm_state::H160::random()),
                    value: 5.into(),
                    input: b"random bytes".to_vec(),
                },
                caller: evm_state::H160::random(),
                chain_id: 0xdead,
                signed_compatible: true,
            });
        let receipt = evm_state::TransactionReceipt {
            transaction: tx,
            status: evm_state::ExitReason::Fatal(evm_state::ExitFatal::Other("test error".into())),
            block_number: 12313,
            index: 15345,
            used_gas: 543543,
            logs_bloom: evm_state::Bloom::random(),
            logs: vec![evm_state::Log {
                address: evm_state::H160::random(),
                data: b"random string topic".to_vec(),
                topics: vec![evm_state::H256::random(), evm_state::H256::random()],
            }],
        };
        let receipt_serialized: generated_evm::TransactionReceipt = receipt.clone().into();
        assert_eq!(receipt, receipt_serialized.try_into().unwrap());
    }

    #[test]
    fn test_evm_block() {
        let block = evm_state::BlockHeader {
            parent_hash: evm_state::H256::random(),
            state_root: evm_state::H256::random(),
            native_chain_hash: evm_state::H256::random(),
            native_chain_slot: 6,
            block_number: 234,
            gas_limit: 543,
            gas_used: 612,
            timestamp: 123123612,
            transactions: vec![
                evm_state::H256::random(),
                evm_state::H256::random(),
                evm_state::H256::random(),
            ],
            logs_bloom: evm_state::Bloom::random(),
            transactions_root: evm_state::H256::random(),
            receipts_root: evm_state::H256::random(),
            version: evm_state::BlockVersion::VersionConsistentHashes,
        };

        let block_serialized: generated_evm::EvmBlockHeader = block.clone().into();
        assert_eq!(block, block_serialized.try_into().unwrap());
    }

    #[test]
    fn test_evm_full_block() {
        let block = evm_state::BlockHeader {
            parent_hash: evm_state::H256::random(),
            state_root: evm_state::H256::random(),
            native_chain_hash: evm_state::H256::random(),
            native_chain_slot: 6,
            block_number: 234,
            gas_limit: 543,
            gas_used: 612,
            timestamp: 123123612,
            transactions: vec![
                evm_state::H256::random(),
                evm_state::H256::random(),
                evm_state::H256::random(),
            ],
            logs_bloom: evm_state::Bloom::random(),
            transactions_root: evm_state::H256::random(),
            receipts_root: evm_state::H256::random(),
            version: evm_state::BlockVersion::InitVersion,
        };
        let tx1 =
            evm_state::TransactionInReceipt::Unsigned(evm_state::UnsignedTransactionWithCaller {
                unsigned_tx: evm_state::UnsignedTransaction {
                    nonce: 1.into(),
                    gas_limit: 2.into(),
                    gas_price: 3.into(),
                    action: evm_state::TransactionAction::Call(evm_state::H160::random()),
                    value: 5.into(),
                    input: b"random bytes".to_vec(),
                },
                caller: evm_state::H160::random(),
                chain_id: 0xdead,
                signed_compatible: false,
            });

        let tx2 = evm_state::TransactionInReceipt::Signed(evm_state::Transaction {
            nonce: 1.into(),
            gas_limit: 4.into(),
            gas_price: 6.into(),
            action: evm_state::TransactionAction::Create,
            value: 23.into(),
            input: b"123random bytes".to_vec(),
            signature: evm_state::TransactionSignature {
                v: 120,
                r: evm_state::H256::random(),
                s: evm_state::H256::random(),
            },
        });
        let transactions = vec![
            evm_state::TransactionReceipt {
                transaction: tx1,
                status: evm_state::ExitReason::Fatal(evm_state::ExitFatal::Other(
                    "test error".into(),
                )),
                block_number: 12313,
                index: 15345,
                used_gas: 543543,
                logs_bloom: evm_state::Bloom::random(),
                logs: vec![evm_state::Log {
                    address: evm_state::H160::random(),
                    data: b"random string topic".to_vec(),
                    topics: vec![evm_state::H256::random(), evm_state::H256::random()],
                }],
            },
            evm_state::TransactionReceipt {
                transaction: tx2,
                status: evm_state::ExitReason::Error(evm_state::ExitError::Other(
                    "test error".into(),
                )),
                block_number: 12313,
                index: 15345,
                used_gas: 543543,
                logs_bloom: evm_state::Bloom::random(),
                logs: vec![evm_state::Log {
                    address: evm_state::H160::random(),
                    data: b"random string topic".to_vec(),
                    topics: vec![evm_state::H256::random(), evm_state::H256::random()],
                }],
            },
        ];
        let block = evm_state::Block {
            transactions: transactions
                .into_iter()
                .map(|t| (evm_state::H256::random(), t))
                .collect(),
            header: block,
        };

        let block_serialized: generated_evm::EvmFullBlock = block.clone().into();
        assert_eq!(block, block_serialized.try_into().unwrap());
    }
}
