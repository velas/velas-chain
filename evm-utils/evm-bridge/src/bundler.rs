use std::sync::Arc;
use log::error;
use crate::rpc_client::AsyncRpcClient;
use crate::bridge::{from_client_error, EvmResult, EvmBridge};
use evm_rpc::bundler::UserOperation;
use evm_rpc::{Bytes, Error, FormatHex, Hex, RPCTransaction};
use evm_state::{Address, Gas};
use primitive_types::{H256, U256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snafu::ResultExt;
use solana_client::client_error::ClientErrorKind;
use solana_client::rpc_request::{RpcError, RpcRequest, RpcResponseErrorData};
use solana_evm_loader_program::scope::evm;

type U48 = u64;

// impl FormatHex for u64 {
//     fn format_hex(&self) -> String {
//         format_hex_trimmed(self)
//     }
//     fn from_hex(data: &str) -> Result<Self, Error> {
//         Self::from_str_radix(data, 16).with_context(|_| IntError {
//             input_data: data.to_string(),
//         })
//     }
// }

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValidationResult {
    pub return_info: ReturnInfo,
    pub sender_info: StakeInfo,
    pub factory_info: StakeInfo,
    pub paymaster_info: StakeInfo,
}

impl Encodable for ValidationResult {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4)
            .append(&self.return_info)
            .append(&self.sender_info)
            .append(&self.factory_info)
            .append(&self.paymaster_info);
    }
}

impl Decodable for ValidationResult {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            return_info: rlp.val_at(0)?,
            sender_info: rlp.val_at(1)?,
            factory_info: rlp.val_at(2)?,
            paymaster_info: rlp.val_at(3)?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReturnInfo {
    pre_op_gas: U256,
    prefund: U256,
    sig_failed: bool,
    valid_after: U48,
    valid_until: U48,
    paymaster_context: Bytes,
}

impl ReturnInfo {
    pub fn is_failed(&self) -> bool {
        self.sig_failed
    }
}

impl Encodable for ReturnInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(6)
            .append(&self.pre_op_gas)
            .append(&self.prefund)
            .append(&self.sig_failed)
            .append(&self.valid_after)
            .append(&self.valid_until)
            .append(&self.paymaster_context.0);
    }
}

impl Decodable for ReturnInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            pre_op_gas: rlp.val_at(0)?,
            prefund: rlp.val_at(1)?,
            sig_failed: rlp.val_at(2)?,
            valid_after: rlp.val_at(3)?,
            valid_until: rlp.val_at(4)?,
            paymaster_context: Bytes::from(rlp.val_at::<Vec<u8>>(5)?),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StakeInfo {
    stake: U256,
    unstake_delay_sec: U256,
}

impl Encodable for StakeInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.stake)
            .append(&self.unstake_delay_sec);
    }
}

impl Decodable for StakeInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            stake: rlp.val_at(0)?,
            unstake_delay_sec: rlp.val_at(1)?,
        })
    }
}

/// What it needs to do?
/// - check if factory is staked
/// -
#[derive(Clone, Debug)]
pub struct Bundler {}

impl Bundler {
    pub async fn check_user_op(
        &self,
        rpc_client: &AsyncRpcClient,
        user_op: &UserOperation,
    ) -> EvmResult<()> {
        let sender_code = rpc_client
            .get_evm_code(&user_op.get_sender())
            .await
            .map_err(from_client_error)?;
        let init_code = user_op.get_init_code();
        if !(sender_code.0.is_empty() ^ init_code.is_empty()) {
            return Err(Error::InvalidUserOp);
        }
        if sender_code.0.is_empty() && init_code.len() < 20 {
            return Err(Error::InvalidUserOp);
        }

        // TODO ...

        Ok(())
    }

    pub async fn simulate_user_op(
        &self,
        rpc_client: &AsyncRpcClient,
        user_op: &UserOperation,
        entry_point: Address,
    ) -> EvmResult<ValidationResult> {
        let prefix = hex::decode("ee219423").unwrap(); // TODO: constant
        let mut stream = RlpStream::new();
        stream.begin_list(1);
        stream.append(user_op);
        let mut input = prefix;
        input.extend(stream.as_raw().iter());
        let rpc_tx = RPCTransaction {
            from: None, // TODO: bridge?
            to: Some(Hex(entry_point)),
            creates: None,
            gas: None, // max gas
            gas_price: None,
            value: None,
            input: Some(Bytes::from(input)),
            nonce: None,
            hash: None,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            v: None,
            r: None,
            s: None,
        };
        let result = rpc_client
            .send::<Bytes>(RpcRequest::EthCall, json!([rpc_tx, "latest"]))
            .await
            .err()
            .ok_or(Error::UserOpSimulateValidationError {
                message: "eth_call must fail with revert".to_string(),
            })?;
        if let ClientErrorKind::RpcError(RpcError::RpcResponseError { data, .. }) = result.kind {
            if let RpcResponseErrorData::Reverted { data } = dbg!(data) {
                let res = ValidationResult::decode(&Rlp::new(&data)).map_err(|_| {
                    Error::UserOpSimulateValidationError {
                        message: "failed to decode eth_call revert data".to_string(),
                    }
                })?;
                return Ok(res);
            }
        }
        Err(Error::UserOpSimulateValidationError {
            message: "eth_call must fail with revert".to_string(),
        })
    }

    pub async fn estimate_handle_ops(
        &self,
        rpc_client: &AsyncRpcClient,
        user_ops: &Vec<&UserOperation>,
        entry_point: Address,
    ) -> EvmResult<Gas> {
        let mut stream = RlpStream::new();
        stream.begin_list(user_ops.len());
        for user_op in user_ops {
            stream.append(*user_op);
        }
        let rpc_tx = RPCTransaction {
            from: None, // TODO: bridge?
            to: Some(Hex(entry_point)),
            creates: None,
            gas: None, // max gas
            gas_price: None,
            value: None,
            input: Some(Bytes::from(stream.as_raw().to_vec())), // TODO: add prefix
            nonce: None,
            hash: None,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            v: None,
            r: None,
            s: None,
        };
        let result = rpc_client
            .send::<Hex<_>>(RpcRequest::EthEstimateGas, json!([rpc_tx, "latest"]))
            .await
            .map_err(|_| Error::InvalidUserOp)?;
        Ok(result.0)
    }

    pub async fn send_user_ops(
        &self,
        meta: Arc<EvmBridge>,
        user_ops: &Vec<&UserOperation>,
        entry_point: Address,
        estimated_gas: Gas,
    ) -> EvmResult<Hex<H256>> {
        let address = Address::default();
        let secret_key = meta
            .get_accounts()
            .get(&address)
            .ok_or(Error::KeyNotFound { account: address })?;
        let nonce = match meta.get_pool().transaction_count(&address) {
            Some(n) => n,
            None => meta
                .get_rpc_client()
                .get_evm_transaction_count(&address)
                .await
                .map_err(|_| Error::ServerError {})?,
        };
        let mut stream = RlpStream::new();
        stream.begin_list(user_ops.len());
        for user_op in user_ops {
            stream.append(*user_op);
        }
        let tx = evm::UnsignedTransaction {
            nonce,
            gas_price: meta.get_min_gas_price(),
            gas_limit: estimated_gas,
            action: evm::TransactionAction::Call(entry_point),
            value: 0.into(),
            input: stream.as_raw().to_vec(), // TODO: add prefix
        };
        let tx = tx.sign(secret_key, Some(meta.get_evm_chain_id()));

        meta.send_tx(tx, Default::default()).await
    }
}
