use super::basic::BasicERPC;
use super::bridge::BridgeERPC;
use super::chain_mock::ChainMockERPC;
use super::error::Error;
use super::serialize::*;
use super::*;
use crate::rpc::JsonRpcRequestProcessor;
use evm_state::*;
use sha3::{Digest, Keccak256};

use solana_client::rpc_client::RpcClient;
use solana_evm_loader_program::instructions::EvmInstruction;
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    signature::{Signer},
};
use std::collections::HashMap;

pub struct ChainMockERPCImpl;

impl ChainMockERPC for ChainMockERPCImpl {
    type Metadata = JsonRpcRequestProcessor;

    fn network_id(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0x77"))
    }

    fn chain_id(&self, _meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        Ok(Hex(0x77))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        Ok(Hex(0))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> Result<Hex<H256>, Error> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    fn client_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("SolanaEvm/v0.1.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn coinbase(&self, _meta: Self::Metadata) -> Result<Hex<Address>, Error> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> Result<bool, Error> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> Result<String, Error> {
        Ok(String::from("0x00"))
    }

    fn block_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(None)
    }

    fn block_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _full: bool,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(Some(RPCBlock {
            number: U256::zero().into(),
            hash: H256::zero().into(),
            parent_hash: H256::zero().into(),
            nonce: 0.into(),
            sha3_uncles: H256::zero().into(),
            logs_bloom: H256::zero().into(), // H2048
            transactions_root: H256::zero().into(),
            state_root: H256::zero().into(),
            receipts_root: H256::zero().into(),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: vec![].into(),
            size: 0.into(),
            gas_limit: Gas::zero().into(),
            gas_used: Gas::zero().into(),
            timestamp: 0.into(),
            transactions: Either::Left(vec![]),
            uncles: vec![],
        }))
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(None)
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> Result<Option<RPCBlock>, Error> {
        Ok(None)
    }

    fn block_transaction_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> Result<Option<Hex<usize>>, Error> {
        Ok(None)
    }

    fn block_transaction_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> Result<Option<Hex<usize>>, Error> {
        Ok(None)
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> Result<Option<Hex<usize>>, Error> {
        Ok(None)
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> Result<Option<Hex<usize>>, Error> {
        Ok(None)
    }
}

pub struct BasicERPCImpl;
impl BasicERPC for BasicERPCImpl {
    type Metadata = JsonRpcRequestProcessor;

    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> Result<Hex<usize>, Error> {
        let bank = meta.bank(None);
        Ok(Hex(bank.slot() as usize))
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        _block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let bank = meta.bank(None);
        let evm_state = bank.evm_state.read().unwrap();
        Ok(Hex(evm_state.basic(address.0).balance))
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        _block: Option<String>,
    ) -> Result<Hex<H256>, Error> {
        let bank = meta.bank(None);
        let evm_state = bank.evm_state.read().unwrap();
        Ok(Hex(evm_state.storage(address.0, data.0)))
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        _block: Option<String>,
    ) -> Result<Hex<U256>, Error> {
        let bank = meta.bank(None);
        let evm_state = bank.evm_state.read().unwrap();
        Ok(Hex(evm_state.basic(address.0).nonce))
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        _block: Option<String>,
    ) -> Result<Bytes, Error> {
        let bank = meta.bank(None);
        let evm_state = bank.evm_state.read().unwrap();
        Ok(Bytes(evm_state.code(address.0)))
    }

    fn transaction_by_hash(
        &self,
        _meta: Self::Metadata,
        _tx_hash: Hex<H256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        unimplemented!()
    }

    fn transaction_receipt(
        &self,
        _meta: Self::Metadata,
        _tx_hash: Hex<H256>,
    ) -> Result<Option<RPCReceipt>, Error> {
        Ok(None)
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        unimplemented!()
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> Result<Option<RPCTransaction>, Error> {
        unimplemented!()
    }
}

pub struct BridgeERPCImpl {
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    rpc_client: RpcClient,
}
impl Default for BridgeERPCImpl {
    fn default() -> Self {
        let keypath = "./keyfile.json";
        info!("Loading keypair from: {}", keypath);
        let secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = evm_state::PublicKey::from_secret_key(&evm_state::SECP256K1, &secret_key);
        let rpc_client = RpcClient::new("http://127.0.0.1:8899".to_string());
        let public_key_hash =
            H256::from_slice(Keccak256::digest(&public_key.serialize()[1..]).as_slice());
        Self {
            key: solana_sdk::signature::read_keypair_file(&keypath).unwrap(),
            accounts: vec![(Address::from(public_key_hash), secret_key)]
                .into_iter()
                .collect(),
            rpc_client,
        }
    }
}

impl BridgeERPC for BridgeERPCImpl {
    type Metadata = JsonRpcRequestProcessor;

    fn accounts(&self, _meta: Self::Metadata) -> Result<Vec<Hex<Address>>, Error> {
        Ok(self.accounts.iter().map(|(k, _)| Hex(*k)).collect())
    }

    fn sign(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _data: Bytes,
    ) -> Result<Bytes, Error> {
        unimplemented!()
    }

    fn send_transaction(
        &self,
        _meta: Self::Metadata,
        tx: RPCTransaction,
    ) -> Result<Hex<H256>, Error> {
        info!("send_transaction");
        let secret_key = self
            .accounts
            .get(&tx.from.map(|a| a.0).unwrap_or_default())
            .unwrap();
        let tx_create = evm::UnsignedTransaction {
            nonce: tx.nonce.map(|a| a.0).unwrap_or(0.into()),
            gas_price: tx.gas_price.map(|a| a.0).unwrap_or(0.into()),
            gas_limit: tx.gas.map(|a| a.0).unwrap_or(300000.into()),
            action: tx
                .to
                .map(|a| evm::TransactionAction::Call(a.0))
                .unwrap_or(evm::TransactionAction::Create),
            value: tx.value.map(|a| a.0).unwrap_or(0.into()),
            input: tx.data.map(|a| a.0).unwrap_or_default(),
        };
        let hash = tx_create.signing_hash(None);

        let tx = tx_create.sign(&secret_key, None);

        let account_metas = vec![AccountMeta::new(self.key.pubkey(), true)];

        let ix = Instruction::new(
            solana_evm_loader_program::ID,
            &EvmInstruction::EvmTransaction { evm_tx: tx },
            account_metas,
        );

        let message = Message::new(&[ix], Some(&self.key.pubkey()));
        let mut send_raw_tx: solana_sdk::transaction::Transaction =
            solana_sdk::transaction::Transaction::new_unsigned(message);

        info!("Getting block hash");
        let (blockhash, _fee_calculator, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::default())
            .unwrap()
            .value;

        send_raw_tx.sign(&vec![&self.key], blockhash);
        println!("Sending tx = {:?}", send_raw_tx);
        let result = self.rpc_client.send_transaction_with_config(
            &send_raw_tx,
            // CommitmentConfig::default(),
            Default::default(),
        );

        println!("Result tx = {:?}", result);
        Ok(Hex(hash))
    }

    fn send_raw_transaction(&self, _meta: Self::Metadata, tx: Bytes) -> Result<Hex<H256>, Error> {
        info!("send_raw_transaction");
        let tx: evm::Transaction = rlp::decode(&tx.0).unwrap();
        let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
        let hash = unsigned_tx.signing_hash(None);
        info!("loaded tx = {:?}, hash = {}", tx, hash);

        let account_metas = vec![AccountMeta::new(self.key.pubkey(), true)];

        let ix = Instruction::new(
            solana_evm_loader_program::ID,
            &EvmInstruction::EvmTransaction { evm_tx: tx },
            account_metas,
        );

        let message = Message::new(&[ix], Some(&self.key.pubkey()));
        let mut send_raw_tx: solana_sdk::transaction::Transaction =
            solana_sdk::transaction::Transaction::new_unsigned(message);

        info!("Getting block hash");
        let (blockhash, _fee_calculator, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::default())
            .unwrap()
            .value;

        send_raw_tx.sign(&vec![&self.key], blockhash);
        println!("Sending tx = {:?}", send_raw_tx);
        let result = self.rpc_client.send_transaction_with_config(
            &send_raw_tx,
            // CommitmentConfig::default(),
            Default::default(),
        );

        println!("Result tx = {:?}", result);
        Ok(Hex(hash))
    }

    fn call(
        &self,
        _meta: Self::Metadata,
        _tx: RPCTransaction,
        _block: Option<String>,
    ) -> Result<Bytes, Error> {
        unimplemented!()
    }

    fn gas_price(&self, _meta: Self::Metadata) -> Result<Hex<Gas>, Error> {
        //TODO: Add gas logic
        Ok(Hex(1.into()))
    }

    fn estimate_gas(
        &self,
        _meta: Self::Metadata,
        _tx: RPCTransaction,
        _block: Option<String>,
    ) -> Result<Hex<Gas>, Error> {
        Ok(Hex(300_000_000.into()))
    }

    fn compilers(&self, _meta: Self::Metadata) -> Result<Vec<String>, Error> {
        unimplemented!()
    }

    fn logs(&self, _meta: Self::Metadata, _log_filter: RPCLogFilter) -> Result<Vec<RPCLog>, Error> {
        unimplemented!()
    }
}
