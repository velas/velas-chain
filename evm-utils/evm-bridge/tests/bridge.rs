use borsh::BorshSerialize;
use evm_state::Address;
use solana_sdk::account::{AccountSharedData, WritableAccount};
use {
    bincode::serialize,
    evm_bridge::bridge::EvmBridge,
    evm_bridge::pool::{EthPool, SystemClock},
    evm_rpc::{BlockId, Hex, RPCLogFilter, RPCTransaction},
    evm_state::TransactionInReceipt,
    log::*,
    primitive_types::{H256, U256},
    reqwest::{self, header::CONTENT_TYPE},
    serde_json::{json, Value},
    solana_account_decoder::UiAccount,
    solana_client::{
        client_error::{ClientErrorKind, Result as ClientResult},
        pubsub_client::PubsubClient,
        rpc_client::RpcClient,
        rpc_config::{RpcAccountInfoConfig, RpcSendTransactionConfig, RpcSignatureSubscribeConfig},
        rpc_request::RpcError,
        rpc_response::{Response as RpcResponse, RpcSignatureResult, SlotUpdate},
        tpu_client::{TpuClient, TpuClientConfig},
    },
    solana_rpc::rpc::JsonRpcConfig,
    solana_sdk::{
        commitment_config::{CommitmentConfig, CommitmentLevel},
        fee_calculator::FeeRateGovernor,
        hash::Hash,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signer},
        system_instruction::assign,
        system_transaction,
        transaction::Transaction,
    },
    solana_streamer::socket::SocketAddrSpace,
    solana_test_validator::{TestValidator, TestValidatorGenesis},
    solana_transaction_status::TransactionStatus,
    std::{
        collections::HashSet,
        net::UdpSocket,
        str::FromStr,
        sync::{mpsc::channel, Arc},
        thread::sleep,
        time::{Duration, Instant},
    },
    tokio::runtime::Runtime,
};
use evm_rpc::bundler::UserOperation;
use evm_rpc::Bytes;
use solana_evm_loader_program::{big_tx_allocate, big_tx_execute, big_tx_write, send_raw_tx, transfer_native_to_evm_ixs};
use solana_evm_loader_program::instructions::FeePayerType;
use solana_sdk::{bs58, system_instruction};


macro_rules! json_req {
    ($method: expr, $params: expr) => {{
        json!({
           "jsonrpc": "2.0",
           "id": 1,
           "method": $method,
           "params": $params,
        })
    }}
}

fn post_rpc(request: Value, rpc_url: &str) -> Value {
    let client = reqwest::blocking::Client::new();
    let response = client
        .post(rpc_url)
        .header(CONTENT_TYPE, "application/json")
        .body(request.to_string())
        .send()
        .unwrap();
    serde_json::from_str(&response.text().unwrap()).unwrap()
}

fn get_blockhash(rpc_url: &str) -> Hash {
    let req = json_req!(
        "getRecentBlockhash",
        json!([json!(CommitmentConfig {
            commitment: CommitmentLevel::Finalized
        })])
    );
    let json = post_rpc(req, &rpc_url);
    json["result"]["value"]["blockhash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn wait_finalization(rpc_url: &str, signatures: &[&Value]) -> bool {
    let request = json_req!("getSignatureStatuses", [signatures]);

    for _ in 0..solana_sdk::clock::DEFAULT_TICKS_PER_SLOT {
        let json = post_rpc(request.clone(), &rpc_url);
        let values = json["result"]["value"].as_array().unwrap();
        if values.iter().all(|v| !v.is_null()) {
            if values.iter().all(|v| {
                assert_eq!(v["err"], Value::Null);
                v["confirmationStatus"].as_str().unwrap() == "finalized"
            }) {
                warn!("All signatures confirmed: {:?}", dbg!(values));
                return true;
            }
        }

        sleep(Duration::from_secs(1));
    }
    false
}

/// This test checks that simulate_user_op() with valid input reverts with expected result
///
/// What is needed:
/// - account for contract
/// - contract code that reverts (check original contract and compile it if it's simple)
///
#[test]
fn test_test() {
    solana_logger::setup();

    let chain_id = 0xdead;

    let alice = Keypair::new();
    let big_tx_storage = Keypair::new();
    let test_validator = TestValidatorGenesis::default()
        .rpc_config(JsonRpcConfig {
            max_batch_duration: Some(Duration::from_secs(0)),
            ..JsonRpcConfig::default_for_test()
        })
        .start_with_mint_address(alice.pubkey(), SocketAddrSpace::Unspecified)
        .expect("validator start failed");
    let rpc_url = test_validator.rpc_url();

    let evm_secret_key = evm_state::SecretKey::from_slice(&[1; 32]).unwrap();
    let evm_address = evm_state::addr_from_public_key(&evm_state::PublicKey::from_secret_key(
        evm_state::SECP256K1,
        &evm_secret_key,
    ));

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let ixs = transfer_native_to_evm_ixs(alice.pubkey(), 1000000, evm_address);
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();

    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json: Value = post_rpc(req, &rpc_url);
    wait_finalization(&rpc_url, &[&json["result"]]);

    // Contract with empty method that will revert after 60 seconds since creation
    // const ENTRY_POINT_CONTRACT: &str = "608060405234801561001057600080fd5b50610398806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063ee21942314610030575b600080fd5b61004a60048036038101906100459190610130565b61004c565b005b60006040518060c001604052806000815260200160008152602001600115158152602001600065ffffffffffff168152602001600065ffffffffffff168152602001604051806020016040528060008152508152509050600060405180604001604052806000815260200160008152509050818182836040517fe0cff05f0000000000000000000000000000000000000000000000000000000081526004016100f89493929190610316565b60405180910390fd5b600080fd5b600080fd5b600080fd5b600061016082840312156101275761012661010b565b5b81905092915050565b60006020828403121561014657610145610101565b5b600082013567ffffffffffffffff81111561016457610163610106565b5b61017084828501610110565b91505092915050565b6000819050919050565b61018c81610179565b82525050565b60008115159050919050565b6101a781610192565b82525050565b600065ffffffffffff82169050919050565b6101c8816101ad565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b838110156102085780820151818401526020810190506101ed565b60008484015250505050565b6000601f19601f8301169050919050565b6000610230826101ce565b61023a81856101d9565b935061024a8185602086016101ea565b61025381610214565b840191505092915050565b600060c0830160008301516102766000860182610183565b5060208301516102896020860182610183565b50604083015161029c604086018261019e565b5060608301516102af60608601826101bf565b5060808301516102c260808601826101bf565b5060a083015184820360a08601526102da8282610225565b9150508091505092915050565b6040820160008201516102fd6000850182610183565b5060208201516103106020850182610183565b50505050565b600060e0820190508181036000830152610330818761025e565b905061033f60208301866102e7565b61034c60608301856102e7565b61035960a08301846102e7565b9594505050505056fea2646970667358221220bcbcc320bd54353dc872a2eb074a676694bea8e30070f979c506e92aeabda96664736f6c63430008120033";
    const ENTRY_POINT_CONTRACT: &str = "608060405234801561001057600080fd5b50610398806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063ee21942314610030575b600080fd5b61004a60048036038101906100459190610130565b61004c565b005b60006040518060c001604052806000815260200160008152602001600115158152602001600065ffffffffffff168152602001600065ffffffffffff168152602001604051806020016040528060008152508152509050600060405180604001604052806000815260200160008152509050818182836040517fe0cff05f0000000000000000000000000000000000000000000000000000000081526004016100f89493929190610316565b60405180910390fd5b600080fd5b600080fd5b600080fd5b600061016082840312156101275761012661010b565b5b81905092915050565b60006020828403121561014657610145610101565b5b600082013567ffffffffffffffff81111561016457610163610106565b5b61017084828501610110565b91505092915050565b6000819050919050565b61018c81610179565b82525050565b60008115159050919050565b6101a781610192565b82525050565b600065ffffffffffff82169050919050565b6101c8816101ad565b82525050565b600081519050919050565b600082825260208201905092915050565b60005b838110156102085780820151818401526020810190506101ed565b60008484015250505050565b6000601f19601f8301169050919050565b6000610230826101ce565b61023a81856101d9565b935061024a8185602086016101ea565b61025381610214565b840191505092915050565b600060c0830160008301516102766000860182610183565b5060208301516102896020860182610183565b50604083015161029c604086018261019e565b5060608301516102af60608601826101bf565b5060808301516102c260808601826101bf565b5060a083015184820360a08601526102da8282610225565b9150508091505092915050565b6040820160008201516102fd6000850182610183565b5060208201516103106020850182610183565b50505050565b600060e0820190508181036000830152610330818761025e565b905061033f60208301866102e7565b61034c60608301856102e7565b61035960a08301846102e7565b9594505050505056fea2646970667358221220fa395ce51d15753c1f45ffbd1a50323290fc72b917009d5c88329abb2ba6a67464736f6c63430008120033";
    let tx_create = evm_state::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 2000000000.into(),
        gas_limit: 300000.into(),
        action: evm_state::TransactionAction::Create,
        value: 0.into(),
        input: hex::decode(ENTRY_POINT_CONTRACT).unwrap(),
    }
        .sign(&evm_secret_key, Some(chain_id));
    let entry_point_address = tx_create.address().unwrap();

    let mut tx_bytes = vec![];
    BorshSerialize::serialize(&tx_create, &mut tx_bytes).unwrap();

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let create_storage_ix = system_instruction::create_account(
        &alice.pubkey(),
        &big_tx_storage.pubkey(),
        10000000,
        tx_bytes.len() as u64,
        &solana_evm_loader_program::ID,
    );
    let ixs = vec![create_storage_ix];
    let tx = Transaction::new_signed_with_payer(&ixs, None, &[&alice, &big_tx_storage], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let allocate = big_tx_allocate(big_tx_storage.pubkey(), dbg!(tx_bytes.len()));
    let write1 = big_tx_write(big_tx_storage.pubkey(), 0, tx_bytes[..700].to_vec());
    let ixs = vec![allocate, write1];
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&alice.pubkey()), &[&big_tx_storage, &alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let blockhash = dbg!(get_blockhash(&rpc_url));
    let write2 = big_tx_write(big_tx_storage.pubkey(), 700, tx_bytes[700..].to_vec());
    let execute = big_tx_execute(big_tx_storage.pubkey(), None, FeePayerType::Evm);
    let ixs = vec![write2, execute];
    let tx = Transaction::new_signed_with_payer(&ixs, Some(&alice.pubkey()), &[&big_tx_storage, &alice], blockhash);
    let serialized_encoded_tx = bs58::encode(serialize(&tx).unwrap()).into_string();
    let req = json_req!("sendTransaction", json!([serialized_encoded_tx]));
    let json = dbg!(post_rpc(req, &rpc_url));
    wait_finalization(&rpc_url, &[&json["result"]]);

    let mut bridge = EvmBridge::new_for_test(chain_id, vec![], rpc_url);
    let user_op = UserOperation {
        sender: Default::default(),
        nonce: Default::default(),
        init_code: Bytes::from(Vec::new()),
        call_data: Bytes::from(Vec::new()),
        call_gas_limit: Default::default(),
        verification_gas_limit: Default::default(),
        pre_verification_gas: Default::default(),
        max_fee_per_gas: Default::default(),
        max_priority_fee_per_gas: Default::default(),
        paymaster_and_data: Bytes::from(Vec::new()),
        signature: Bytes::from(Vec::new()),
    };
    let res = tokio_test::block_on(
        bridge.get_bundler().simulate_user_op(bridge.get_rpc_client(), &user_op, entry_point_address)
    ).unwrap();
    error!("{:?}", res);

    // assert!(false);
}
