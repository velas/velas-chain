use evm_rpc::Hex;
use evm_state::FromKey;
use log::*;
use solana_client::rpc_client::RpcClient;
use solana_evm_loader_program::scope::*;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    message::Message,
    native_token::lamports_to_sol,
    signature::{read_keypair_file, Signer},
};
use std::fs::File;
use std::io::{Read, Write};

// With the "paw" feature enabled in structopt
#[derive(Debug, structopt::StructOpt)]
enum SubCommands {
    /// Broadcast raw ethereum transaction.
    SendRawTx {
        /// A path to a file where raw transaction is stored in bincode encoding.
        raw_tx: String,
    },
    /// Transfer native chain token to EVM world.
    TransferToEvm {
        /// Amount in plancks
        amount: u64,
        /// Address in EVM, that will receive tokens
        ether_address: Hex<evm::Address>,
    },
    ///
    /// At some point in our history, in database was found incorrect blocks (native chain slots was changed).
    /// In order to recover that blocks from database, we found a solution.
    ///
    FindBlockHeader {
        #[structopt(long = "expected-blockhash")]
        expected_block_hash: Hex<evm::H256>,
        #[structopt(long = "blocks-range")]
        range: u64,
        #[structopt(long = "file", default_value = "-")]
        file: String,
    },

    /// Print EVM address.
    PrintEvmAddress {
        /// HEX representated private key.
        secret_key: evm::SecretKey,
    },
    /// Print EVM address.
    GetEvmBalance {
        /// HEX representated private key.
        secret_key: Option<evm::SecretKey>,
        #[structopt(short = "a", long = "address")]
        address: Option<Hex<evm::Address>>,
    },

    /// DEBUG: Create dummy "CREATE" transaction.
    CreateDummy {
        tx_file: String,
        #[structopt(short = "c", long = "code")]
        contract_code: Option<String>,
    },
    /// DEBUG: Create dummy "CALL" transaction.
    CallDummy {
        create_tx: String,
        tx_file: String,
        #[structopt(short = "a", long = "abi")]
        abi: Option<String>,
    },

    /// DEBUG: Parse binary array as hex/utf8.
    ParseArray { array: String },
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    #[structopt(short = "r", long = "rpc")]
    rpc_address: Option<String>,
    #[structopt(subcommand)]
    subcommand: SubCommands,
}

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];
use env_logger::Env;

#[paw::main]
fn main(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::new().default_filter_or("info");
    env_logger::init_from_env(env);

    let keypath = solana_cli_config::Config::default().keypair_path;
    info!("Loading keypair from: {}", keypath);
    let signer = Box::new(read_keypair_file(&keypath).unwrap()) as Box<dyn Signer>;

    let address = args
        .rpc_address
        .unwrap_or_else(|| "https://api.next.velas.com:8899".to_string());
    let rpc_client = RpcClient::new(address);

    match args.subcommand {
        SubCommands::SendRawTx { raw_tx } => {
            let mut file = File::open(raw_tx).unwrap();
            let mut buf = Vec::new();
            Read::read_to_end(&mut file, &mut buf).unwrap();
            let tx: evm::Transaction =
                solana_sdk::program_utils::limited_deserialize(&buf).unwrap();

            debug!("loaded tx = {:?}", tx);
            let ix = solana_evm_loader_program::send_raw_tx(signer.pubkey(), tx, None);

            let message = Message::new(&[ix], Some(&signer.pubkey()));
            let mut create_account_tx = solana::Transaction::new_unsigned(message);

            debug!("Getting block hash");
            let (blockhash, _fee_calculator, _) = rpc_client
                .get_recent_blockhash_with_commitment(CommitmentConfig::default())
                .unwrap()
                .value;

            create_account_tx.sign(&vec![&*signer], blockhash);
            debug!("Sending tx = {:?}", create_account_tx);
            let result = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &create_account_tx,
                CommitmentConfig::default(),
                Default::default(),
            );
            debug!("Result = {:?}", result);
        }
        SubCommands::TransferToEvm {
            amount,
            ether_address,
        } => {
            let ixs = solana_evm_loader_program::transfer_native_to_eth_ixs(
                signer.pubkey(),
                amount,
                ether_address.0,
            );
            let message = Message::new(&ixs, Some(&signer.pubkey()));
            let mut create_account_tx = solana::Transaction::new_unsigned(message);

            debug!("Getting block hash");
            let (blockhash, _fee_calculator, _) = rpc_client
                .get_recent_blockhash_with_commitment(CommitmentConfig::default())
                .unwrap()
                .value;

            create_account_tx.sign(&vec![&*signer], blockhash);
            debug!("Sending tx = {:?}", create_account_tx);
            let result = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &create_account_tx,
                CommitmentConfig::default(),
                Default::default(),
            );
            debug!("Result = {:?}", result);
            let res = result.expect("Failed to send transaction using rpc");
            println!("Transaction signature = {}", res);
        }
        SubCommands::FindBlockHeader {
            expected_block_hash,
            range,
            file,
        } => {
            use std::str::FromStr;
            let (input, file): (_, Box<dyn std::io::Read>) = if file == "-" {
                (
                    "standart input(stdin)".to_string(),
                    Box::new(std::io::stdin()),
                )
            } else {
                (
                    format!("file({})", file),
                    Box::new(std::fs::File::open(file).unwrap()),
                )
            };
            println!("Reading blockheader from: {}", input);
            let block: evm_rpc::RPCBlock = serde_json::from_reader(file).unwrap();
            let mut block: evm_state::BlockHeader = block.to_native_block(Default::default());
            let native_slot = block.native_chain_slot;
            debug!("Readed block = {:?}", block);
            for slot in native_slot - range..native_slot + range {
                let native_block = if let Ok(native_block) = rpc_client.get_confirmed_block(slot) {
                    native_block
                } else {
                    debug!("Skiped slot = {:?}, Cannot request blockhash", slot);
                    continue;
                };
                let hash: solana_sdk::hash::Hash =
                    solana_sdk::hash::Hash::from_str(&native_block.blockhash).unwrap();
                let hash = evm::H256::from_slice(&hash.0);
                block.native_chain_hash = hash;
                block.native_chain_slot = slot;
                debug!("Produced block = {:?}, hash = {:?}", block, block.hash());
                if block.hash() == expected_block_hash.0 {
                    println!("Block slot found, slot = {}", slot);
                    return Ok(());
                }
            }
            println!("Block slot not found.");
        }
        SubCommands::PrintEvmAddress { secret_key } => {
            println!("EVM Address: {:?}", secret_key.to_address());
        }
        SubCommands::GetEvmBalance {
            secret_key,
            address,
        } => {
            let address = address.map(|a| a.0).unwrap_or_else(|| {
                secret_key
                    .expect("Expected secret_key, or address in arguments")
                    .to_address()
            });
            let balance = rpc_client
                .get_evm_balance(&address)
                .expect("Cannot parse request");
            let lamports = evm::gweis_to_lamports(balance).0; // ignore dust
            let vlx = lamports_to_sol(lamports);
            println!(
                "EVM Address: {:?}, balance: {} ({} in hex)",
                address,
                vlx,
                Hex(balance)
            );
        }
        SubCommands::CreateDummy {
            tx_file,
            contract_code,
        } => {
            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            let tx_create = evm::UnsignedTransaction {
                nonce: 0.into(),
                gas_price: 0.into(),
                gas_limit: 300000.into(),
                action: evm::TransactionAction::Create,
                value: 0.into(),
                input: hex::decode(
                    contract_code
                        .as_deref()
                        .unwrap_or(evm_state::HELLO_WORLD_CODE),
                )
                .unwrap()
                .to_vec(),
            };
            let tx_create = tx_create.sign(&secret_key, None);

            let mut file = File::create(tx_file).unwrap();
            Write::write_all(&mut file, &bincode::serialize(&tx_create).unwrap()).unwrap();
        }
        SubCommands::CallDummy {
            tx_file,
            create_tx,
            abi,
        } => {
            let mut file = File::open(create_tx).unwrap();
            let mut buf = Vec::new();
            Read::read_to_end(&mut file, &mut buf).unwrap();
            let evm_tx: evm::Transaction =
                solana_sdk::program_utils::limited_deserialize(&buf).unwrap();
            let tx_address = evm_tx.address().unwrap();

            let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap();
            let tx_call = evm::UnsignedTransaction {
                nonce: 0.into(),
                gas_price: 0.into(),
                gas_limit: 300000.into(),
                action: evm::TransactionAction::Call(tx_address),
                value: 0.into(),
                input: hex::decode(abi.as_deref().unwrap_or(evm_state::HELLO_WORLD_ABI))
                    .unwrap()
                    .to_vec(),
            };

            let tx_call = tx_call.sign(&secret_key, None);

            let mut file = File::create(tx_file).unwrap();
            Write::write_all(&mut file, &bincode::serialize(&tx_call).unwrap()).unwrap();
        }
        SubCommands::ParseArray { array } => {
            let bytes: Vec<u8> = serde_json::from_str(&array).unwrap();
            println!("Resulting data HEX = {}", hex::encode(&bytes));
            println!("Resulting data utf8 = {}", String::from_utf8_lossy(&bytes));
        }
    }
    Ok(())
}
