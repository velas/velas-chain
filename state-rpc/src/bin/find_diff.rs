use std::path::Path;
use evm_state::H256;
use evm_rpc::FormatHex;

use state_rpc::state_diff;

fn main() {
    let dir = Path::new("./.tmp/db/");
    let state_root_str = std::fs::read_to_string("./.tmp/state_root.txt").expect("get the state root");
    let state_root = H256::from_hex(&state_root_str).expect("get hash from &str");


}
