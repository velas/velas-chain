use std::fs::File;
use std::path::Path;
use std::io::Write;

use evm_state::*;
use evm_state::rand::Rng;
use derive_more::Display;

mod utils;

#[derive(Clone, Display)]
#[display(
    fmt = "slots {}, squash each {}, {} accounts per 100k slots, gc={}",
    n_slots,
    squash_each,
    accounts_per_100k,
    with_gc
)]
struct Params {
    n_slots: BlockNum,
    squash_each: BlockNum,
    accounts_per_100k: usize,
    with_gc: bool,
}

fn main() {
    let dir = Path::new("../db/");
    let state_root = generate_db(&dir);

    let mut file = File::create("state_root.txt").unwrap();
    file.write_all(state_root.as_bytes()).unwrap();

   // Example of state

   // [state-rpc/src/main.rs:39] state = EvmBackend {
   //   state: Incomming {
   //       block_number: 100000,
   //       timestamp: 0,
   //       used_gas: 0,
   //       state_root: 0x8295f3fdef7c8652f124abed07a06533526f49e57181a4709b87310a4bac75ae,
   //       last_block_hash: 0x61e3b6fbf500ce94b1086fc37d817475e5770986e3c3e0d1ed03bb93837a9276,
   //       state_updates: {},
   //       executed_transactions: [],
   //       block_version: InitVersion,
   //   },
   //   kvs: Storage {
   //       db: DbWithClose(
   //           RocksDB { path: "db/" },
   //       ),
   //       location: Persisent(
   //           "db/",
   //       ),
   //       gc_enabled: true,
   //   },
   // }
}

fn generate_db(dir: &Path) -> H256 {
    let params = Params {
        n_slots: 1_000_00,
        squash_each: 1_000,
        accounts_per_100k: 1_000,
        with_gc: false,
    };
    let evm_state = EvmState::new(&dir)
        .expect("Unable to create new EVM state in a directory");
    let mut state = match evm_state {
        EvmState::Incomming(i) => i,
        _ => unreachable!(),
    };
    add_some_and_advance(&mut state, &params);

    let db = state.kvs;
    let state_root = state.state.state_root;
    let last_block_hash = state.state.last_block_hash;

    let handle = db.typed_for::<H256, Vec<u8>>(state_root);
    let val = db.db().get(&state_root);
    state_root
}


fn add_some_and_advance(state: &mut EvmBackend<Incomming>, params: &Params) {
    // repeat 1/3 of accounts from previous slots
    let mut addresses = utils::AddrMixer::new(3);
    let mut rng = rand::thread_rng();

    for slot in 0..params.n_slots {
        addresses.advance();

        if rng.gen_ratio(params.accounts_per_100k as u32, 100_000) {
            let (address, account) = (addresses.some_addr(), utils::some_account());
            state.set_account_state(address, account);
        }

        let committed = state.clone().commit_block(slot, Default::default());
        *state = committed.next_incomming(0);

        state
            .kvs()
            .register_slot(slot, state.last_root(), false)
            .unwrap();
    }
}
