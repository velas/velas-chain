use {
    evm_state::types::{AccountState, H160 as Address, U256},
    rand::{prelude::IteratorRandom, random, Rng},
    std::{collections::HashSet, iter},
};

const AVERAGE_DATA_SIZE: usize = 2 * 1024;

pub fn some_account() -> AccountState {
    AccountState {
        nonce: U256::from(random::<u64>()),
        balance: U256::from(random::<u64>()),
        code: iter::repeat_with(random)
            .take(rand::thread_rng().gen_range(0..=2 * AVERAGE_DATA_SIZE))
            .collect::<Vec<u8>>()
            .into(),
    }
}

#[allow(dead_code)] // in use actually
pub fn unique_random_accounts() -> impl Iterator<Item = (Address, AccountState)> {
    let mut addresses = HashSet::new();

    iter::repeat_with(Address::random)
        .filter(move |addr| addresses.insert(*addr))
        .zip(iter::repeat_with(some_account))
}

/// Random accounts generator with chance to repeat existing address as 1 / repeat_prob
pub struct AddrMixer {
    repeat_prob: u32,
    current: HashSet<Address>,
    previous: HashSet<Address>,
}

impl AddrMixer {
    pub fn new(repeat_prob: u32) -> Self {
        Self {
            repeat_prob,
            current: HashSet::new(),
            previous: HashSet::new(),
        }
    }

    pub fn some_addr(&mut self) -> Address {
        let mut rng = rand::thread_rng();
        if rng.gen_ratio(1, self.repeat_prob) {
            match self.previous.iter().choose(&mut rng) {
                Some(addr) => *addr,
                None => self.new_addr(),
            }
        } else {
            self.new_addr()
        }
    }

    pub fn new_addr(&mut self) -> Address {
        loop {
            let addr = random();
            if !self.previous.contains(&addr) && self.current.insert(addr) {
                return addr;
            }
        }
    }

    pub fn advance(&mut self) {
        self.previous.extend(self.current.drain());
    }
}
