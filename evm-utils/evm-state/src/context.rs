use {
    super::state::{AccountProvider, EvmBackend, Incomming},
    crate::types::*,
    evm::backend::{Apply, Backend, Basic},
    log::*,
    primitive_types::{H160, H256, U256},
    serde::{Deserialize, Serialize},
    std::{collections::HashMap, fmt, iter::FromIterator},
};

/// Transaction information.
/// This information will be propagated to solidity.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransactionContext {
    gas_price: u64,
    origin: H160,
    coinbase: H160, // Zero inited
}

impl TransactionContext {
    pub fn new(gas_price: u64, origin: H160) -> TransactionContext {
        Self {
            gas_price,
            origin,
            coinbase: H160::zero(),
        }
    }

    pub fn new_with_coinbase(gas_price: u64, origin: H160, coinbase: H160) -> TransactionContext {
        Self {
            gas_price,
            origin,
            coinbase,
        }
    }
}

/// Choose of EVM hardfork configuration.
/// Will define instruction cost, and behaviour acording to hardfork specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HardforkConfig {
    Istanbul,
    Frontier,
}

impl Default for HardforkConfig {
    fn default() -> Self {
        Self::Istanbul
    }
}

/// Config of evm chain.
/// This type is written to genesis config, and can be updated in future releases
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvmConfig {
    pub executor_config: HardforkConfig,
    pub gas_limit: u64,
    /// Current chain_id.
    pub chain_id: u64,
    /// If true transactions with chain id = None will be rejected.
    /// false can be set if we need support pre eip-155 applications.
    pub force_chain_id: bool,
    /// Executor should be called with estimate purposes (count transaction in worst scenario).
    pub estimate: bool,
    pub burn_gas_price: U256,
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self {
            executor_config: Default::default(),
            gas_limit: crate::DEFAULT_GAS_LIMIT,
            chain_id: crate::TEST_CHAIN_ID,
            force_chain_id: true,
            estimate: false,
            burn_gas_price: U256::zero(),
        }
    }
}

impl EvmConfig {
    pub fn new(chain_id: u64, basic_burn_gas_price: bool) -> EvmConfig {
        let mut this = Self {
            chain_id,
            ..Default::default()
        };
        if basic_burn_gas_price {
            this.burn_gas_price = crate::BURN_GAS_PRICE.into();
        }
        this
    }
    pub(crate) fn to_evm_params(self) -> evm::Config {
        evm::Config {
            estimate: self.estimate,
            has_chain_id: true,
            ..match self.executor_config {
                HardforkConfig::Istanbul => evm::Config::istanbul(),
                HardforkConfig::Frontier => evm::Config::frontier(),
            }
        }
    }
}

/// Represents some chain context, that should be emulated for EVM based application proper works.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChainContext {
    // From sysvars
    last_hashes: [H256; 256], // From sysvar EvmBlockHashes

    // Mocked with empty value
    difficulty: U256, // Zero
}
impl fmt::Debug for ChainContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainContext")
            .field("difficulty", &self.difficulty)
            .field(
                "last_hashes", // limit debug hashes to last 5
                &(
                    self.last_hashes[255],
                    self.last_hashes[254],
                    self.last_hashes[253],
                    self.last_hashes[252],
                    self.last_hashes[251],
                    self.last_hashes[250],
                    "...",
                ),
            )
            .finish()
    }
}

impl Default for ChainContext {
    fn default() -> Self {
        Self::new([H256::zero(); 256])
    }
}

impl ChainContext {
    pub fn new(last_hashes: [H256; 256]) -> Self {
        ChainContext {
            last_hashes,
            difficulty: U256::zero(),
        }
    }
}

#[derive(Debug)]
pub struct ExecutorContext<'a, State> {
    pub(crate) backend: &'a mut EvmBackend<State>,
    chain_context: ChainContext,
    tx_context: TransactionContext,
    config: EvmConfig,
}

impl<'a> ExecutorContext<'a, Incomming> {
    pub fn new(
        backend: &'a mut EvmBackend<Incomming>,
        chain_context: ChainContext,
        tx_context: TransactionContext,
        config: EvmConfig,
    ) -> Self {
        Self {
            backend,
            chain_context,
            tx_context,
            config,
        }
    }
    pub fn testing(backend: &'a mut EvmBackend<Incomming>) -> Self {
        Self {
            backend,
            chain_context: Default::default(),
            tx_context: Default::default(),
            config: Default::default(),
        }
    }

    pub fn gas_left(&self) -> u64 {
        self.config
            .gas_limit
            .saturating_sub(self.backend.state.used_gas)
    }

    // TODO: implement logs append for blocks.
    pub fn apply<A, I>(self, values: A, used_gas: u64)
    where
        A: IntoIterator<Item = Apply<I>>,
        I: IntoIterator<Item = (H256, H256)>,
    {
        for apply in values {
            match apply {
                Apply::Modify {
                    address,
                    basic,
                    code,
                    storage,
                    reset_storage: _,
                } => {
                    debug!(
                        "Apply::Modify address = {}, basic = {:?}, code = {:?}",
                        address, basic, code
                    );

                    let storage = HashMap::<H256, H256>::from_iter(storage);
                    debug!("Apply::Modify storage = {:?}", storage);

                    let mut account_state =
                        self.backend.get_account_state(address).unwrap_or_default();

                    account_state.nonce = basic.nonce;
                    account_state.balance = basic.balance;

                    if let Some(code) = code {
                        account_state.code = code.into();
                    }

                    self.backend.ext_storage(address, storage);

                    if !account_state.is_empty() {
                        self.backend.set_account_state(address, account_state);
                    } else {
                        self.backend.remove_account(address);
                    }
                }
                Apply::Delete { address } => {
                    self.backend.remove_account(address);
                }
            }
        }

        self.backend.state.used_gas += used_gas;
    }
}

impl<'a, State> Backend for ExecutorContext<'a, State>
where
    EvmBackend<State>: AccountProvider,
{
    fn gas_price(&self) -> U256 {
        self.tx_context.gas_price.into()
    }

    fn origin(&self) -> H160 {
        self.tx_context.origin
    }

    fn block_coinbase(&self) -> H160 {
        self.tx_context.coinbase
    }

    fn block_number(&self) -> U256 {
        self.backend.block_number().into()
    }

    fn block_timestamp(&self) -> U256 {
        self.backend.timestamp().into()
    }

    fn block_hash(&self, number: U256) -> H256 {
        let current_block = self.block_number();
        if number >= current_block
            || current_block - number - U256::one()
                >= U256::from(self.chain_context.last_hashes.len())
        {
            H256::default()
        } else {
            let index = if self.backend.block_version() >= BlockVersion::VersionConsistentHashes {
                // Fix bug with block_hash calculation
                self.chain_context.last_hashes.len() - (current_block - number).as_usize()
            } else {
                (current_block - number - U256::one()).as_usize()
            };
            self.chain_context.last_hashes[index]
        }
    }

    fn block_difficulty(&self) -> U256 {
        self.chain_context.difficulty
    }

    fn block_gas_limit(&self) -> U256 {
        self.config.gas_limit.into()
    }

    fn block_base_fee_per_gas(&self) -> U256 {
        U256::zero()
    }

    fn chain_id(&self) -> U256 {
        self.config.chain_id.into()
    }

    fn exists(&self, address: H160) -> bool {
        self.backend.get_account_state(address).is_some()
    }

    fn basic(&self, address: H160) -> Basic {
        let AccountState { balance, nonce, .. } =
            self.backend.get_account_state(address).unwrap_or_default();

        Basic { balance, nonce }
    }

    fn code(&self, address: H160) -> Vec<u8> {
        self.backend
            .get_account_state(address)
            .map(|account_state| account_state.code)
            .unwrap_or_else(Code::empty)
            .into()
    }

    fn storage(&self, address: H160, index: H256) -> H256 {
        self.backend.get_storage(address, index).unwrap_or_default()
    }

    fn original_storage(&self, address: H160, index: H256) -> Option<H256> {
        Some(self.storage(address, index))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn check_that_balance_zero_by_default() {
        let mut evm_backend = EvmBackend::default();
        let context = ExecutorContext::testing(&mut evm_backend);
        for _ in 0..1000 {
            let address = H160::random();
            assert_eq!(context.basic(address).balance, U256::zero());
        }
    }
}
