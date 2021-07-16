# Changenotes
[Migrating Rust programs from v1.5 to v1.6][migrating-guide]  

### RPC improvements:
<!-- 1.5.17 -->
- new `getSlotLeaders` endpoint
- `getBlockTime` now returns the block time for any processed block (previously only finalized)
- several endpoints now return confirmed data when specified with the commitment parameter (default finalized): `getConfirmedBlock`, `getConfirmedBlocks`, `getConfirmedBlocksWithLimit`, and `getConfirmedTransaction`
<!-- 1.6.2 -->
- `getConfirmedBlock` response data can now be limited via request args: transaction data may be full, just signatures, or skipped altogether; rewards info may be skipped
- new `getSlotLeaders` endpoint
- `getBlockTime` now returns the block time for any processed block (previously only finalized)
- several endpoints now return confirmed data when specified with the commitment parameter (default finalized): `getConfirmedBlock`, `getConfirmedBlocks`, `getConfirmedBlocksWithLimit`, and `getConfirmedTransaction`
<!-- 1.5.18 -->
- fixes potential for `getConfirmedTransaction` to return the wrong slot
- `getConfirmedSignaturesForAddress2` now returns confirmed data when specified with the commitment parameter (default finalized)
<!-- 1.6.3 -->
- fixes potential for `getConfirmedTransaction` to return the wrong slot
- `getConfirmedSignaturesForAddress2` now returns confirmed data when specified with the commitment parameter (default finalized)
<!-- 1.6.5 -->
<!-- - new `getInflationReward` endpoint -->
<!-- 1.5.19 -->
- new `getInflationReward` endpoint
- unprocessed transactions are now filtered out of logs
- correct transaction parsing for uninitialized system/nonce accounts
- PubSub now correctly uses finalized as the default commitment level
<!-- 1.6.7 -->
- Add `getBlockProduction` RPC method
- `getLeaderSchedule` now supports filtered results based on validator identity
- The default commitment of pubsub subscriptions are now correctly set to `confirmed` instead of `finalized`
- Add Rust TPU client for sending transactions to the current leader TPU port
<!-- 1.6.8 -->
- RpcClient now respects the retry-after server response header when getting rate limited
- `getBlockProduction` RPC method now correctly reports block production in all cases
<!-- 1.6.10 -->
- Add toggle to `getProgramAccounts` to enable return of slot context
<!-- 1.6.11 -->
- Adds last-valid block height to Fees
- Adds block height to block metadata
- Adds rent debit charges to block and transaction metadata
- `simulateTransaction` can now return accounts modified by the transaction
- Adds flag to `simulateTransaction` to use most-recent blockhash
<!-- 1.6.13 -->
- Fix bincode deserialization of BigTable `StoredConfirmedBlocks`

### CLI tools:
<!-- 1.6.5 -->
<!-- - `velas stake-account` and `velas vote-account` are now wicked fast; use the `--with-rewards` and `--num-rewards-epochs` parameters to control amount of reward data -->
<!-- - New `velas inflation rewards` command allows inspecting rewards for multiple accounts during a particular epoch -->
- All transaction-generating commands now support `--with-memo` to add an spl-memo instruction
<!-- 1.5.19 -->
- `velas stake-account` and `velas vote-account` are now wicked fast; use the `--with-rewards` and `--num-rewards-epochs` parameters to control amount of reward data
- New `velas inflation rewards` command allows inspecting rewards for multiple accounts during a particular epoch
- Limit `velas stake-history` output by default
<!-- - `velas airdrop` now uses JSON RPC instead to receive the airdrop transaction -->

<!-- 1.6.7 -->
#### velas command-line improvements:
  - Fix APR calculation and clarify language around APR in `velas inflation` output
  - Add sorting options to `velas validators`
  - Display last vote, skip rate, and root behind distance in `velas validators` output
  - `withdraw-stake` now supports `ALL`
  - Add `--seed` argument support to `delegate-stake` and `withdraw-stake` commands
  - The deprecated `pay` command is now an alias to `transfer`
  - Implement Bip32 for seed-phrase/passphrase signing
#### velas-test-validator improvements:
  - Add `--limit-ledger-size` argument
  - Upgradable BPF loader is now included by default
#### velas-validator improvements:
  - send votes to next leader's TPU instead of our TPU
  - gossip optimizations
  - Allow `SetUpgradeAuthority` instruction in CPI calls
  - Vote processing improvements
  
<!-- 1.6.8 -->
#### velas-validator improvements:
  - Interrupted snapshot archive downloads are now ignored
  - Add `--tower` argument to specify where tower files are persisted
  - `velas-validator `exit terminates the process more forcefully if necessary
  - Gossip optimizations
#### velascommand-line improvements:
  - `velas gossip` now supports JSON output
#### velas-ledger-tool improvements:
  - Add new `repair-roots` command
  - capitalization command now outputs rent collector and inflation configuration
  
<!-- 1.6.9 -->
#### velas-validator improvements:
  - (RPC nodes) Removes bloat for account secondary indexes, and allow index keys to be explicitly excluded/included
  - Gossip optimizations
  - Moves block-time caching earlier to improve availability of this data
  - Expands dashboard information for `velas-test-validator`
#### velas command-line improvements:
  - `velas-keygen` recover now supports bip32 HD
  
<!-- 1.6.10 -->
#### velas-validator improvements:
  - Gossip optimizations and bug fixes
  - Validator progress bars are now rendered when stdout is not a terminal
  - Add flag for RPC nodes to scan and verify ledger roots on boot
  
<!-- 1.6.11 -->
#### velas-validator improvements:
  - `velas-test-validator` faucet balance now configurable
  
<!-- 1.6.13 -->
- `velas-validator`: run poh test earlier in startup
- Remove unwrap of metrics client instatiaion

<!-- 1.6.14 -->
- Expose validator RPC Pubsub subscription limit via CLI flag
- Harden loader instruction checks
- Add metrics for RPC Pubsub subscriptions and RPC health check
- Update validator requirements docs with networking guidance

### Other changes:
<!-- 1.5.17 -->
- Program Test now properly handles duplicate accounts
- Improved handling of duplicate shreds

<!-- 1.6.2 -->
- Adds loader instruction and cli tooling for closing program buffer accounts
- Velas CLI now supports dumping the transaction message in sign-only mode

- Fixes pesky cli crash when calling `velas epoch-info` against non-RPC nodes
- Solana Ledger app settings now available via the remote-wallet crate
- Update BPF Toolchain to v1.4
- Program Test now properly handles duplicate accounts
- Improved handling of duplicate shreds
- `velas-keygen` grind can now output BIP39 mnemonics (see `--use-mnemonic`)


<!-- 1.5.18 -->
- Improves ClusterInfo performance

<!-- 1.6.3 -->
- Write locks on sysvar accounts are automatically lowered to read locks; increases transaction processing batch sizes
- Fixes BPF ELF layout
- `velas-validator monitor` now displays the max retransmit slot

<!-- 1.6.4 -->
- Require 90% stake in gossip for restart
- PoH timing improvements and metrics
- `wait-for-restart-window` improvements

<!-- 1.6.5 -->
- `velas-validator`: Add new authorized-voter subcommand to give dynamic control over the validator's ability to vote
- `velas-test-validator`: Add `--faucet-port` option
- Bug fix in banking stage
- Update BPF VM

<!-- 1.6.6 -->
- Gossip pull request optimizations
- Airdrop is now available via RPC
- Improved reliability of System account decoding

<!-- 1.5.19 -->
Update BPF VM
Erasure coding improvements
Various other bug fixes and minor performance improvements

<!-- 1.6.7 -->
<!-- Documentation improvements -->
Upgrade Rust toolchain to 1.51

<!-- 1.6.8 -->
<!-- - Minor documentation fixes -->

<!-- 1.6.9 -->
#### SDK improvements:
  - Improves C sdk
  - Adds `get_instance_packed_len` for variable-size types
  - Adds Keccak256 syscall feature
<!-- - Documentation improvements -->

<!-- 1.6.10 -->
<!-- 1.6.11 -->
<!-- - Documentation improvements -->

<!-- 1.6.12 -->
- Changed ledger (RocksDB) cleaning strategy to avoid peaked IOs at every few days and possible stalls 
  (NOTE: it'll take a week or two for nodes with existing ledger to transition; also downgrading is supported).
- New minor runtime feature activation for system instruction processor
- Improve usability of `ProgramTest`
- Bump internal libraries (`spl-token`, `jsonrpc`)
- Other stability improvements.


### BREAKING CHANGES
- `velas transfer` will no longer transfer to an unfunded recipient by default to prevent accidental loss of funds. Add the `--allow-unfunded-recipient` flag to override
- `velas stake-account` and `velas vote-account` will only show rewards with the `--with-rewards` flag added
- `velas-faucet` args `--slice` and `--per-time-cap` now apply to individual IP addresses and recipient account addresses

<!-- - `velas stake-account` and `velas vote-account` will only show rewards with the `--with-rewards` flag added -->
<!-- - `velas-faucet` args `--slice` and `--per-time-cap` now apply to individual IP addresses and recipient account addresses -->
- `velas stake-history` output is now limited to 10 entries by default, use `--limit` to display more
- The default commitment level for PubSub now correctly uses "finalized" as the default commitment level, as documented, instead of "confirmed" (#16596)

- The recently added ask: signer-source with bip32 support (v1.6.7) renamed to prompt:. With no query string, prompt: derives the solana bip44 base key, m/44'/501'



[migrating-guide]: https://github.com/solana-labs/solana/wiki/Migrating-Rust-programs-from-v1.5-to-v1.6
