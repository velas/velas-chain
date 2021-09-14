# Our upderstanding of solana(native) runtime.

As a regular blockchain, solana has its transaction format.
Transaction is data transfer object, that user publish in order to change some data in the shared (among parties) state.
In solana state is represented as set of accounts. 

Some blockchains has smart contracts - arbitrary code that can extend blockchain capabilities, and should be executed on blockchain parties.
Solana names them "programs". Each program has entrypoint, which expects some bytearray, each program decide how they represent this bytearray.

In solana transaction contain multiple instructions. Instruction is a chunk of data that is feeded into program entrypoint, with some meta information about account that it uses, and program identificator that should be executed.
Instruction can also be perceived as minimal execution unit.
When any instruction fails - full transaction will fail, and any data change will be reverted.

## Bank

As we understand bank - is a structure that rule how block will be formed. It can be in completed, or in incompleted state.
When state is incompleted (unfreezed) - transaction processing and committing are allowed.
Completed(freezed) banks are used only for transaction simulation in rpc.
Bank structure represent current state of blockchain with refference to actual account database, etc.

### Multithread execution
For state, we understand that solana has same mechanism as in rw-lock. Account metas from transaction define how it would use account state.
If account state is used as write, then this account should not be used from any other thread, for time of transaction execution.

So for multithread execution, solana just need to balance transactions among threads, apply rw-lock rule for each account in execution batch, if any of rw-locks rising will fail - transaction execution should be postponed.

## Blockstore
Blockstore in solana is just retrospective information storage, it store shreds(parts of block) for blocks, and multiple metadata indexes.
Blockstore can be purged, to shrink space used on disk.
To save shared disk space, for rpc, blockstore is also backed-up to bigtable.



# Requirements

Main requirement was to create a program in solana that can execute EVM bytecode.
Later it's extended too, not only execute evm bytecode, but also be compatible with ethereum  transaction and blocks structure.
Also for better user expirience we should support eth_ rpc calls https://openethereum.github.io/JSONRPC-eth-module

# Design choses

## Serialization format

When we started, `bincode` was "default" serialization format, and we was familar with serde family, so we decide to keep it as format for evm instruction. As a drawback of fast production release, our evm types are serialized as a hex string instead of binnary data, which increase memory footprints.

But we have plan change this format in future to `borsch`, which will allow better compatibility with JS clients.

## Single storage for data

Currently all evm implementation are singlethread. Moreover, any transaction in evm world, can refer to any address, even it can compute address
and evaluate it from computed value, so it is complicated task to seperate evm storage into multiple independent parts with rw-lock mechanism as in solana.

Solana has transaction and account size limitation. It expect transaction size to be less than ipv6 MTU 1280 bytes, in order to process and distribute transactions faster.
For account, they have hand-written database, which can handle multiple versions of some account, but they limit account size to be 10MB max.
Also they use they actively use cloning of accounts, therefore, increasing the account size was not an option for us.

So our design was to implement storage, for big state, with versioning support. Also as requirement we should support most of ethereum rpc calls.
This rpc calls need to get state from past, so support multiple version of storage is also required. 

### Abstract view of Trie db
As state provider, we adopt https://github.com/velas/triedb - this is modified merkle-patricia tree from sputnikvm https://github.com/ETCDEVTeam/etcommon-rs/tree/master/trie with small code cleanups, and refactoring to make it work only with rocksdb (persistent storage). See https://eth.wiki/en/fundamentals/patricia-tree as reference for implementation, and https://medium.com/@chiqing/merkle-patricia-trie-explained-ae3ac6a7e123 as explanation how it works.

In shorts, we work with this as with k-v database:
where k - is an evm account address (20 bytes long),
and v - is a evm account state (balance, nonce, code, storage).

For versioning, this abstraction also give us a special "handle" called "state root". We can think that "state root" is like a version id.
In order to get some value by key, you also should provide "state root". When you need to create new version, all changes should be accumulated to a tree-patch, which will describe what tree nodes should be modified. And after apply this patch new "state root" is returned.

Database state after apply changes:

![Trie state after change](https://hsto.org/r/w1560/webt/lv/-e/mr/lv-emrvfxac4ccdfi38ps6ajvfs.png)

## Evm-state details

As base for our implementation we took https://github.com/rust-blockchain/evm. The main idea behind this project is to allow easy embedding.
It also provide StackExecutor - object that allows you execute call and create transactions on some abstract state.
We use this executor to execute single evm transaction.

Evm-state crate provide four kind of thinks:
1) Types that is inherited from ethereum: transactions.rs types.rs.
2) Storage that save state, in ethereum partially compatible format: storage.rs/state.rs.
3) Executor that should execute evm transactions, and modify storage: executor.rs.
4) And context that is just provide some meta information to executor about, blockchain, it's configuration, and some transaction info: context.rs.

### EVM Transactions
In evm-state/transactions.rs we save types related to transaction structure, compatible with ethereum world.
In ethereum world RLP encoding is most important part for compatibility.
The main properties of transaction, is that it uses nonce to prevent double spend, and that it didn't store caller\sender address in its structure.
This address should be recovered from signature.

As extension to ethereum world, we have UnsignedTransaction or AuthorizedTranasction (in terms of evm_loader program).

UnsignedTransaction is a transaction that is executed and stored without signature check. Executor of method `transaction_execute_unsinged`
should verify that caller really authorized to call this method. More of this in `Evm loader program/Authorized Transaction`
Because unsignedTransaction didn't store signature, in `UnsignedTransactionWithCaller` structure we add caller address, and chain_id to its structure.

`TransactionReceipt` - is other type from ethereum world, in ethereum it saves information about transaction execution. In our implementation transaction receipt contain transaction, and their stored in single collection.

### Storage module
Storage module is an abstraction that provide triedbs for Accounts and AccountStorage.
It provides methods for open db, create backup (used in snapshot), and restoring from this backup.
Currently powered is worked by rocksdb mechanism, and it saves all versions that node know in single backup, that then will be shared among nodes, trough solanas snapshots.

Known flaws:
1) It contain a lot of dead code for creating colomnfamilies in rocksdb.
2) Also we know that not much of validation is done in snapshot verification.

### State module
State is the biggest module from our implementation.

The main reason to seperate state and executor, was the idea to make some structure that carry data between executions.
And create executor only for executing single/batch of transactions.

Original state machine design can be drawn in diagram:

     new_bank
    ┌───────┐
    │       │
    │  ┌────┴─────┐new_bank┌───────────┐
    └──►  Empty   ◄────────┤ Committed │
       └────┬─────┘        └─────▲─────┘
            │                    │
   execute  │                    │
     tx     │                    │
            │                    │
       ┌────▼─────┐              │
       │  Active  ├──────────────┘
       └──────────┘    commit(on bank freeze)

State is created as `Empty`. When any tx is procesed, it transit to `Active`.
`Active` state is accumulating state changes and transactions that would be executed, but newer write in database dirrectly.
On bank freeze `Active` state transit to `Committed` and save block header in its structure.

When solana create new bank (at slot beginning) state is again reset to `Empty`.

Original state machine was later simplified in code, and now Empty and Active are merged into one - `Incoming`

`Incoming` is handled as empty, if state_updates.is_empty() && executed_transactions.is_empty(). See `is_active_changes` method.

In shorts, the difference betwee Incoming and Committed can be sumarized in table:

|                              | Incoming | Committed |
| ---------------------------- | -------- | --------- |
| Change persist store         | -        | +         |
| Calculate roots *            | -        | +         |
| Will save block in database  | -        | +         |
| Has unsaved changes          | **       | -         |
| Can be used to retrieve data | +        | +         |
| Can be used to execute tx    | +        | ***       |

*-  Transaction roots, and receip roots are used in block structure in order to implement SPV clients, and allow blockchain verification for light clients.
**- Incoming can contain unsaved changes or not, see `is_active_changes` method.
***- Technically Transaction can be executed on Committed state but only without later persisting its results.

State persistent:
`Incoming` and `Committed` Also has wrappers `EvmBackend<Incoming>`\ `EvmBackend<Committed>` the difference between them is that
`Incoming` and `Committed` only save fields that can be persisted, and EvmBackend also add refference to global KVS.

`EvmState` - is a type that monomorphize this two states and provide highlevel wrapper for bank to work with.
Methods that correspond to state transition: `EvmState::try_commit` `EvmState::new_from_parent`

Save block: For saving blocks in blockstore, we go the same way as solana goes - after bank finalization background service EvmRecorderService receive block from `Committed` state and save it in blockstore.

### Executor
Provides api for transaction execution.
For executor construction you need Incoming state of EvmBackend and context information.
As result it provide methods that can be called in evm_loader, some evm specific contracts are hardcoded in calls, and this method are marked as failable, other solana specific are implemented in evm_loader.

### Context

Context module provide types for executor context.

`TransactionContext` - provide information about current transaction, and should be set in `Executor::transaction_execute*` methods.
`EvmConfig` - provide information about current blockchain configuration. It designed to be changed only at epoch change, and currently it didn't change at all.
`ChainContext` - provide last 256 blockhashes

And `ExecutorContext` - which provide `Backend` logic for `StackExecutor` (simply provide all data fields that stack executor need, like account state, account storage, caller address, last block hashes, timestamp, etc.).

# Evm loader program.
Evm loader program is solana native program with custom entrypoint that execute next instruction types:

1) `EvmTransaction` - execute regular evm transaction, it is limited to be less than 900 bytes in bincode encoding, internally call `Executor::transaction_execute`. As extension to regular transaction flow, we implement precompile module, wich provide evm specific precompile, and swap from evm to solana world code.
2) `SwapNativeToEther` - transfer solana lamports to evm world. Internally it just take lamports from user account, transfer it to EvmState account in solana world, and mint new tokens in evm world for specific account.
3) `FreeOwnership` - SwapNativeToEther is done in three instructions: 1) assign account to evm, 2) SwapNativeToEther 3) FreeOwnership.
It just set account owner to system program, if it perviously was set ot evm account.
4) `EvmBigTransaction` - Big transaction functionality is done like in solana bpf program deploy. User create account that assign to evm program, write batches trough `EvmTransactionWrite` and after this call `EvmTransactionExecute` to ask evm_loader to load transaction from account and execute it using 1), or `EvmTransactionExecuteUnsigned` to execute it using 5)
5) `EvmAuthorizedTransaction` - Execute evm transaction that is created by solana program. In evm world we allocate addresses started with `0xacc0`, check method `evm_address_for_program` for more details how we allocate addresses. This transaction is signed in solana, so we check is_signed flag, and execute it trough `Executor::transaction_execute_unsigned`.
   
Swap from evm implementation:
Swap from evm world is done by implementing precompile that modify solana state,
when any transaction make call to specific address `ETH_TO_VLX_ADDR` program interupted and `ETH_TO_VLX_CODE` is called.
When it is called, it expect `recipient` address as argument, also this precompile is done as payable, so it is also expect internal `value` argument, before call this value is substracted from caller account. And `ETH_TO_VLX_CODE` is transfer it from EvmState account to account that it tries to find by `recipient` address.

Problems that we discover before:
- Both our swaps works invalid with revert. `SwapNativeToEther` with revert in solana can keep money on evm, and reverts in evm didn't trigger revert in solana. To fix this, now revert in evm trigger revert in solana, and on any revert, state changes are ignored for whole transaction execution.