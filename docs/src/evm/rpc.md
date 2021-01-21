---
title: EVM JSONRPC API
---

## The default block parameter

The following methods have an optional extra `defaultBlock` parameter:

- [eth_estimateGas](#eth_estimategas)
- [eth_getBalance](#eth_getbalance)
- [eth_getCode](#eth_getcode)
- [eth_getTransactionCount](#eth_gettransactioncount)
- [eth_getStorageAt](#eth_getstorageat)
- [eth_call](#eth_call)

When requests are made that act on the state of Ethereum, the last parameter determines the height of the block.

The following options are possible for the `defaultBlock` parameter:

- `Quantity`/`Integer` - an integer block number;
- `String "earliest"` - for the earliest/genesis block;
- `String "latest"` - for the latest mined block;

## JSON-RPC methods

- [eth_blockNumber](#eth_blocknumber)
- [eth_call](#eth_call)
- [eth_chainId](#eth_chainid)
- [eth_coinbase](#eth_coinbase)
- [eth_estimateGas](#eth_estimategas)
- [eth_getBalance](#eth_getbalance)
- [eth_getBlockByNumber](#eth_getblockbynumber)
- [eth_getCode](#eth_getcode)
- [eth_getStorageAt](#eth_getstorageat)
- [eth_getTransactionByHash](#eth_gettransactionbyhash)
- [eth_getTransactionReceipt](#eth_gettransactionreceipt)


## JSON-RPC specific for EVM Bridge


- [eth_accounts](#eth_accounts)

- [eth_gasPrice](#eth_gasprice)
- [eth_sendRawTransaction](#eth_sendrawtransaction)
- [eth_sendTransaction](#eth_sendtransaction)
- [eth_sign](#eth_sign)
- [eth_signTransaction](#eth_signtransaction)

## JSON-RPC API Reference

### eth_accounts

Returns a list of addresses owned by client.

#### Parameters

None

#### Returns

- `Array` - 20 Bytes - addresses owned by the client.

#### Example

Request
```bash
curl --data '{"method":"eth_accounts","params":[],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": ["0x407d73d8a49eeb85d32cf465507dd71d507100c1"]
}
```

***

### eth_blockNumber

Returns the number of most recent block.

#### Parameters

None

#### Returns

- `Quantity` - integer of the current block number the client is on.

#### Example

Request
```bash
curl --data '{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x4b7" // 1207
}
```

***

### eth_call

Executes a new message call immediately without creating a transaction on the block chain.

#### Parameters

0. `Object` - The transaction call object.
    - `from`:   `Address` - (optional) 20 Bytes - The address the transaction is send from.
    - `to`:   `Address` - (optional when creating new contract) 20 Bytes - The address the transaction is directed to.
    - `gas`:   `Quantity` - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
    - `gasPrice`:   `Quantity` - (optional) Integer of the gas price used for each paid gas.
    - `value`:   `Quantity` - (optional) Integer of the value sent with this transaction.
    - `data`:   `Data` - (optional) 4 byte hash of the method signature followed by encoded parameters. For details see [Ethereum Contract ABI](https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI).
0. `Quantity` or `Tag` - (optional) Integer block number, or the string `'latest'`, `'earliest'` or `'pending'`, see the [default block parameter](#the-default-block-parameter).

```js
params: [{
  "from": "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
  "to": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
  "value": "0x186a0" // 100000
}]
```

#### Returns

- `Data` - the return value of executed contract.

#### Example

Request
```bash
curl --data '{"method":"eth_call","params":[{"from":"0x407d73d8a49eeb85d32cf465507dd71d507100c1","to":"0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b","value":"0x186a0"}],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x"
}
```

***

### eth_chainId

Returns the EIP155 chain ID used for transaction signing at the current best block. Null is returned if not available.

#### Parameters

None

#### Returns

- `Quantity` - EIP155 Chain ID, or `null` if not available.

#### Example

Request
```bash
curl --data '{"method":"eth_chainId","params":[],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x1"
}
```

***

### eth_estimateGas

Makes a call or transaction, which won't be added to the blockchain and returns the used gas, which can be used for estimating the used gas.

#### Parameters

0. `Object` - Same as [eth_call](#eth_call) parameters, except that all properties are optional.
    - `from`:   `Address` - (optional) 20 Bytes - The address the transaction is send from.
    - `to`:   `Address` - (optional when creating new contract) 20 Bytes - The address the transaction is directed to.
    - `gas`:   `Quantity` - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
    - `gasPrice`:   `Quantity` - (optional) Integer of the gas price used for each paid gas.
    - `value`:   `Quantity` - (optional) Integer of the value sent with this transaction.
    - `data`:   `Data` - (optional) 4 byte hash of the method signature followed by encoded parameters. For details see [Ethereum Contract ABI](https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI).
0. `Quantity` or `Tag` - (optional) Integer block number, or the string `'latest'`, `'earliest'` or `'pending'`, see the [default block parameter](#the-default-block-parameter).

#### Returns

- `Quantity` - The amount of gas used.

#### Example

Request
```bash
curl --data '{"method":"eth_estimateGas","params":[{ ... }],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x5208" // 21000
}
```

***

### eth_gasPrice

Returns the current price per gas in wei.

#### Parameters

None

#### Returns

- `Quantity` - integer of the current gas price in wei.

#### Example

Request
```bash
curl --data '{"method":"eth_gasPrice","params":[],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x9184e72a000" // 10000000000000
}
```

***

### eth_getBalance

Returns the balance of the account of given address.

#### Parameters

0. `Address` - 20 Bytes - address to check for balance.
0. `Quantity` or `Tag` - (optional) integer block number, or the string `'latest'`, `'earliest'` or `'pending'`, see the [default block parameter](#the-default-block-parameter).

```js
params: ["0x407d73d8a49eeb85d32cf465507dd71d507100c1"]
```

#### Returns

- `Quantity` - integer of the current balance in wei.

#### Example

Request
```bash
curl --data '{"method":"eth_getBalance","params":["0x407d73d8a49eeb85d32cf465507dd71d507100c1"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x0234c8a3397aab58"
}
```

***

### eth_getBlockByNumber

Returns information about a block by block number.

#### Parameters

0. `Quantity` or `Tag` - integer of a block number, or the string `'earliest'`, `'latest'` or `'pending'`, as in the [default block parameter](#the-default-block-parameter).
0. `Boolean` - If `true` it returns the full transaction objects, if `false` only the hashes of the transactions.

```js
params: [
  "0x1b4", // 436
  true
]
```

#### Returns

- `Object` - A block object, or `null` when no block was found.
    - `number`:   `Quantity` - The block number. `null` when its pending block
    - `hash`:   `Hash` - 32 Bytes - hash of the block. `null` when its pending block
    - `parentHash`:   `Hash` - 32 Bytes - hash of the parent block
    - `author`:   `Address` - 20 Bytes - the address of the author of the block (the beneficiary to whom the mining rewards were given)
    - `miner`:   `Address` - 20 Bytes - alias of 'author'
    - `gasLimit`:   `Quantity` - the maximum gas allowed in this block
    - `gasUsed`:   `Quantity` - the total used gas by all transactions in this block
    - `timestamp`:   `Quantity` - the unix timestamp for when the block was collated
    - `transactions`:   `Array` - Array of transaction objects, or 32 Bytes transaction hashes depending on the last given parameter

#### Example

Request
```bash
curl --data '{"method":"eth_getBlockByNumber","params":["0x1b4",true],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "number": "0x1b4", // 436
    "hash": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331",
    "parentHash": "0x9646252be9520f6e71339a8df9c55e4d7619deeb018d2a3f2d21fc165dde5eb5",
    "sealFields": [
      "0xe04d296d2460cfb8472af2c5fd05b5a214109c25688d3704aed5484f9a7792f2",
      "0x0000000000000042"
    ],
    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    "logsBloom": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331",
    "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
    "stateRoot": "0xd5855eb08b3387c0af375e9cdb6acfc05eb8f519e419b874b6ff2ffda7ed1dff",
    "miner": "0x4e65fda2159562a496f9f3522f89122a3088497a",
    "difficulty": "0x27f07", // 163591
    "totalDifficulty": "0x27f07", // 163591
    "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "size": "0x27f07", // 163591
    "gasLimit": "0x9f759", // 653145
    "minGasPrice": "0x9f759", // 653145
    "gasUsed": "0x9f759", // 653145
    "timestamp": "0x54e34e8e", // 1424182926
    "transactions": [{ ... }, { ... }, ...],
    "uncles": [
      "0x1606e5...",
      "0xd5145a9..."
    ]
  }
}
```

***

### eth_getBlockTransactionCountByHash

Returns the number of transactions in a block from a block matching the given block hash.

#### Parameters

0. `Hash` - 32 Bytes - hash of a block.

```js
params: ["0xb903239f8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238"]
```

#### Returns

- `Quantity` - integer of the number of transactions in this block.

#### Example

Request
```bash
curl --data '{"method":"eth_getBlockTransactionCountByHash","params":["0xb903239f8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0xb" // 11
}
```

***

### eth_getStorageAt

Returns the value from a storage position at a given address.

#### Parameters

0. `Address` - 20 Bytes - address of the storage.
0. `Quantity` - integer of the position in the storage.
0. `Quantity` or `Tag` - (optional) integer block number, or the string `'latest'`, `'earliest'` or `'pending'`, see the [default block parameter](#the-default-block-parameter).

```js
params: [
  "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
  "0x0", // 0
  "0x2" // 2
]
```

#### Returns

- `Data` - the value at this storage position.

#### Example

Request
```bash
curl --data '{"method":"eth_getStorageAt","params":["0x407d73d8a49eeb85d32cf465507dd71d507100c1","0x0","0x2"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x0000000000000000000000000000000000000000000000000000000000000003"
}
```

***

### eth_getTransactionByHash

Returns the information about a transaction requested by transaction hash.

#### Parameters

0. `Hash` - 32 Bytes - hash of a transaction.

```js
params: ["0xb903239f8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238"]
```

#### Returns

- `Object` - A transaction object, or `null` when no transaction was found:
    - `hash`:   `Hash` - 32 Bytes - hash of the transaction.
    - `nonce`:   `Quantity` - the number of transactions made by the sender prior to this one.
    - `blockHash`:   `Hash` - 32 Bytes - hash of the block where this transaction was in. `null` when its pending.
    - `blockNumber`:   `Quantity` or `Tag` - block number where this transaction was in. `null` when its pending.
    - `transactionIndex`:   `Quantity` - integer of the transactions index position in the block. `null` when its pending.
    - `from`:   `Address` - 20 Bytes - address of the sender.
    - `to`:   `Address` - 20 Bytes - address of the receiver. `null` when its a contract creation transaction.
    - `value`:   `Quantity` - value transferred in Wei.
    - `gasPrice`:   `Quantity` - gas price provided by the sender in Wei.
    - `gas`:   `Quantity` - gas provided by the sender.
    - `input`:   `Data` - the data send along with the transaction.
    - `v`:   `Quantity` - the standardised V field of the signature.
    - `standardV`:   `Quantity` - the standardised V field of the signature (0 or 1).
    - `r`:   `Quantity` - the R field of the signature.
    - `raw`:   `Data` - raw transaction data
    - `publicKey`:   `Hash` - public key of the signer.
    - `chainId`:   `Quantity` - the chain id of the transaction, if any.
    - `creates`:   `Hash` - creates contract hash
    - `condition`:   `Object` - (optional) conditional submission, Block number in `block` or timestamp in `time` or `null`.

#### Example

Request
```bash
curl --data '{"method":"eth_getTransactionByHash","params":["0xb903239f8543d04b5dc1ba6579132b143087c68db1b2168786408fcbce568238"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "hash": "0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b",
    "nonce": "0x0", // 0
    "blockHash": "0xbeab0aa2411b7ab17f30a99d3cb9c6ef2fc5426d6ad6fd9e2a26a6aed1d1055b",
    "blockNumber": "0x15df", // 5599
    "transactionIndex": "0x1", // 1
    "from": "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
    "to": "0x853f43d8a49eeb85d32cf465507dd71d507100c1",
    "value": "0x7f110", // 520464
    "gas": "0x7f110", // 520464
    "gasPrice": "0x09184e72a000",
    "input": "0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360"
  }
}
```

***

### eth_getTransactionCount

Returns the number of transactions *sent* from an address.

#### Parameters

0. `Address` - 20 Bytes - address.
0. `Quantity` or `Tag` - (optional) integer block number, or the string `'latest'`, `'earliest'` or `'pending'`, see the [default block parameter](#the-default-block-parameter).

```js
params: ["0x407d73d8a49eeb85d32cf465507dd71d507100c1"]
```

#### Returns

- `Quantity` - integer of the number of transactions send from this address.

#### Example

Request
```bash
curl --data '{"method":"eth_getTransactionCount","params":["0x407d73d8a49eeb85d32cf465507dd71d507100c1"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0x1" // 1
}
```

***

### eth_getTransactionReceipt

Returns the receipt of a transaction by transaction hash.

**Note** That the receipt is available even for pending transactions.

#### Parameters

0. `Hash` - hash of a transaction.

```js
params: ["0x444172bef57ad978655171a8af2cfd89baa02a97fcb773067aef7794d6913374"]
```

#### Returns

- `Object` - A transaction receipt object, or `null` when no receipt was found:
    - `blockHash`:   `Hash` - 32 Bytes - hash of the block where this transaction was in.
    - `blockNumber`:   `Quantity` or `Tag` - block number where this transaction was in.
    - `contractAddress`:   `Address` - 20 Bytes - The contract address created, if the transaction was a contract creation, otherwise `null`.
    - `cumulativeGasUsed`:   `Quantity` - The total amount of gas used when this transaction was executed in the block.
    - `from`:   `Address` - 20 Bytes - The address of the sender.
    - `to`:   `Address` - 20 Bytes - The address of the receiver. null when it’s a contract creation transaction.
    - `gasUsed`:   `Quantity` - The amount of gas used by this specific transaction alone.
    - `logs`:   `Array` - Array of log objects, which this transaction generated.
    - `logsBloom`:   `Hash` - 256 Bytes - A bloom filter of logs/events generated by contracts during transaction execution. Used to efficiently rule out transactions without expected logs.
    - `root`:   `Hash` - 32 Bytes - Merkle root of the state trie after the transaction has been executed (optional after Byzantium hard fork [EIP609](https://eips.ethereum.org/EIPS/eip-609))
    - `status`:   `Quantity` - `0x0` indicates transaction failure , `0x1` indicates transaction success. Set for blocks mined after Byzantium hard fork [EIP609](https://eips.ethereum.org/EIPS/eip-609), `null` before.
    - `transactionHash`:   `Hash` - 32 Bytes - hash of the transaction.
    - `transactionIndex`:   `Quantity` - Integer of the transactions index position in the block.

#### Example

Request
```bash
curl --data '{"method":"eth_getTransactionReceipt","params":["0x444172bef57ad978655171a8af2cfd89baa02a97fcb773067aef7794d6913374"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "blockHash": "0x67c0303244ae4beeec329e0c66198e8db8938a94d15a366c7514626528abfc8c",
    "blockNumber": "0x6914b0",
    "contractAddress": "0x471a8bf3fd0dfbe20658a97155388cec674190bf", // or null, if none was created
    "from": "0xc931d93e97ab07fe42d923478ba2465f2",
    "to": null, // value is null because this example transaction is a contract creation
    "cumulativeGasUsed": "0x158e33",
    "gasUsed": "0xba2e6",
    "logs": [], // logs as returned by eth_getFilterLogs, etc.
    "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "root": null,
    "status": "0x1",
    "transactionHash": "0x444172bef57ad978655171a8af2cfd89baa02a97fcb773067aef7794d6913374",
    "transactionIndex": "0x4"
  }
}
```

***


### eth_sendRawTransaction

Creates new message call transaction or a contract creation for signed transactions.

**Note:** `eth_submitTransaction` is an alias of this method.

#### Parameters

0. `Data` - The signed transaction data.

```js
params: ["0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"]
```

#### Returns

- `Hash` - 32 Bytes - the transaction hash, or the zero hash if the transaction is not yet available

Use [eth_getTransactionReceipt](#eth_gettransactionreceipt) to get the contract address, after the transaction was mined, when you created a contract.

#### Example

Request
```bash
curl --data '{"method":"eth_sendRawTransaction","params":["0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"
}
```

***

### eth_sendTransaction

Creates new message call transaction or a contract creation, if the data field contains code.

#### Parameters

0. `Object` - The transaction object.
    - `from`:   `Address` - 20 Bytes - The address the transaction is send from.
    - `to`:   `Address` - (optional) 20 Bytes - The address the transaction is directed to.
    - `gas`:   `Quantity` - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
    - `gasPrice`:   `Quantity` - (optional) Integer of the gas price used for each paid gas.
    - `value`:   `Quantity` - (optional) Integer of the value sent with this transaction.
    - `data`:   `Data` - (optional) 4 byte hash of the method signature followed by encoded parameters. For details see [Ethereum Contract ABI](https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI).
    - `nonce`:   `Quantity` - (optional) Integer of a nonce. This allows to overwrite your own pending transactions that use the same nonce.
    - `condition`:   `Object` - (optional) Conditional submission of the transaction. Can be either an integer block number `{ block: 1 }` or UTC timestamp (in seconds) `{ time: 1491290692 }` or `null`.

```js
params: [{
  "from": "0xb60e8dd61c5d32be8058bb8eb970870f07233155",
  "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
  "gas": "0x76c0", // 30400
  "gasPrice": "0x9184e72a000", // 10000000000000
  "value": "0x9184e72a", // 2441406250
  "data": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"
}]
```

#### Returns

- `Hash` - 32 Bytes - the transaction hash, or the zero hash if the transaction is not yet available.

Use [eth_getTransactionReceipt](#eth_gettransactionreceipt) to get the contract address, after the transaction was mined, when you created a contract.

#### Example

Request
```bash
curl --data '{"method":"eth_sendTransaction","params":[{"from":"0xb60e8dd61c5d32be8058bb8eb970870f07233155","to":"0xd46e8dd67c5d32be8058bb8eb970870f07244567","gas":"0x76c0","gasPrice":"0x9184e72a000","value":"0x9184e72a","data":"0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675"}],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331"
}
```

***

### eth_sign

The sign method calculates an Ethereum specific signature with: `sign(keccak256("Ethereum Signed Message:
" + len(message) + message)))`.

#### Parameters

0. `Address` - 20 Bytes - address.
0. `Data` - Data which hash to sign.

```js
params: [
  "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826",
  "0x5363686f6f6c627573" // Schoolbus
]
```

#### Returns

- `Data` - Signed data.

#### Example

Request
```bash
curl --data '{"method":"eth_sign","params":["0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826","0x5363686f6f6c627573"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": "0xb1092cb5b23c2aa55e5b5787729c6be812509376de99a52bea2b41e5a5f8601c5641e74d01e4493c17bf1ef8b179c49362b2c721222128d58422a539310c6ecd1b"
}
```

***

### eth_signTransaction

Signs transactions without dispatching it to the network. It can be later submitted using [eth_sendRawTransaction](#eth_sendrawtransaction).

#### Parameters

0. `Object` - Transaction object, see [eth_sendTransaction](#eth_sendTransaction).
    - `from`:   `Address` - 20 Bytes - The address the transaction is send from.
    - `to`:   `Address` - (optional) 20 Bytes - The address the transaction is directed to.
    - `gas`:   `Quantity` - (optional) Integer of the gas provided for the transaction execution. eth_call consumes zero gas, but this parameter may be needed by some executions.
    - `gasPrice`:   `Quantity` - (optional) Integer of the gas price used for each paid gas.
    - `value`:   `Quantity` - (optional) Integer of the value sent with this transaction.
    - `data`:   `Data` - (optional) 4 byte hash of the method signature followed by encoded parameters. For details see [Ethereum Contract ABI](https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI).
    - `nonce`:   `Quantity` - (optional) Integer of a nonce. This allows to overwrite your own pending transactions that use the same nonce.
    - `condition`:   `Object` - (optional) Conditional submission of the transaction. Can be either an integer block number `{ block: 1 }` or UTC timestamp (in seconds) `{ time: 1491290692 }` or `null`.

#### Returns

- `Object` - Signed transaction and it's details:
    - `raw`:   `Data` - The signed, RLP encoded transaction.
    - `tx`:   `Object` - Transaction object:
        - `hash`:   `Hash` - 32 Bytes - hash of the transaction.
        - `nonce`:   `Quantity` - the number of transactions made by the sender prior to this one.
        - `blockHash`:   `Hash` - 32 Bytes - hash of the block where this transaction was in. `null` when its pending.
        - `blockNumber`:   `Quantity` or `Tag` - block number where this transaction was in. `null` when its pending.
        - `transactionIndex`:   `Quantity` - integer of the transactions index position in the block. `null` when its pending.
        - `from`:   `Address` - 20 Bytes - address of the sender.
        - `to`:   `Address` - 20 Bytes - address of the receiver. `null` when its a contract creation transaction.
        - `value`:   `Quantity` - value transferred in Wei.
        - `gasPrice`:   `Quantity` - gas price provided by the sender in Wei.
        - `gas`:   `Quantity` - gas provided by the sender.
        - `input`:   `Data` - the data send along with the transaction.
        - `v`:   `Quantity` - the standardised V field of the signature.
        - `standard_v`:   `Quantity` - the standardised V field of the signature (0 or 1).
        - `r`:   `Quantity` - the R field of the signature.
        - `raw`:   `Data` - raw transaction data
        - `publicKey`:   `Hash` - public key of the signer.
        - `chainId`:   `Quantity` - the chain id of the transaction, if any.
        - `creates`:   `Hash` - creates contract hash
        - `condition`:   `Object` - (optional) conditional submission, Block number in `block` or timestamp in `time` or `null`.

#### Example

Request
```bash
curl --data '{"method":"eth_signTransaction","params":[{ ... }],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:8545
```

Response
```js
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "raw": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445675058bb8eb970870f072445675",
    "tx": {
      "hash": "0xc6ef2fc5426d6ad6fd9e2a26abeab0aa2411b7ab17f30a99d3cb96aed1d1055b",
      "nonce": "0x0", // 0
      "blockHash": "0xbeab0aa2411b7ab17f30a99d3cb9c6ef2fc5426d6ad6fd9e2a26a6aed1d1055b",
      "blockNumber": "0x15df", // 5599
      "transactionIndex": "0x1", // 1
      "from": "0x407d73d8a49eeb85d32cf465507dd71d507100c1",
      "to": "0x853f43d8a49eeb85d32cf465507dd71d507100c1",
      "value": "0x7f110", // 520464
      "gas": "0x7f110", // 520464
      "gasPrice": "0x09184e72a000",
      "input": "0x603880600c6000396000f300603880600c6000396000f3603880600c6000396000f360"
    }
  }
}
```

***