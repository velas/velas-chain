---
title: EVM in solana
---

[Solana application model](apps/rent.md) is aiming to high performance by spliting its modifiable state on accounts.
While this allows to process transactions in parallel on single shard, it also introduce complication for ordinary DApps developer.
Also, most of DApps infrastructure is already relies on Solidity, and targeting Ethereum blockchain.
This two reasons can significantly slow down the spread of solana ecosystem.

To make life of DApps developers, and integrators more easier, we at Velas introduce full hybrid of solana and EVM.

## Metamask support

In our integration we support Metamask. In order to use it just follow [metamask official instruction](https://metamask.zendesk.com/hc/en-us/articles/360043227612-How-to-add-a-custom-Network-RPC-and-or-Block-Explorer) to add any public [EVM Bridge](evm/bridge.md) as custom network.


## Transfer native token to EVM
In order to transfer native token into EVM, we can use evm-utils binary.
Note: EVM store tokens in nano plancks, so when you transfer for example, 5 planks, your balance will be reported as 5*10^9

Usage:
```
/target/debug/evm-utils transfer-to-eth --help
evm-utils-transfer-to-eth 0.1.0
Transfer solana token to EVM world

USAGE:
    evm-utils transfer-to-eth <amount> <ether-address>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <amount>           Amount in plancks
    <ether-address>    Address in evm, that will receive tokens

```

Example:
```
evm-utils transfer-to-eth 5 9Edb9E0B88Dbf2a29aE121a657e1860aEceaA53D
```
Result after transaction processing:
```
[2020-12-26T15:03:01Z INFO  evm_utils] Loading keypair from: /home/vladimir/.config/solana/id.json
Transaction signature = 5d3eP741NYgemyM4CLmXuTEcP8f8w7QxfZ5vBxorqenEtNeSHWMFpkwtyi1meFKHVNXzDD3NbvFCExjZH79gEMKk
```


To make sure that balance was updated, you can request it using rpc:
```
curl -s -X POST --data '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x9Edb9E0B88Dbf2a29aE121a657e1860aEceaA53D", "latest"],"id":1}' -H "Content-Type: application/json" http://127.0.0.1:8899                
{"jsonrpc":"2.0","result":"0x12a05f200","id":1}
```
`0x12a05f200` is a hex representation of 5*10^9

For more information about rpc checkout [evm-rpc](evm/rpc.md) page.


