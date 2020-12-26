---
title: Bridge to EVM
---

All Ethereum transaction is wrapped into native format. In order to execute native transaction,
someone should pay a fee in native coin.
EVM bridge is managing this routine. Its a regular web-server that wrap EVM transaction into native, and take gas price as fee.

To run your evm-bridge locally, just provide a path to keyfile and address to solana-rpc.
```
evm-bridge ./keyfile.json http://127.0.0.1:8899
```

For devnet we provide a public evm-bridge, which is located at http://bridge.next.velas.com

## Gas price, and gas limit collecting:

Every evm-bridge is responsible to set it's own commision, every evm-bridge users is paying this commission by increasing gas price in transaction.
This mechanism provide incentivise to host your own evm bridge, and increase decentralisation. 