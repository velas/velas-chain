## Build and deploy

Build program:

``./cargo-build-bpf -- -p evm-gas-station``

Resulting .so file will be located at *./target/deploy/*

Deploy program:

``velas program deploy -u <public rpc> -k <signer keypair> path/to/evm_gas_station.so``

## User-Program-Bridge interaction

On testnet you can use deployed gas station program: **99GZJejoz8L521qEgjDbQ4ucheCsw17SL8FWCYXmDCH7**

As a test evm contract you can use this one: **0x507AAe92E8a024feDCbB521d11EC406eEfB4488F**.  
It has one method that accepts uint256. Valid input data will be *0x6057361d* as a method selector following by encoded uint256  
Example input data (passing 1 as an argument): *0x6057361d0000000000000000000000000000000000000000000000000000000000000001*

### Register payer

Given you have successfully deployed gas station program your next step is
to register payer account that will be paying for incoming evm transactions
if they meet its filter conditions:

``velas evm create-gas-station-payer -u <public rpc> -k <signer keypair>
<storage keypair> <program id> <lamports> <filters file> [<owner keypair>]``

Where:

- *signer keypair* - path to keypair of an account that will pay for this transaction
- *storage keypair* - path to keypair of payer storage account that will hold filters data
- *program id* - gas station program id
- *lamports* - amount of tokens (above rent exemption) that will be transferred to gas station pda account to pay for future evm transactions
- *filters file* - path to JSON file with filters to store in payer storage
- *owner keypair* - (**OPTIONAL**) keypair of payer owner account that will have write access to payer storage (for a future use)  
  Default value: *signer keypair*  
  *Only one registered payer per owner supported*

Example *filters file*:
```
[
	{ "InputStartsWith": [ "<evm contract address>", <starting tx bytes: ex: [1, 1, 1, 1]> ] }
]
```

### Start bridge

Run evm-bridge command with next additional options:
``--gas-station <program id> --redirect-to-proxy <evm contract address>:<payer owner pubkey>:<payer storage pubkey>``

Where:
- *program id* - gas station program id
- *evm contract address* - address of evm contract you want to pay for. It should match one of addresses provided in *filters file* during register payer step
- *payer owner pubkey* - pubkey of a payer owner account. It should match the pubkey of *owner keypair* used during register payer step
- *payer storage pubkey* - pubkey of a payer storage account. It should match the pubkey of *storage keypair* used during register payer step

After these steps bridge will be redirecting incoming evm transactions to gas station program.
