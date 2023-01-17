## Build

``./cargo-build-bpf -- -p evm-gas-station``

## Deploy

``./target/release/velas program deploy -u t -k ../keypairs/main.testnet.json ./target/deploy/evm_gas_station.so``

## Create payer

Create velas account for payer storage:

``./target/release/velas evm create-gas-station-payer -u t -k ../keypairs/main.testnet.json ../keypairs/testnet_payer_owner.json 8K3MnqwSAuhKezhP1aW63mjiC46NiroUAkVyfiQFvz79 1566000 ../tmp/whitelist_b.json``

Register payer on gas station:

````
