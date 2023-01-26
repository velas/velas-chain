#!/bin/bash

evm_contract=0x507AAe92E8a024feDCbB521d11EC406eEfB4488F;

if [[ $# -lt 3 ]] ; then
    echo 'Usage: ./quickstart.sh path/to/signer_keypair.json <output directory> <velas-chain root>'
    exit 0
fi

signer_keypair=$1;
out_dir=$2;
project_root=$3;

gas_station_keypair=$out_dir/gas_station_keypair.json;
payer_info_storage_keypair=$out_dir/payer_storage_keypair.json;

mkdir -p "$out_dir"
velas-keygen new -o "$payer_info_storage_keypair"
velas-keygen new -o "$gas_station_keypair"

owner_key=$(velas -u t -k "$signer_keypair" address)
storage_key=$(velas -u t -k "$payer_info_storage_keypair" address)
gas_station_key=$(velas -u t -k "$gas_station_keypair" address)
echo "Keys used: signer/owner: $owner_key, storage: $storage_key, gas_station: $gas_station_key"

echo Building..
"$project_root"/cargo-build-bpf -- -p evm-gas-station
echo Deploying..
velas program deploy -u t -k "$signer_keypair" --program-id "$gas_station_keypair" "$project_root"/target/deploy/evm_gas_station.so

echo "Registering payer.."
gas_station_filter=$out_dir/gas_station_filter.json
echo "[{ \"InputStartsWith\": [ \"$evm_contract\", [96, 87, 54, 29] ] }]" > "$gas_station_filter"
velas evm create-gas-station-payer -u t -k "$signer_keypair" \
  "$payer_info_storage_keypair" "$gas_station_key" 100000 "$gas_station_filter"

echo "Starting bridge.."
RUST_LOG=info evm-bridge "$signer_keypair" https://api.testnet.velas.com 127.0.0.1:8545 111 \
  --gas-station "$gas_station_key" --redirect-to-proxy "$evm_contract:$owner_key:$storage_key"
