
#!/bin/bash
set -ex

if ls /data/ledger/snapshot*.tar.zst 1> /dev/null 2>&1; then
    echo "Snapshot found skip downloading"
    velas-validator --log - --snapshot-interval-slots 300 --max-genesis-archive-unpacked-size 707374182 --ledger /data/ledger --dynamic-port-range 8001-8011 --entrypoint bootstrap.velas.com:8001 --no-voting --enable-rpc-transaction-history --rpc-port 8899 --expected-shred-version 17211 --no-port-check --evm-state-archive /data/archive --no-snapshot-fetch
else
    echo "Download snapshot before running validator"
    velas-validator --log - --snapshot-interval-slots 300 --max-genesis-archive-unpacked-size 707374182 --ledger /data/ledger --dynamic-port-range 8001-8011 --entrypoint bootstrap.velas.com:8001 --no-voting --enable-rpc-transaction-history --rpc-port 8899 --expected-shred-version 17211 --no-port-check --evm-state-archive /data/archive
fi


