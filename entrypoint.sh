#!/bin/bash
set -ex

MIN_VALIDATOR_STAKE=10001 # 10k min stake + rent exempt
MIN_RENT_FEE=100 # Some value that should be enough for fee
DATADIR=/data/solana
NODE_TYPE=$1  #validator/bootstrap
NETWORK="devnet" #devnet/testnet/mainnet
mkdir -p $DATADIR
get_my_ip() {
  curl ifconfig.me
}

stake_account_exist() {
  solana --keypair $datadir/identity.json --url $rpc_url stake-account $datadir/stake-account.json
}

vote_account_exist() {
  solana --keypair $datadir/identity.json --url $rpc_url vote-account $datadir/vote-account.json
}

run_solana_validator() {
  declare datadir=$1
  declare entrypoint=$2
  declare port_range=$3
  declare network=$4

  set +e # FALL BACK to entrypoint RPC, DONT FAIL.
  rpc_url=`solana-gossip rpc-url --timeout 180 --entrypoint $entrypoint` # get rpc url
  if [ $? -ne 0 ]; then
    rpc_url=http://$(echo $entrypoint | cut -d ':' -f 1):8899
  fi
  set -e

  if ! vote_account_exist; then
    solana-keygen new --no-passphrase -so $datadir/identity.json #try to generate identity
    solana-keygen new --no-passphrase -so $datadir/vote-account.json #try to generate vote account
    solana --keypair /config/faucet.json --url $rpc_url transfer $datadir/identity.json $(($MIN_VALIDATOR_STAKE + $MIN_RENT_FEE))
    solana --keypair $datadir/identity.json --url $rpc_url create-vote-account $datadir/vote-account.json $datadir/identity.json
  fi

  case "$NETWORK" in
    # airdrop on testnet devnet
    "testnet"|"devnet")
          if ! stake_account_exist; then
            # TODO: Airdrop tokens if not enough
            vote_account=$(solana address --keypair $datadir/vote-account.json)
            solana-keygen new --no-passphrase -so $datadir/stake-account.json
            solana --keypair $datadir/identity.json --url $rpc_url create-stake-account $datadir/stake-account.json $MIN_VALIDATOR_STAKE
            stake_account=$(solana address --keypair $datadir/stake-account.json)
            solana --keypair $datadir/identity.json --url $rpc_url delegate-stake --force $stake_account $vote_account
          fi
          ;;
  esac


  RUST_LOG=debug solana-validator \
    --max-genesis-archive-unpacked-size 1073741824 \
    --entrypoint $entrypoint  \
    --identity $datadir/identity.json \
    --vote-account $datadir/vote-account.json \
    --ledger $datadir \
    --log - \
    --enable-rpc-exit \
    --enable-rpc-set-log-filter \
    --dynamic-port-range $port_range \
    --snapshot-interval-slots 200
}

run_solana_bootstrap() {
  declare datadir=$1
  declare host=$2
  declare port_range=$3
  declare rpc_port=$4
  RUST_LOG=debug solana-validator \
    --enable-rpc-exit \
    --enable-rpc-set-log-filter \
    --enable-rpc-transaction-history \
    --gossip-host $host \
    --ledger $datadir \
    --dynamic-port-range $port_range \
    --rpc-port $rpc_port \
    --identity $datadir/identity.json \
    --vote-account $datadir/vote-account.json \
    --log - \
    --snapshot-interval-slots 200
}

run_evm_bridge() {
  declare keyfile=$1
  declare entrypoint=$2
  declare listen_addr=$3
  # RUN evm bridge with specific logs configuration
  RUST_LOG="debug,hyper=info,tokio_reactor=info,reqwest=info" evm-bridge $keyfile $entrypoint $listen_addr
}


fetch_program() {
  declare name=$1
  declare version=$2
  declare address=$3
  declare loader=$4

  declare so=spl_$name-$version.so

  genesis_args+=(--bpf-program "$address" "$loader" "$so")

  if [[ -r $so ]]; then
    return
  fi

  if [[ -r ~/.cache/solana-spl/$so ]]; then
    cp ~/.cache/solana-spl/"$so" "$so"
  else
    echo "Downloading $name $version"
    so_name="spl_${name//-/_}.so"
    (
      set -x
      curl -L --retry 5 --retry-delay 2 --retry-connrefused \
        -o "$so" \
        "https://github.com/solana-labs/solana-program-library/releases/download/$name-v$version/$so_name"
    )

    mkdir -p ~/.cache/solana-spl
    cp "$so" ~/.cache/solana-spl/"$so"
  fi

}
generate_first_node() {
  solana-keygen new --no-passphrase -fso $DATADIR/faucet.json
  solana-keygen new --no-passphrase -so $DATADIR/identity.json
  solana-keygen new --no-passphrase -so $DATADIR/vote-account.json
  solana-keygen new --no-passphrase -so $DATADIR/stake-account.json

  fetch_program token 2.0.6 TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA BPFLoader2111111111111111111111111111111111
  fetch_program memo  1.0.0 Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo BPFLoader1111111111111111111111111111111111
  fetch_program associated-token-account 1.0.1 ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL BPFLoader2111111111111111111111111111111111
  fetch_program feature-proposal 1.0.0 Feat1YXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNgAse BPFLoader2111111111111111111111111111111111

  solana-genesis --max-genesis-archive-unpacked-size 1073741824 --enable-warmup-epochs --bootstrap-validator $DATADIR/identity.json $DATADIR/vote-account.json $DATADIR/stake-account.json --bpf-program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA BPFLoader2111111111111111111111111111111111 spl_token-2.0.6.so --bpf-program Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo BPFLoader1111111111111111111111111111111111 spl_memo-1.0.0.so --bpf-program ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL BPFLoader2111111111111111111111111111111111 spl_associated-token-account-1.0.1.so --bpf-program Feat1YXHhH6t1juaWF74WLcfv4XoNocjXA6sPWHNgAse BPFLoader2111111111111111111111111111111111 spl_feature-proposal-1.0.0.so --ledger $DATADIR --faucet-pubkey $DATADIR/faucet.json --faucet-lamports 500000000000000000 --hashes-per-tick auto --cluster-type development
}

case "${NODE_TYPE}" in
  "bootstrap") 
    if  [ ! -f $DATADIR/identity.json ] ; then
      generate_first_node
    fi
    PORT_RANGE=$2
    RPC_PORT=$3
    IP=`get_my_ip`
    run_solana_bootstrap $DATADIR $IP $PORT_RANGE $RPC_PORT
    ;;
  "validator")    
    ENTRYPOINT=$2
    PORT_RANGE=$3
    mkdir -p $DATADIR/v
    cp /config/genesis.bin $DATADIR/v/genesis.bin
    DATADIR=$DATADIR/v
    run_solana_validator $DATADIR $ENTRYPOINT $PORT_RANGE
    ;;
  "bridge")
    ENTRYPOINT=$2
    run_evm_bridge /config/faucet.json $ENTRYPOINT 0.0.0.0:8545
    ;;
  *)
    echo "Unknown nodetype ${NODE_TYPE} Use one of bootstrap|validator|bridge sub command"
    ;;
esac
