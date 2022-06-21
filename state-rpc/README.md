# State RPC

## Generate state DB

To simplify a testing and have a local randomly generated DB you can use `generate-state` script.

Database would be stored in a `.tmp` directory, state_root would be stored in a  `state_root.txt` file (for an optional usage).

``` bash
cargo run --bin generate-state
```

## Run rpc server

``` bash
RUST_LOG="info" cargo run
```

## Request block by Hash

After running a server you can interactively request different APIs with `grpcurl` tool.

Move to `state-rpc` directory:

``` bash
velas-chain 1 % cd state-rpc
```

### Ping route
``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto 127.0.0.1:8000 rpcserver.Backend/ping
```

### Ask for a db record by sending hash string
``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto -d '{"hash": "0xadf0a07188819e46c6e1b903dcb7ffd9b1eb4f7a3fea22b096b8df867b63c664"}' 127.0.0.1:8000 rpcserver.Backend/getBlock
```

### Ask for a diff between two state roots
Request:

``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto -d '{"first_root": "0xadf0a07188819e46c6e1b903dcb7ffd9b1eb4f7a3fea22b096b8df867b63c664", "second_root": "0xadf0a07188819e46c6e1b903dcb7ffd9b1eb4f7a3fea22b096b8df867b63c456"}' 127.0.0.1:8000 rpcserver.Backend/getStateDiff
```

Sample response:

``` json
{
  "changes": [
    {
      "insert": {
        "hash": "0xadf0…c664",
        "data": "AQIDBAU="
      }
    }
  ]
}
```
