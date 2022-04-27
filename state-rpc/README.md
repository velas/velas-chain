# State RPC

## Generate state DB

``` bash
cargo run --bin generate-state
```

## Request block by Hash

``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto 127.0.0.1:8000 rpcserver.Backend/ping
```

``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto -d '{"hash": "0xadf0a07188819e46c6e1b903dcb7ffd9b1eb4f7a3fea22b096b8df867b63c664"}' 127.0.0.1:8000 rpcserver.Backend/getBlock
```
