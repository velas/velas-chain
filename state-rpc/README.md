# State RPC

## Generate state DB

``` bash
cargo run --bin generate-state
```

## Request block by Hash

``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto 127.0.0.1:8000 rpcserver.Backend/ping
```

Ask for a db record by sending hash string
``` bash
grpcurl -plaintext -import-path ./proto -proto rpc.proto -d '{"hash": "0xadf0a07188819e46c6e1b903dcb7ffd9b1eb4f7a3fea22b096b8df867b63c664"}' 127.0.0.1:8000 rpcserver.Backend/getBlock
```

sentry issue (was resolved quickly)
review demand-backend (pr)
not yet announced full provider360 infra deprication, because I need approve from Vadi
checked what happened in the last couple of days, marcos thank you for VPN
