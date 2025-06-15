# Build and run Velas Subchain Bridge using Docker

```bash
docker build -f bridge-subchain.dockerfile -t velas-subchain-bridge .
# TODO: docker cp keypair.json velas-subchain-bridge:/velas-chain/keypair.json
docker run -it \
    -e VELAS_RPC_URL="http://api.devnet.velas.com" \
    -e BRIDGE_BIND_ADDRESS="0.0.0.1:8545" \
    -e SUBCHAIN_ID="57005" \
    velas-subchain-bridge:latest
```
