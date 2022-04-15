## Quickstart
Provide environment variable with google security token:
```sh
echo "GOOGLE_APPLICATION_CREDENTIALS=\"/path/to/token.json\"\n" > .env
```

Set log level to info:
```
echo "RUST_LOG=\"info\"\n" > .env
``

### Example
Restoring single block #1234
```
cargo run restore-chain -f 1234 -l 1234 --rpc-address http://1.2.3.4:8899
```