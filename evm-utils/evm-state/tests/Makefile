default: build

build:
	solc MetaCoin.sol --bin --output-dir .

abi:
	solc MetaCoin.sol --abi | tail -1 | jq
