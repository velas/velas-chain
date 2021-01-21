---
title: Solana Clusters
---

Solana maintains several different clusters with different purposes.

Before you begin make sure you have first
[installed the Solana command line tools](cli/install-solana-cli-tools.md)

Explorers:

- [http://explorer.next.velas.com/](https://explorer.next.velas.com/).

## Devnet

- Devnet serves as a playground for anyone who wants to take Solana for a
  test drive, as a user, token holder, app developer, or validator.
- Application developers should target Devnet.
- Potential validators should first target Devnet.
- Key differences between Devnet and Mainnet Beta:
  - Devnet tokens are **not real**
  - Devnet includes a token faucet for airdrops for application testing
  - Devnet may be subject to ledger resets
  - Devnet typically runs a newer software version than Mainnet Beta
- Gossip entrypoint for Devnet: `bootstrap.next.velas.com:8001`
- RPC URL for Devnet: `https://api.next.velas.com`

##### Example `solana` command-line configuration

```bash
solana config set --url https://api.next.velas.com
```

##### Example `solana-validator` command-line

```bash
$ solana-validator \
    --identity ~/validator-keypair.json \
    --vote-account ~/vote-account-keypair.json \
    --no-untrusted-rpc \
    --ledger ~/validator-ledger \
    --rpc-port 8899 \
    --dynamic-port-range 8000-8010 \
    --entrypoint bootstrap.next.velas.com:8001 \
    --expected-shred-version 37460 \
    --limit-ledger-size
```

The `--trusted-validator`s is operated by Solana
