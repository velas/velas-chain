<p align="center">
  <a href="https://velas.com">
    <img alt="Velas chain" src="https://i.imgur.com/1AHYxYP.png" width="250" />
  </a>
</p>

# Building

## **1. Install rustc, cargo and rustfmt.**

```bash
$ curl https://sh.rustup.rs -sSf | sh
$ source $HOME/.cargo/env
$ rustup component add rustfmt
```

Please sure you are always using the latest stable rust version by running:

```bash
$ rustup update
```

On Linux systems you may need to install libssl-dev, pkg-config, zlib1g-dev, etc.  On Ubuntu:

```bash
$ sudo apt-get update
$ sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang
```

## **2. Download the source code.**

```bash
$ git clone https://github.com/velas/velas-chain.git
$ cd velas-chain
```

## **3. Build.**

```bash
$ cargo build
```

## **4. Run a minimal local cluster.**
```bash
$ ./run.sh
```

# Testing

**Run the test suite:**

```bash
$ cargo test --no-fail-fast
```

### EVM integration
Info about EVM integration is at our [docs](https://docs.velas.com/evm).

### Starting a local testnet
Start your own devnet locally, instructions are in the [online docs](https://docs.velas.com/cluster/bench-tps).

### Accessing the remote testnet and mainnet
* `testnet` - public devnet accessible via bootstrap.testnet.veladev.net.
* `mainnet` - public devnet accessible via bootstrap.velas.com.

# Benchmarking

First install the nightly build of rustc. `cargo bench` requires use of the
unstable features only available in the nightly build.

```bash
$ rustup install nightly
```

Run the benchmarks:

```bash
$ cargo +nightly bench
```

# Release Process

The release process for this project is described [here](RELEASE.md).

# Disclaimer

All claims, content, designs, algorithms, estimates, roadmaps, specifications, and performance measurements described in this project are done with the author's best effort.  It is up to the reader to check and validate their accuracy and truthfulness.  Furthermore nothing in this project constitutes a solicitation for investment.
