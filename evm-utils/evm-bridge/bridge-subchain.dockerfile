#---------------------------
#  *      BUILD STAGE
#---------------------------

FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    libssl-dev \
    pkg-config \
    libudev-dev \
    pkg-config \
    zlib1g-dev \
    llvm \
    clang \
    make \
    cmake \
    protobuf-compiler

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

ENV PATH="/root/.cargo/bin:${PATH}"

# NOTE: branch is set to zeta
RUN git clone --branch zeta --depth 1 https://github.com/velas/velas-chain.git

WORKDIR /velas-chain

RUN cargo build --release --package evm-bridge

#---------------------------
#  *       EXEC STAGE
#---------------------------

FROM ubuntu:22.04

RUN mkdir /velas-chain

COPY --from=builder /velas-chain/target/release/evm-bridge /velas-chain

WORKDIR /velas-chain

# TODO: cp keypair.json /velas-chain
ENV VELAS_RPC_URL="http://api.devnet.velas.com"
ENV BRIDGE_BIND_ADDRESS="0.0.0.1:8545"
ENV SUBCHAIN_ID="57005"

CMD ["sh", "-c", "./evm-bridge ./keypair.json $VELAS_RPC_URL $BRIDGE_BIND_ADDRESS $SUBCHAIN_ID --subchain --no-simulate --borsh-encoding"]