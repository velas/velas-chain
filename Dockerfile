FROM ubuntu:20.04 as builder

ENV TZ=Europe/Stockholm
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get -y update && apt-get install && \ 
    apt-get -y install curl git libssl-dev libudev-dev make pkg-config zlib1g-dev llvm clang

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup component add rustfmt && rustup update

#Use own solana, clone for repo or add to existent repo
COPY ./ /solana
#COPY ./solana /solana
#RUN git clone https://github.com/solana-labs/solana
WORKDIR /solana
RUN cargo build --release
RUN rm /solana/target/release/deps -rf
RUN rm /solana/target/release/build -rf

FROM ubuntu:20.04 as dest
RUN apt-get update && \
    apt-get -y install libssl-dev libudev-dev curl
COPY --from=builder /solana/target/release/ /usr/local/solana
COPY ./entrypoint.sh /entrypoint.sh
ENV PATH="/usr/local/solana:$PATH"

#CMD /bin/bash
