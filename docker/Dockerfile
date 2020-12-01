FROM ubuntu:20.04
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -y update && \
    apt-get -y install curl git tzdata && \
    apt-get -y install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang wget

RUN curl -sSfL https://release.solana.com/v1.4.2/install -o /tmp/install_solana.sh && \
    chmod +x /tmp/install_solana.sh && \
    /tmp/install_solana.sh --data-dir /usr/local/solana 1.4.2
COPY ./entrypoint.sh /entrypoint.sh
ENV PATH="/usr/local/solana/active_release/bin:$PATH"
