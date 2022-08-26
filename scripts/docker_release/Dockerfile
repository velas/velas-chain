FROM ubuntu:20.04
ARG release_version=LATEST_VELAS_RELEASE
RUN apt-get -y update && apt-get -y install libssl-dev libudev-dev curl
RUN curl -sSf https://raw.githubusercontent.com/velas/velas-chain/develop/install/velas-install-init.sh | sh -s - LATEST_VELAS_RELEASE
ENV PATH="/root/.local/share/velas/install/active_release/bin":"$PATH"
COPY entrypoint.sh entrypoint.sh
ENTRYPOINT [ "/usr/bin/sh","-c", "./entrypoint.sh" ]
