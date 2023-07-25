#!/usr/bin/env bash


case "$CI_OS_NAME" in
    osx)
        brew install coreutils pkg-config llvm make cmake protobuf
        brew install hub
    ;;
    linux)
        apt-get -y install curl git libssl-dev libudev-dev make pkg-config zlib1g-dev llvm clang cmake openssh-client protobuf-compiler
        wget https://github.com/mislav/hub/releases/download/v2.14.2/hub-linux-amd64-2.14.2.tgz -O hub.tgz
        tar -xvf hub.tgz 
        sudo mv hub-linux-amd64-2.14.2/bin/hub /usr/local/bin/hub
        rm -rf hub.tgz hub-linux-amd64-2.14.2
    ;;
    windows)
    ;;
    *)
        exit 1
    ;;
esac

curl https://sh.rustup.rs -sSf | sh -s -- -y
