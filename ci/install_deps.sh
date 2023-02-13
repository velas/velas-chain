#!/usr/bin/env bash


case "$CI_OS_NAME" in
    osx)
        brew install coreutils pkg-config llvm make cmake protobuf
        brew install hub
    ;;
    linux)
        apt-get -y install curl git libssl-dev libudev-dev make pkg-config zlib1g-dev llvm clang cmake openssh-client protobuf-compiler
        apt-get -y install hub
    ;;
    windows)
    ;;
    *)
        exit 1
    ;;
esac

curl https://sh.rustup.rs -sSf | sh -s -- -y