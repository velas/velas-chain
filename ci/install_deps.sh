#!/usr/bin/env bash


case "$CI_OS_NAME" in
    osx)
        brew install coreutils pkg-config llvm make cmake protobuf
        brew install hub
    ;;
    linux)
        sudo apt-get -y install curl git libssl-dev libudev-dev make pkg-config zlib1g-dev llvm clang cmake openssh-client protobuf-compiler
    ;;
    windows)
    ;;
    *)
        exit 1
    ;;
esac

curl https://sh.rustup.rs -sSf | sh -s -- -y
