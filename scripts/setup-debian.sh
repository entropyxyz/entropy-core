#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "This script must be run as root" && exit 1; fi
apt update  
apt upgrade
apt install -y cmake pkg-config libssl-dev build-essential clang libclang-dev libgmp-dev unzip curl git
export PROTOC_VERSION="$(curl -s "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest" | grep -Po '"tag_name": "v\K[0-9.]+')"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup default stable
rustup update nightly
rustup update stable
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup toolchain add aarch64-apple-darwin    
rustup toolchain add x86_64-apple-darwin     
rustup toolchain add x86_64-unknown-linux-gnu
curl -Lo protoc.zip "https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
unzip -o -q protoc.zip bin/protoc -d /usr/local
chmod a+x /usr/local/bin/protoc