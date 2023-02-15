#!/bin/bash
if [[ $EUID -ne 0 ]]; then echo "This script must be run as root" && exit 1; fi
readonly ARCH=${1:-""}
readonly tag="$(git tag|head -n 1)-$(git rev-parse --short HEAD)"
readonly fn="$ARCH-$tag"

# apt
apt update -y
apt upgrade -y
apt install -y cmake pkg-config libssl-dev build-essential clang libclang-dev libgmp-dev unzip curl git zstd libzstd-dev libzstd1 libarchive-dev libarchive13

# protocol buffers
PROTOC_VERSION=$(curl -s "https://api.github.com/repos/protocolbuffers/protobuf/releases/latest"  | grep 'tag_name' | sed 's/.*: //g' | tr -d ',"v')
curl -Lo protoc.zip "https://github.com/protocolbuffers/protobuf/releases/latest/download/protoc-${PROTOC_VERSION}-linux-x86_64.zip"
unzip -o -q protoc.zip bin/protoc -d /usr/local
chmod a+x /usr/local/bin/protoc

# cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env
#cat ~/.cargo/env >> ~/.bashrc
#. $HOME/.cargo/env
rustup set profile complete
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup default stable
#rustup target add x86_64-unknown-linux-gnu --toolchain stable
#rustup target add x86_64-apple-darwin --toolchain stable
#rustup target add aarch64-apple-darwin --toolchain stable
rustup update stable
rustup update nightly

#. $HOME/.cargo/env
