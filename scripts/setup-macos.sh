#!/bin/bash

brew update
brew install openssl cmake protoc-gen-go cproto protoc-gen-go-grpc git curl wget 

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
cat ~/.cargo/env >> ~/.bashrc
. $HOME/.cargo/env
rustup default stable
rustup target add x86_64-unknown-linux-gnu --toolchain stable
rustup target add x86_64-apple-darwin --toolchain stable
rustup target add aarch64-apple-darwin --toolchain stable
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup update stable
rustup update nightly
