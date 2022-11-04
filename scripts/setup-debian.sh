#!/bin/bash

sudo apt update -y 
sudo apt upgrade -y
sudo apt install -y cmake pkg-config libssl-dev git build-essential clang libclang-dev curl libgmp-dev
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
rustup default stable
rustup update nightly
rustup update stable
rustup target add wasm32-unknown-unknown --toolchain nightly

echo -e "\n\n\nfinished, please run:\n\n\t source ~/.cargo/env\n\nto setup your shell environment.\n"
