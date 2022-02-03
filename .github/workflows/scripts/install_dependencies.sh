#!/usr/bin/env bash

set -e

sudo apt install -y libssl-dev clang libclang-dev
rustup default nightly-x86_64-unknown-linux-gnu
rustup update
rustup update nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup component add clippy
