#!/usr/bin/env bash

set -e

sudo apt install -y libssl-dev clang libclang-dev
rustup default nightly
rustup update nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
rustup component add clippy
