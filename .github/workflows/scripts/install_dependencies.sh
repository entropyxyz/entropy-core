#!/usr/bin/env bash

set -e

sudo apt install -y libssl-dev clang libclang-dev
rustup default stable
rustup update nightly
rustup update stable
rustup target add wasm32-unknown-unknown --toolchain nightly
