#!/bin/sh
# This script checks that entropy-shared will compile with all the different combinations of feature
# flags / targets which will be used. This is useful to check that changes to entropy-shared have
# not broken anything without needing to run the entire CI pipeline.
#
# Used by entropy-tss
cargo check -p entropy-shared
# Used by entropy-tss in production
cargo check -p entropy-shared -F production
# Used by entropy-protocol
cargo check -p entropy-shared -F std -F user-native --no-default-features
# Used by entropy-protocol built for wasm
cargo check -p entropy-shared -F user-wasm -F wasm --no-default-features --target wasm32-unknown-unknown
# Used by pallets
cargo check -p entropy-shared -F wasm-no-std --no-default-features --target wasm32-unknown-unknown
# Used by pallets in production
cargo check -p entropy-shared -F wasm-no-std -F production --no-default-features --target wasm32-unknown-unknown
