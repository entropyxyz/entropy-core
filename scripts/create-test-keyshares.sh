#!/bin/sh

# Creates a set of keyshares for use in entropy-tss tests

cargo run -p entropy-testing-utils --release -- ./crates/testing-utils/keyshares
