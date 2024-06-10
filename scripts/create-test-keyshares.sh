#!/bin/sh

# Creates a set of keyshares for use in entropy-tss tests

cargo run -p entropy-testing-utils -- ./crates/testing-utils/keyshares
