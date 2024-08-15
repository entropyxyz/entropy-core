#!/bin/sh

# Creates a set of keyshares for use in entropy-tss tests

cargo run -p entropy-create-test-keyshares -- ./crates/testing-utils/keyshares
