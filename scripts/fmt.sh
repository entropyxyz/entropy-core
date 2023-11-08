#!/bin/bash
cargo fmt --all
taplo fmt
cargo clippy -- -D warnings
