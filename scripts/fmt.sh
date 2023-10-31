#!/bin/bash
cargo fmt
taplo fmt
cargo clippy -- -D warnings
