#!/bin/bash
rustup run nightly cargo fmt
taplo fmt
rustup run nightly cargo clippy -- -D warnings