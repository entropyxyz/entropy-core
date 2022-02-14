#!/usr/bin/env bash


./target/release/entropy purge-chain --base-path /tmp/alice --chain local -y

./target/release/entropy \
--base-path /tmp/alice \
--chain local \
--alice \
--port 30333 \
--ws-port 9944 \
--rpc-port 9933 \
--node-key 0000000000000000000000000000000000000000000000000000000000000001 \
--validator
