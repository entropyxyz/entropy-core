#!/usr/bin/env bash
set -eux

basePath=$1
secretPhrase=$2

./target/debug/entropy key insert --base-path $basePath \
  --chain entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//babe" \
  --key-type babe

./target/debug/entropy key insert --base-path $basePath \
  --chain entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//imon" \
  --key-type imon

./target/debug/entropy key insert --base-path $basePath \
  --chain entropy-testnet.json \
  --scheme Sr25519 \
  --suri "$secretPhrase//audi" \
  --key-type audi

./target/debug/entropy key insert --base-path $basePath \
  --chain entropy-testnet.json \
  --scheme Ed25519 \
  --suri "$secretPhrase//gran" \
  --key-type gran
