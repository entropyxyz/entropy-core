#!/usr/bin/env bash
set -eux

secretPhrase=$(cargo run -p entropy -- key generate --output-type json | jq -r .secretPhrase)

./target/debug/entropy key inspect "$secretPhrase//controller" --output-type json
./target/debug/entropy key inspect "$secretPhrase//stash" --output-type json
./target/debug/entropy key inspect "$secretPhrase//babe" --output-type json
./target/debug/entropy key inspect "$secretPhrase//imon" --output-type json
./target/debug/entropy key inspect "$secretPhrase//audi" --output-type json

./target/debug/entropy key inspect "$secretPhrase//gran" --scheme ed25519 --output-type json
