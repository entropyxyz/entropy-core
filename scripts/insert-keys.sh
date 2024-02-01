#!/usr/bin/env bash
#
# A helper for inserting keys into a validator's keystore.
#
# This assumes that you're using our Docker images running on infrastructure provisioned by our
# Terraform code. Otherwise the volume mounts won't work.
#
# Expected usage: ./insert-keys.sh "secret seed ... phrase"

set -eux

secretPhrase=$1

keyInsert="./target/debug/entropy key insert \
    --base-path /tmp/entropy_local \
    --chain testnet-local"

declare -A keyTypes=(
  ["babe"]="Sr25519"
  ["imon"]="Sr25519"
  ["audi"]="Sr25519"
  ["gran"]="Ed25519"
)

for name in "${!keyTypes[@]}"; do
  scheme="${keyTypes[$name]}"
  $keyInsert \
    --scheme $scheme \
    --suri "$secretPhrase//$name" \
    --key-type $name
done
