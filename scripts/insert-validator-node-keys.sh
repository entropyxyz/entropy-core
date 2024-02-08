#!/usr/bin/env bash
#
# A helper for inserting keys into a validator's keystore.
#
# This assumes that you're using our Docker images running on infrastructure provisioned by our
# Terraform code. Otherwise the volume mounts won't work.
#
# The derivation paths here (so the `//name` bit) should match that of the
# `generate-validator-node-keys.sh` script.
#
# Expected usage: ./insert-validator-node-keys.sh "secret seed ... phrase"

set -eu

secretPhrase=$1

keyInsert="docker run -it --init -v /srv/entropy/:/srv/entropy/ \
    entropyxyz/entropy key insert \
    --base-path /srv/entropy \
    --chain /srv/entropy/entropy-testnet.json"

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
