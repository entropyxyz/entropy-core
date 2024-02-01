#!/usr/bin/env bash
#
# A script used to generate all the keys needed for validators.
#
# **This should not be used anywhere sensitive, it prints out your new seed phrase!**

set -eu

secretPhrase=$(cargo run -p entropy -- key generate --output-type json | jq -r .secretPhrase)

# Not safe, I know...but this is a development tool.
echo -e "Secret Phrase: $secretPhrase\n"

declare -A keyTypes=(
  ["controller"]="Sr25519"
  ["stash"]="Sr25519"
  ["babe"]="Sr25519"
  ["imon"]="Sr25519"
  ["audi"]="Sr25519"
  ["gran"]="Ed25519"
)

for name in "${!keyTypes[@]}"; do
  scheme="${keyTypes[$name]}"
  ./target/debug/entropy key inspect "$secretPhrase//$name" --scheme $scheme
  echo
done
