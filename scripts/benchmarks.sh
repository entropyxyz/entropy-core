#!/bin/bash

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
# Manually exclude some pallets.
excluded_pallets=(
  "pallet_babe"
  "pallet_grandpa"
  "pallet_offences"
)

# Load all pallet names in an array.
allPallets=($(
  ./target/release/entropy benchmark pallet --list --chain=dev |\
    tail -n+2 |\
    cut -d',' -f1 |\
    sort |\
    uniq
))

pallets=($({ printf '%s\n' "${allPallets[@]}" "${excluded_pallets[@]}"; } | sort | uniq -u))

echo "[+] Benchmarking ${#pallets[@]} Substrate pallets by excluding ${#excluded_pallets[@]} from ${#ALL_PALLETS[@]}."

for p in ${pallets[@]}
do
    ./target/release/entropy benchmark pallet \
        --chain $entropyChain \
        --wasm-execution=compiled \
        --pallet=$p  \
        --extrinsic='*' \
        --steps=$steps  \
        --repeat=$repeat \
        --header=./file_header.txt \
        --output=$entropyOutput
done
