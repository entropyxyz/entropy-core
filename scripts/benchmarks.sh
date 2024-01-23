#!/bin/bash

set -eux

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
entropyTemplate=.maintain/frame-weight-template.hbs
licenseHeader=.maintain/AGPL-3.0-header.txt
# Manually exclude some pallets.
excluded_pallets=(
  "pallet_babe"
  "pallet_grandpa"
  "pallet_offences"
)

# Load all pallet names in an array.
all_pallets=($(
  cargo run -p entropy --release --features runtime-benchmarks -- benchmark pallet --list --chain=dev |\
    tail -n+2 |\
    cut -d',' -f1 |\
    sort |\
    uniq
))

pallets=($({ printf '%s\n' "${all_pallets[@]}" "${excluded_pallets[@]}"; } | sort | uniq -u))

echo "[+] Benchmarking ${#pallets[@]} pallets by excluding ${#excluded_pallets[@]} from ${#all_pallets[@]}."

for p in ${pallets[@]}
do
    cargo run -p entropy --release --features runtime-benchmarks -- benchmark pallet \
        --chain $entropyChain \
        --wasm-execution=compiled \
        --pallet=$p  \
        --extrinsic='*' \
        --steps=$steps  \
        --repeat=$repeat \
        --header=$licenseHeader \
        --template $entropyTemplate \
        --output=$entropyOutput
done
