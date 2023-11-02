#!/bin/bash

steps=5
repeat=2
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
  pallet_relayer
)

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
