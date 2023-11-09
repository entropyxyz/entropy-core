#!/bin/bash

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
  pallet_relayer
  pallet_staking_extension
  pallet_programs
  pallet_transaction_pause
  pallet_free_tx
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
