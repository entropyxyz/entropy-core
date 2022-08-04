#!/bin/bash

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
	pallet_relayer
  pallet_staking_extension
  pallet_constraints
  pallet_transaction_pause
)

for p in ${pallets[@]}
do
	./target/release/entropy benchmark \
		--chain=$entropyChain \
		--execution=wasm \
		--wasm-execution=compiled \
		--pallet=$p  \
		--extrinsic='*' \
		--steps=$steps  \
		--repeat=$repeat \
		--output=$entropyOutput

done
