#!/bin/bash

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
	pallet_relayer
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
