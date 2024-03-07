#!/bin/bash

steps=5
repeat=2
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
  pallet_registry
)
licenseHeader=.maintain/AGPL-3.0-header.txt

for p in ${pallets[@]}
do
	./target/release/entropy benchmark pallet \
		--chain $entropyChain \
		--pallet=$p  \
		--extrinsic='*' \
		--steps=$steps  \
		--repeat=$repeat \
        --header=$licenseHeader \
		--output=$entropyOutput

done
