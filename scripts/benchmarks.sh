#!/bin/bash

steps=50
repeat=20
entropyOutput=./runtime/src/weights/
entropyChain=dev
pallets=(
  pallet_free_tx
  pallet_programs
  pallet_relayer
  pallet_staking_extension
  pallet_transaction_pause
  pallet_balances
  pallet_bags_list
  pallet_balances
  pallet_bounties
  pallet_collective
  pallet_democracy
  pallet_election_provider_multi_phase
  pallet_elections_phragmen
  pallet_im_online
  pallet_indices
  pallet_membership
  pallet_nomination_pools
  pallet_multisig
  pallet_preimage
  pallet_proxy
  pallet_scheduler
  pallet_session
  pallet_staking
  frame_system
  pallet_timestamp
  pallet_tips
  pallet_transaction_storage
  pallet_treasury
  pallet_utility
  pallet_vesting
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
