#!/bin/bash
#
# This script uses psvm to update substrate repos
# It uses psvm repo https://github.com/paritytech/psvm

version="1.7.0"

psvm -v $version -p ./runtime
psvm -v $version -p ./node/cli
psvm -v $version -p ./pallets/parameters
psvm -v $version -p ./pallets/programs
psvm -v $version -p ./pallets/propagation
psvm -v $version -p ./pallets/registry
psvm -v $version -p ./pallets/slashing
psvm -v $version -p ./pallets/staking
psvm -v $version -p ./pallets/transaction-pause

# Some packages that are not part of substrate need to be updated manually sometimes 
# Below is a list
# /node/cli - jsonrpsee