# This script uses psvm to update substrate repos
# It uses psvm repo https://github.com/paritytech/psvm
#!/bin/bash
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
psvm -v $version -p ./crates/shared

# Amazing but not perfect will miss some packages, below are a list of missed packages
# /node/cli - jsonrpsee