# This script is meant to be run once before launching the devnet to build the inital chain spec
CHAINSPEC=${1:-"devnet"}
ENTROPY_TESTNET_TSS_IP=0.0.0.0:3001 ./target/release/entropy build-spec --disable-default-bootnode --raw --chain=$CHAINSPEC > chains/${CHAINSPEC}.json
