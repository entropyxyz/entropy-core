# This script is meant to be run once before launching the devnet to build the inital chain spec
./target/release/entropy build-spec --disable-default-bootnode --raw --chain=devnet > chains/devnet.json
