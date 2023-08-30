# NOTE: Use only for testing.
# Launches alices node on the public ipv4 address passed in as the first
# command line parameter
# TODO: add parameters for ports, currently they are hard coded.

./target/release/entropy purge-chain --base-path /tmp/alice --chain local -y

./target/release/entropy \
--base-path /tmp/alice \
--chain local \
--alice \
--port 30333 \
--rpc-port 9944 \
--telemetry-url "wss://telemetry.polkadot.io/submit/ 0" \
--validator \
--rpc-methods=unsafe \
--unsafe-rpc-external \
--rpc-cors all
