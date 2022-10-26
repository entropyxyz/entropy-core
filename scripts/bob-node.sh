# NOTE: Use only for testing.
# Launches alices node on the public ipv4 address passed in as the first 
# command line parameter

BOB_IP=${1:-""}
if [ "${#BOB_IP}" -lt 1 ]; then echo -e "[USAGE]\n\n./bob-node.sh [ip]\n" && exit; fi
# TODO: replace the usage of an environment variable with a command line param/config.
export ENDPOINT="ws://$BOB_IP"

../target/release/entropy purge-chain --base-path /tmp/bob --chain local -y 

../target/release/entropy \
--base-path /tmp/bob \
--chain local \
--bob \
--port 30334 \
--ws-port 9946 \
--rpc-port 9934 \
--telemetry-url "wss://telemetry.polkadot.io/submit/ 0" \
--validator \
--bootnodes /ip4/54.90.13.241/tcp/30333/p2p/12D3KooWHBYK2Vu6E3KXRpfkNZ8nr9wZ48GvXEy5cYSt6dCwkYw9 \
--unsafe-rpc-external \
--unsafe-ws-external \
--rpc-methods=unsafe \
--rpc-cors all


