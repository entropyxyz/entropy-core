# NOTE: Use only for testing.
# Launches bobs node.
# First parameter is bobs public ipv4 address. 
# Second parameter is alices ipv4 address used to 
#   bootstrap alice/bob as the first two nodes of the network. 
# TODO: add parameters for ports, currently they are hard-coded.
BOB_IP=${1:-""}
ALICE_IP=${2:-""}
if [[ "${#BOB_IP}" -lt 1 || "${#ALICE_IP}" -lt 1 ]]; then echo -e "[USAGE]\n\n./bob-node.sh [bob_websocket_ip] [alice_peer_ip]\n" && exit; fi
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
--bootnodes /ip4/$ALICE_IP/tcp/30333/p2p/12D3KooWHBYK2Vu6E3KXRpfkNZ8nr9wZ48GvXEy5cYSt6dCwkYw9 \
--unsafe-rpc-external \
--unsafe-ws-external \
--rpc-methods=unsafe \
--rpc-cors all


