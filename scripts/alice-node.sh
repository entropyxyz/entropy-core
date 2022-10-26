# NOTE: Use only for testing.
# Launches alices node on the public ipv4 address passed in as the first 
# command line parameter

ALICE_IP=${1:-""}
if [ "${#ALICE_IP}" -lt 1 ]; then echo -e "[USAGE]\n\n./alice-node.sh [ip]\n" && exit; fi
# TODO: replace the usage of an environment variable with a command line param/config.
export ENDPOINT="ws://$ALICE_IP"

../target/release/entropy purge-chain --base-path /tmp/alice --chain local -y 

../target/release/entropy \
--base-path /tmp/alice \
--chain local \
--alice \
--port 30333 \
--ws-port 9946 \
--rpc-port 9934 \
--telemetry-url "wss://telemetry.polkadot.io/submit/ 0" \
--validator \
--rpc-methods=unsafe \
--unsafe-rpc-external \
--unsafe-ws-external \
--rpc-cors all
