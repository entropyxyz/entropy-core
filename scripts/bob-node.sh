# NOTE: Use only for testing.
# Launches bobs node.
# First parameter is bobs public ipv4 address.
# Second parameter is alices ipv4 address used to
#   bootstrap alice/bob as the first two nodes of the network.
# TODO: add parameters for ports, currently they are hard-coded.


./target/release/entropy purge-chain --base-path /tmp/bob --chain local -y

./target/release/entropy \
--base-path /tmp/bob \
--chain local \
--bob \
--port 30334 \
--rpc-port 9945 \
--telemetry-url "wss://telemetry.polkadot.io/submit/ 0" \
--validator \
--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWErpGfMFcRjMtGUFrn5TqxE2WpBJFLWDAqkgMQCcKuHY9 \
--unsafe-rpc-external \
--rpc-methods=unsafe \
--rpc-cors all


