export ROCKET_PORT=3002
ROOT=$(git rev-parse --show-toplevel)
$ROOT/target/release/server
