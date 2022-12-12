export ROCKET_PORT=3001
ROOT=$(git rev-parse --show-toplevel)
$ROOT/target/release/server --sync
