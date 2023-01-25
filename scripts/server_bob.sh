export ROCKET_PORT=3002
ROOT=$(git rev-parse --show-toplevel)
cargo run -p server -- --bob
