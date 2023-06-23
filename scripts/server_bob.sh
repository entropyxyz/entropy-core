ROOT=$(git rev-parse --show-toplevel)
cargo run -p server -- --bob --threshold-url="127.0.0.1:3002"
