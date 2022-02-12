# Protocol Implementation
See [HackMD spec](https://hackmd.io/kLiqrFYETOiONBYXIdqdMA?view) for details.
## Usage
```sh
# Terminal 1, from project root
cargo build --release
cd target/release
# starts an HTTP server on http://127.0.0.1:8000. This server relays all communication between nodes.
./protocol sm-manager
# Terminal 2, from target/release; Alice generates keys
export M=6 # M of N
export N=6
./protocol keygen -t $M -n $N 
```
