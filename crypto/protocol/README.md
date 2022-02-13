# Protocol Implementation
See [HackMD spec](https://hackmd.io/kLiqrFYETOiONBYXIdqdMA?view) for details.
## Keygen   
```sh
# Terminal 1, from project root
cargo build --release -p protocol
cd target/release
# starts an HTTP server on http://127.0.0.1:8000. This server relays all communication between nodes.
./protocol sm-manager
# Terminal 2, from target/release; Alice generates keys
rm local-share* # if there are already local-share files in the directory
# TODO BLOCKING: the following generates a pre-validation error
./protocol keygen # defaults to 6 of 7, the last of which is an ignorable extra
```

## Sign, assume 6 of 6
```sh
# Terminal 1..6, from target/release
./protocol sign -p 1,2,3,4,5,6 -i 1
./protocol sign -p 1,2,3,4,5,6 -i 2
./protocol sign -p 1,2,3,4,5,6 -i 3
./protocol sign -p 1,2,3,4,5,6 -i 4
./protocol sign -p 1,2,3,4,5,6 -i 5
./protocol sign -p 1,2,3,4,5,6 -i 6
```
