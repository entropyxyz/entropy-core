# Protocol Implementation
See [HackMD spec](https://hackmd.io/kLiqrFYETOiONBYXIdqdMA?view) for details.
## Keygen   
```sh
# Terminal 1, from project root
cargo build --release -p protocol
cd target/release
# starts an HTTP server on http://127.0.0.1:8000. This server relays all communication between nodes.
./cli sm-manager
# Terminal 2, from target/release; Alice generates keys
export M=6 # M of N
export N=6
./cli keygen -t $M -n $N 
```

## Sign, assume 6 of 6
```sh
# Terminal 1..6, from target/release
let TX="immaculate"
./cli -p 1,2,3,4,5,6 -d $TX -l local-share0.json
./cli -p 1,2,3,4,5,6 -d $TX -l local-share1.json
./cli -p 1,2,3,4,5,6 -d $TX -l local-share2.json
./cli -p 1,2,3,4,5,6 -d $TX -l local-share3.json
./cli -p 1,2,3,4,5,6 -d $TX -l local-share4.json
./cli -p 1,2,3,4,5,6 -d $TX -l local-share5.json
```
