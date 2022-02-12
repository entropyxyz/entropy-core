# Protocol Implementation
See [HackMD spec](https://hackmd.io/kLiqrFYETOiONBYXIdqdMA?view) for details.
## Keygen   
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

## Sign, assume 6 of 6
```sh
# Terminal 1..6, from target/release
let TX="immaculate"
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share0.json
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share1.json
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share2.json
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share3.json
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share4.json
./protocol -p 1,2,3,4,5,6 -d $TX -l local-share5.json
```