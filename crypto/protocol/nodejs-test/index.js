import { run_dkg_protocol } from "entropy-protocol"
// import "websocket-polyfill"

const unused = new Uint8Array(32)
const userSigningKeypairSeed = new Uint8Array(32)
const x25519PrivateKey = new Uint8Array(32)

run_dkg_protocol(unused, userSigningKeypairSeed, x25519PrivateKey).then((output) => {
  console.log('OUTPUT:', output)
}).catch((err) => {
  console.log('ERR', err)
})
