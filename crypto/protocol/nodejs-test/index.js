const protocol = require('entropy-protocol')
Object.assign(global, { WebSocket: require('ws') });

const unused = new Uint8Array(32)
const userSigningKeypairSeed = new Uint8Array(32)
const x25519PrivateKey = new Uint8Array(32)

protocol.run_dkg_protocol(unused, userSigningKeypairSeed, x25519PrivateKey).then((output) => {
  console.log('OUTPUT:', output)
}).catch((err) => {
  console.log('ERR', err)
})
