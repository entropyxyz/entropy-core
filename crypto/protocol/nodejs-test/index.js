const protocol = require('entropy-protocol')
Object.assign(global, { WebSocket: require('ws') });

const validatorInfo = new protocol.ValidatorInfo(
    new Uint8Array(32), // x25519PrivateKey
    '127.0.0.1:3000',
    new Uint8Array(32), // TSS Account
)

const userSigningKeypairSeed = new Uint8Array(32)
const x25519PrivateKey = new Uint8Array(32)

protocol.run_dkg_protocol([validatorInfo], userSigningKeypairSeed, x25519PrivateKey).then((output) => {
  console.log('OUTPUT:', output)
}).catch((err) => {
  console.log('ERR', err)
})
