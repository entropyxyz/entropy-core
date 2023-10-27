const protocol = require('entropy-protocol')
Object.assign(global, { WebSocket: require('ws') });

function parseVadidatorInfo(inputObject) {
    return new protocol.ValidatorInfo(
        new Uint8Array(inputObject.x25519PrivateKey),
        inputObject.ipAddress,
        new Uint8Array(inputObject.tssAccount),       )
)
}

let parsed
try {
    const input = JSON.parse(process.argv[3])
    Object.assign(input, {
        userSigningKeypairSeed: new Uint8Array(input.userSigningKeypairSeed),
        x25519PrivateKey: new Uint8Array(input.x25519PrivateKey),
        validatorsInfo: input.validatorsInfo.map(parseVadidatorInfo)
    })
} catch (err) {
    console.log(`Usage: ${process.argv[0]} JSON`)
    console.log(err)
}
console.log(parsed)

switch(process.argv[2].toLowerCase()) {
    case 'register':
// protocol.run_dkg_protocol([validatorInfo], userSigningKeypairSeed, x25519PrivateKey).then((output) => {
//   console.log('OUTPUT:', output)
// }).catch((err) => {
//   console.log('ERR', err)
// })
        break
    case 'sign':
// protocol.run_signing_protocol(keyshare, sig_uid, sig_hash, [validatorInfo], userSigningKeypairSeed, x25519PrivateKey).then((output) => {
//   console.log('OUTPUT:', output)
// }).catch((err) => {
//   console.log('ERR', err)
// })
        break
    default:
        throw new Error('First argument must be register or sign')
}
// const validatorInfo = new protocol.ValidatorInfo(
//     new Uint8Array(32), // x25519PrivateKey
//     '127.0.0.1:3000',
//     new Uint8Array(32), // TSS Account
// )
// console.log(JSON.stringify(validatorInfo))

