// This takes parameters for the sign or dkg protocols as a JSON serialized string given as a
// command line argument
//
// It is called from a rust test in `server` by spawning a process running Nodejs with this script
const protocol = require('entropy-protocol')
Object.assign(global, { WebSocket: require('ws') });

// Create ValidatorInfo objects from objects parsed from JSON
function parseVadidatorInfo(inputObject) {
    console.log('input: ', inputObject)
    return new protocol.ValidatorInfo(
        new Uint8Array(inputObject.x25519_public_key),
        inputObject.ip_address,
        new Uint8Array(inputObject.tss_account),
    )
}

let input
try {
    input = JSON.parse(process.argv[3])
    Object.assign(input, {
        user_sig_req_seed: new Uint8Array(input.user_sig_req_seed),
        x25519_private_key: new Uint8Array(input.x25519_private_key),
        validators_info: input.validators_info.map(parseVadidatorInfo)
    })
} catch (err) {
    console.log(`Usage: ${process.argv[0]} <command> <JSON payload>`)
    console.log(err)
}

switch(process.argv[2].toLowerCase()) {
    case 'register':
        // It is not yet possible to test registering
        // protocol.run_dkg_protocol([validatorInfo], userSigningKeypairSeed, x25519PrivateKey).then((output) => {
        //   console.log('OUTPUT:', output)
        // }).catch((err) => {
        //   console.log('ERR', err)
        // })
        break
    case 'sign':
        console.log('Starting signing protocol with these arguments', input)
        protocol.run_signing_protocol(input.key_share, input.sig_uid, input.validators_info, input.user_sig_req_seed, input.x25519_private_key).then((output) => {
            console.log('OUTPUT:', output)
        }).catch((err) => {
            console.error('ERR', err)
        })
        break
    default:
        throw new Error('First argument must be register or sign')
}
