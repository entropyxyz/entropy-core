const client = require('entropy-client')

// This is needed on Nodejs as we use bindings to the browser websocket API which is a property
// of the global object
Object.assign(global, { WebSocket: require('ws') })

// console.log(client)
async function getApi () {
  const api = await new client.EntropyApi('ws://testnet.entropy.xyz:9944')
  console.log(api)
  // create a keypair from mnemonic
  // create a program instance from a known program hash
  // register
  // sign with registered account
}

getApi().then(() => {
  console.log('done')
})
