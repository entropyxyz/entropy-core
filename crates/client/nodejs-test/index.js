const client = require('entropy-client')
const minimist = require('minimist')
const fs = require('node:fs');

// This is needed on Nodejs as we use bindings to the browser websocket API which is a property
// of the global object
Object.assign(global, { WebSocket: require('ws') })

async function main () {
  const args = minimist(process.argv.slice(2))

  const endpointUrl = args.endpoint ? args.endpoint : 'ws://testnet.entropy.xyz:9944'
  console.log(`Chain endpoint ${endpointUrl}`)

  const api = await new client.EntropyApi(endpointUrl)
  const userKeypair = new client.Sr25519Pair(args.keypair ? args.keypair : '//Alice')

  switch (args._[0]) {
      case 'store':
          // Store a program
          const programBinary = new Uint8Array(fs.readFileSync(args._[1]))
          const configurationInterface = new Uint8Array()
          const auxDataInterface = new Uint8Array()
          const oraclePointer = new Uint8Array()
          const programHash = await client.storeProgram(api, userKeypair, programBinary, configurationInterface, auxDataInterface, oraclePointer)
          console.log(`Stored program with hash ${programHash}`)
          break
      case 'register':
          // Register an account

          // Use the device key proxy program for now
          const program = new client.ProgramInstance(new Uint8Array(32), new Uint8Array())
          const programAccount = userKeypair.public()

          let verifyingKey = await client.register(api, userKeypair, programAccount, program)
          console.log(`Registered succesfully. Verifying key: ${verifyingKey}`)
          break
      case 'sign':
          // Sign a message
          const signature = await client.sign(
              api,
              userKeypair,
              client.VerifyingKey.fromHexString(args._[1]),
              new Uint8Array(Buffer.from('my message to sign')),
              undefined, // Aux data goes here
          )
          console.log(`Signed message ${signature}`)
          break
      case 'accounts':
          // Display information about all registered accounts
          const accounts = await client.get_accounts(api)
          console.log(accounts)
          break
  }
}

main().then(() => {
  console.log('Done')
})
