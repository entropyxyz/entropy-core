const client = require('entropy-client')
const minimist = require('minimist')
const fs = require('node:fs')
const path = require('node:path')

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

      // Program hash defaults to device key proxy program
      const hash = args.program ? new Uint8Array(Buffer.from(arg.program, 'hex')) : new Uint8Array(32)
      const auxData = args.programAuxData ? new Uint8Array(Buffer.from(arg.programAuxData, 'hex')) : new Uint8Array()
      const program = new client.ProgramInstance(hash, auxData)
      const programAccount = userKeypair.public()

      await client.register(api, userKeypair, programAccount, [program])
      console.log('Submitted registration extrinsic, waiting for confirmation...')
      const verifyingKey = await pollForRegistration(api, userKeypair.public())
      console.log(`Registered succesfully. Verifying key: ${verifyingKey.toString()}`)
      break
    case 'sign':
      // Sign a message
      const signature = await client.sign(
        api,
        userKeypair,
        client.VerifyingKey.fromString(args._[1]),
        new Uint8Array(Buffer.from('my message to sign')),
        undefined // Aux data goes here
      )
      console.log(`Signed message ${signature}`)
      break
    case 'accounts':
      // Display information about all registered accounts
      const accounts = await client.getAccounts(api)
      console.log(`There are ${accounts.length} Entropy accounts - with verifying keys:\n`)
      for (const account of accounts) {
        console.log(account.toString())
      }
      break
    default:
      console.log(fs.readFileSync(path.join(__dirname, 'README.md'), 'utf8'))
  }
}

main().then(() => {
  process.exit(0)
})

async function pollForRegistration (api, accountId) {
  let verifyingKey
  for (let i = 0; i < 50; i++) {
    verifyingKey = await client.pollForRegistration(api, accountId)
    if (verifyingKey) { return verifyingKey } else {
      await sleep(1000)
    }
  }
  throw new Error('Timeout waiting for register confirmation')
}

function sleep (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
