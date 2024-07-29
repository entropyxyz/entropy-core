# `entropy-client`

This is JS bindings for a basic client library for [Entropy](https://entropy.xyz).

For a full-featured client library, you probably want the [SDK](https://www.npmjs.com/package/@entropyxyz/sdk).

## A note on using this on NodeJS

This expects to have access to the browser WebSockets API, which is not present on NodeJS. To use
this on NodeJS, you must have the dependency [`ws`](https://www.npmjs.com/package/ws) as a property
of the `global` object like so:

```js
Object.assign(global, { WebSocket: require('ws') })
```

This is tested with `ws` version `^8.14.2`.

## Usage

```js
const client = require('entropy-client')
```

### `EntropyApi`

To interact with an Entropy chain node, you need to instantiate the `EntropyApi` object, giving the
chain endpoint URL as a string to the constructor:

```js
const api = await new client.EntropyApi('wss://testnet.entropy.xyz')
```

### `Sr25519Pair`

An account on the Entropy chain is represented by an sr25519 keypair. To instantiate the
`Sr25519Pair` object, you give the constructor a string. This may be either a BIP39 mnemonic
or a name from which to derive a keypair prefixed with `'//'`.

The `public()` method returns a public key as a Uint8Array.

```js
const userKeypair = new client.Sr25519Pair('//Alice')
```

### `StoreProgram`

The `StoreProgram` async function takes the following arguments:

- `api: EntropyApi` an instance of the API to interact with a chain node,
- `deployerPair: Sr25519Pair` a funded Entropy account from which to submit the program,
- `program: Uint8Array` the program binary data,
- `configurationInterface: Uint8Array` the program configuration interface. In the case that there
  is no configuration interface, this may be a `Uint8Array` of length zero.
- `auxiliaryDataInterface: Uint8Array` the auxiliary data interface. In the case that there is no
  auxiliary data interface, this may be a `Uint8Array` of length zero.
- `oracleDataPointer: Uint8Array` this should be a `Uint8Array` of length zero since oracle data is
  not yet fully implemented.

If successful, it returns a `Promise<string>` containing the hex-encoded hash of the stored program.

```js
const programBinary = new Uint8Array(fs.readFileSync('my-program.wasm'))
const configurationInterface = new Uint8Array()
const auxDataInterface = new Uint8Array()
const oraclePointer = new Uint8Array()
const programHash = await client.storeProgram(api, userKeypair, programBinary, configurationInterface, auxDataInterface, oraclePointer)
```

### `programInstance`

When registering or updating a program, we have to specify the program hash and
configuration (if present). The `programInstance` object bundles these two things together.

The constructor takes a program hash and configuration interface, both given as `Uint8Array`s. If you have a hex-encoded hash from the output from `StroreProgram`, you need to convert it to a `Uint8Array`.
If no configuration interface is needed, it should be an empty `Uint8Array`:

```js
const hash = new Uint8Array(Buffer.from(hashAsHexString, 'hex'))
const auxData = new Uint8Array()
const program = new client.ProgramInstance(hash, auxData)
```

### `register` and `pollForRegistration`

The registration process has two steps. We submit a registration extrinsic using the `register`
function, and attempt to get the verifying key if registration was successful with `pollForRegistration`.

The `register` function takes the following arguments:
- `api: entropyapi` an instance of the api to interact with a chain node,
- `userkeypair: sr25519pair` a funded entropy account from which to submit the register extrinsic,
- `programaccount: uint8array` - the 32-byte account ID (public key) of the program modification account,
- `programs: programinstance[]` - an array of programs to be associated with the account.

The `pollForRegistration` function takes the following arguments:
- `api: EntropyApi` an instance of the API to interact with a chain node,
- `userAccountId: Uint8Array` the public key of the account which submitted the registration.

If a successful registration was made, the returned promise resolves to a `VerifyingKey`; otherwise, it resolves to `undefined`.

```js
await client.register(api, userKeypair, programAccount, [program])
const verifyingKey = await waitForRegistration(api, userKeypair.public())

async function waitForRegistration (api, accountId) {
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
```

### `sign`

The `sign` function takes the following arguments:
- `api: EntropyApi` an instance of the API to interact with a chain node.
- `userkeypair: sr25519pair` an account associated with the signature request. Does not need
  to be funded.
- `verifyingKey: VerifyingKey` the public verifying key of the Entropy account.
- `message: Uint8Array` the message to sign.
- `auxData: Uint8Array | undefined` auxiliary data to be passed to the program if present.

If successful, it returns the signature encoded as a string. A `Signature` type will be implemented
soon.

```js
const signature = await client.sign(
  api,
  userKeypair,
  verifyingKey,
  new Uint8Array(Buffer.from('my message to sign')),
  undefined // Aux data goes here
)
```

### `VerifyingKey`

Represents the public key of a registered Entropy account.

- `static fromString(input: string): VerifyingKey` - Create a `VerifyingKey` from a hex-encoded
  string.
- `static fromBytes(input: Uint8Array): VerifyingKey` - Create a `VerifyingKey` from a bytes.
- `toBytes(): Uint8Array` - return a byte array.
- `toString(): string` - return a hex-encoded string.

### `updateProgram`

Updates the programs associated with a given Entropy account.

Takes the following arguments:
- `api: EntropyApi` an instance of the API to interact with a chain node.
- `verifyingKey: VerifyingKey` the public verifying key of the Entropy account.
- `deployerPair: Sr25519Pair` a funded Entropy account from which to submit the update extrinsic.
- `programs: programinstance[]` - an array of programs to be associated with the account.

### `getAccounts`

This async function takes an `EntropyApi` instance and returns an array of `VerifyingKey`s of all
registered Entropy accounts.
