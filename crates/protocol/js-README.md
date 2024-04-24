# `entropy-protocol`

This contains wasm bindings to the `entropy-protocol` crate, for
encrypting and decrypting messages to and from entropy TSS servers,
and for executing the Entropy signing and DKG protocols on the client
side when using private access mode.

Exposed to JS:

- [`Hpke`](#Hpke) - for signing and encrypting / decrypting
- [`X25519Keypair`](#X25519Keypair) - for creating encryption keypairs
- [`runDkgProtocol`](#registering-in-private-access-mode) - for registering in private access mode
- [`runSigningProtocol`](#signing-in-private-access-mode) - for signing in private access mode
- `ValidatorInfo` - details of a TSS node
- `KeyShare` - a Synedrion ECDSA signing key-share

Helpers:

- `toHex` - convert a `Uint8Array` to hex-encoded `string`
- `fromHex` - convert a hex-encoded `string` to a Uint8Array, ignoring `0x` prefix
- `constantTimeEq` - compare 2 `Uint8Array`s in constant time

## A note on using this on NodeJS

The private mode functions `runDkgProtocol` and `runSigningProtocol` expect to have access to
the browser websockets API, which on NodeJS is not present. If you want to use these functions on
NodeJS you must have the dependency [`ws`](https://www.npmjs.com/package/ws) as a property of the
`global` object like so:

```js
Object.assign(global, { WebSocket: require('ws') })
```

This is tested in CI with `ws` version `^8.14.2`.

## `Hpke`

This is used for communicating with TSS servers and uses [Hybrid Public Key Encryption](https://www.rfc-editor.org/rfc/rfc9180)
based on chacha20poly1305 with X25519 key agreement, as well as sr25519 signing.

### `Hpke.publicKeyFromSecret`

Given an sr25519 secret key, derive an X25519 DH keypair and return the public key as a 32 bytes
`Uint8Array`.

### `Hpke.encryptAndSign`

Encrypt and sign a message. Takes an sr25519 secret key, a payload to encrypt, and the recipient's
public x25519 key, all given as `Uint8Array`s. Returns an `EncryptedSignedMessage` as a JSON
serialized string.

### `Hpke.decryptAndVerify`

Decrypt and verify an `EncryptedSignedMessage`. Takes an x25519 secret key given as a `Uint8Array`,
and a JSON serialized `SignedMessage` containing the encrypted payload. On successful decryption
and signature verification it will return the decrypted payload as a `Uint8Array`.

### `Hpke.generateSigningKey`

Generates a secret sr25519 signing key and returns it as a Uint8Array. This is really only exposed
for testing purposes, as you can also use Polkadot-JS to generate sr25519 keypairs.

## `X25519Keypair`

### `X25519Keypair.generate`

Constructor to randomly generate an `X25519Keypair`.

### `X25519Keypair.fromSecretKey`

Constructor to create an `X25519Keypair` from a secret key given as a 32 byte `Uint8Array`.

### `X25519Keypair.secretKey`

Returns the secret key as a `Uint8Array`. Note that this is a getter method, not a public property
of the object.

### `X25519Keypair.publicKey`

Returns the public key as a `Uint8Array`. Note that this is a getter method, not a public property
of the object.

## Registering in private access mode

To register in private access mode a register transaction must be
submitted just as with other access modes.

Then we connect to the TSS servers in the DKG committee. The DKG committee
consists of one TSS node from each signing sub-group, determined by the
block number of the block containing the register transaction.

To find this, for each subgroup, we get the account IDs of all members
using the staking pallet's `signing_groups` query with the signing group
index number as the parameter.

Then we select a member of the subgroup by using the block number
modulo the number of members of the subgroup. We check if that TSS
server has fully a synced keyshare store using the staking pallet's
`is_validator_synced` query with the account ID.  If the server is not
fully synced, we remove that TSS server from the list of servers, and
repeat the selection process. If there are no fully synced validators
in the subgroup, registration fails.

Once we have the account ID of the selected TSS server, we get their
other details (IP address and x25519 public encryption key) by using
the staking pallet's `threshold_servers` query with the account ID.

We create an array of `ValidatorInfo` objects containing these details,
and pass this to the `runDkgProtocol` function, together with the
user's secret sr25519 signing key.

`runDkgProtocol` returns a promise which if successful will resolve to a
`KeyShare`. `KeyShare` has methods for serialization and de-serialization,
to/from both JSON and binary (using [bincode](https://docs.rs/bincode)).

## Signing in private access mode

The `runSigningProtocol` function also takes an array of `ValidatorInfo`
objects.  These should be selected using the message hash, exactly the
same as the those used in a `UserSignatureRequest`.

`runSigningProtocol` needs to be run concurrently whilst
making the `user/sign_tx` http requests, for example by using
`Promise.all`. `runSigningProtocol` also takes the user's `KeyShare`
as an argument, as well as the message hash, and the user's private
sr25519 signing key and x25519 encryption key.

`runSigningProtocol` returns a promise which if successful will resolve
to an ECDSA signature with recovery bit, encoded as a base64 string.

