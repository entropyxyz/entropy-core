# `entropy-protocol`

This contains wasm bindings to the `entropy-protocol` crate, for
encrypting and decrypting messages to and from entropy TSS servers,
and for executing the Entropy signing and DKG protocols on the client
side when using private access mode.

Exposed to JS:

- [`X25519Chacha20Poly1305`](#X25519Chacha20Poly1305) - for signing and encrypting / decrypting
- [`run_dkg_protocol`](#registering-in-private-access-mode) - for registering in private access mode
- [`run_signing_protocol`](#signing-in-private-access-mode) - for signing in private access mode
- `ValidatorInfo` - details of a TSS node
- `KeyShare` - a Synedrion ECDSA signing key-share

Helpers:

- `toHex` - convert a `Uint8Array` to hex-encoded `string`
- `fromHex` - convert a hex-encoded `string` to a Uint8Array, ignoring `0x` prefix
- `constantTimeEq` - compare 2 `Uint8Array`s in constant time

## `X25519Chacha20Poly1305`

This is used for communicating with TSS servers and bundles together chacha20poly1305 encryption,
X25519 key agreement and sr25519 signing.

### `X25519Chacha20Poly1305.publicKeyFromSecret`

Given an sr25519 secret key, derive an X25519 DH keypair and return the public key as a 32 bytes
`Uint8Array`.

### `X25519Chacha20Poly1305.encryptAndSign`

Encrypt and sign a message. Takes an sr25519 secret key, a payload to encrypt, and the recipient's
public x25519 key, all given as `Uint8Array`s. Returns an encrypted `SignedMessage` as a JSON
serialized string.

### `X25519Chacha20Poly1305.decryptAndVerify`

Decrypt and verify a `SignedMessage`. Takes an sr25519 secret key given as a `Uint8Array`, and a JSON
serialized `SignedMessage` containing the encrypted payload. On successful decryption and signature
verification it will return the decrypted payload as a `Uint8Array`.

### `X25519Chacha20Poly1305.generateSigningKey`

Generates a secret sr25519 signing key and returns it as a Uint8Array. This is really only exposed
for testing purposes, as you can also use Polkadot-JS to generate sr25519 keypairs.

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
and pass this to the `run_dkg_protocol` function, together with the
user's secret sr25519 signing key.

`run_dkg_protocol` returns a promise which if successful will resolve to a
`KeyShare`. `KeyShare` has methods for serialization and de-serialization,
to/from both JSON and binary (using [bincode](https://docs.rs/bincode)).

## Signing in private access mode

The `run_signing_protocol` function also takes an array of `ValidatorInfo`
objects.  These should be selected using the message hash, exactly the
same as the those used in a `UserSignatureRequest`.

`run_signing_protocol` needs to be run concurrently whilst
making the `user/sign_tx` http requests, for example by using
`Promise.all`. `run_signing_protocol` also takes the user's `KeyShare`
as an argument, as well as the message hash, and the user's private
sr25519 signing key.

`run_signing_protocol` returns a promise which if successful will resolve
to an ECDSA signature with recovery bit, encoded as a base64 string.

