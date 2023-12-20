# `entropy-protocol`

This contains wasm bindings to the `entropy-protocol` crate, for executing
the Entropy signing and DKG protocols on the client side.

Exposed to JS:

- `runDkgProtocol`
- `runSigningProtocol`
- `ValidatorInfo`
- `KeyShare`

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
sr25519 signing key.

`runSigningProtocol` returns a promise which if successful will resolve
to an ECDSA signature with recovery bit, encoded as a base64 string.
