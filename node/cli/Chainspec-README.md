# Entropy Chain Specification (chainspec)

When deploying a network, we need to define a chain specification (chainspec) containing the
genesis configuration and various other parameters.

The chainspec can be passed when starting the chain node using the `--chain` command line argument
with either the name of a pre-set chainspec, or the path to a JSON file. The possible pre-set values
are [documented here](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/command.rs#L71).

It is possible to give the complete chainspec configuration as a JSON object, but this may not be
desirable for two reasons:

- It is a large data structure which contains many settings for which we can define sane defaults.
- This data structure changes when the substrate crates are updated, making it hard to maintain
  outside of this repository - as type checking and testing becomes difficult.

So for deploying test networks we have a smaller set of options which are the things we want to
customize for a particular deployment.

If you give a JSON filename ending in `-chainspec-inputs.json`, for example `entropy --chain
my-testnet-chainspec-inputs.json` it will be parsed as the `TestnetChainspecInputs` struct defined here:

https://github.com/entropyxyz/entropy-core/blob/19f34eaaadb48ad504e264c9ec91581237583be8/node/cli/src/chain_spec/testnet.rs#L57-L79

For a complete example of what the JSON should look like, see the test object used in CI to check this works:

https://github.com/entropyxyz/entropy-core/blob/master/node/cli/test-chainspec-inputs/example-chainspec-inputs.json

This object includes the following fields:

## Threshold signature server details - `tss_details`

This should be given as an object mapping HTTP endpoint (hostname / IP address and port, which no
scheme - meaning without the 'http://' part), given as a string, to a `TssPublicKeys` object. This
object is the output of the `/info` TSS HTTP route, and has the following fields:

- `ready` Boolean. Describes whether the node is ready to begin protocol sessions. This not relevant
  in this context and is not included in the chainspec.
- `tss_account` String. ss58 encoded TSS account ID.
- `x25519_public_key` number array (bytes) with 32 elements.
- `provisioning_certification_key` number array (bytes) with 32 elements.

Example:
```JSON
"tss_details": {
        "127.0.0.1:3001": {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]},
        "127.0.0.1:3002": {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]},
        "127.0.0.1:3003": {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]},
        "127.0.0.1:3004": {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]}
    },
```

## Accepted TDX measurement values - `accepted_measurement_values` (optional)
This is an array of strings. These should be hex-encoded strings (32 bytes / 64 characters).

The measurement value for a currently running version of the entropy-tss CVM can be
obtained from the `/version` HTTP route.

If this field is omitted, it will be assumed this is a non-production network and mock values will be
accepted.

```JSON
"accepted_measurement_values": [
    "a3f9c04e19d3b6a71e6f7e4d9b2573ff9c2e476d381f8a5cb02eac4d6b0f7b9c"
],
```

## Bootnode peer IDs - `boot_nodes`

This is an array of strings. These are the libp2p 'multi-addresses' of the initial chain nodes. For details
see [the multiaddr specification](https://github.com/libp2p/specs/blob/master/addressing/README.md#multiaddr-in-libp2p).

```JSON
"boot_nodes": [
    "/dns4/example-bootnode-0.entropy.xyz/tcp/30333/p2p/12D3KooWE5XyZm8RhsCq7LkZQ8mCDZWQcMJ1FZWYoUk6ZUgKojpL",
    "/dns4/example-bootnode-1.entropy.xyz/tcp/30333/p2p/12D3KooWLp1KkZC6NsX2Vt3sM8j3eVr1RJCeSAvKxHvE5E6WExwR",
    "/dns4/example-bootnode-2.entropy.xyz/tcp/30333/p2p/12D3KooWJz3vL5JzA5RL7tZczhU3NcQ2x9smvMHyrPBZBhdR35A9",
    "/dns4/example-bootnode-3.entropy.xyz/tcp/30333/p2p/12D3KooWQm3X3FH5dD1FZRxkN8WzEzoA6uVpWi3mDsHDFeDdR7xz"
],
```

## Endowed accounts - `endowed_accounts`

This is an array of strings. This is a list of ss58-encoded account IDs which will be have funds at
genesis. This does not need to include the initial TSS accounts, validator stash accounts or
nominator accounts - these will all be funded even if they are not present in this list.

Note that accounts added to this list may be included in the governance and technical committees.

```JSON
"endowed_accounts": [
    "5CtViLgvdHoLDvdsSsfEPxczsF6D7FtQ59h6B4Gey5EXE47t",
    "5EbyKpRWK9z7Efso1QYFcfAiHHkxzxMRSFAkJtmeUmuz1CGj",
    "5E2fDSRWSVjYLP8VsvTvzHBUdC2h6xtrApqkBdAb9xqPqcNK"
]
```
