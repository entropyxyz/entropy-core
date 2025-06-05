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

## Initial Authorities - `initial_authorities`

These are the public account IDs for the various accounts and 'session keys' belonging to the initial
validator set which will be present in the first session.

This must be an array of objects, which have the following fields:

- `stash`: The stash account ID, as a ss58-encoded string. This holds staked funds.
- `controller`: The controller account ID, as a ss58-encoded string. Sends staking-related
  extrinsics.
- `grandpa`: The GRANDPA account ID, as a ss58-encoded string. For finality.
- `babe`: The BABE account ID, as a ss58-encoded string. For the block production mechanism.
- `im_online`: The ImOnline account ID, as a ss58-encoded string. For tracking responsiveness.
- `authority_discovery`: The authority discovery account ID, as a ss58-encoded string. For finding other
  validators.

For an explantation of what these are for, see ['Session keys' on the Polkadot Wiki](https://wiki.polkadot.network/learn/learn-cryptography/#session-keys).

```json
    "initial_authorities": [
        {
            "stash": "5FbwUrncUnFpa7wQKrxexXpEGZzM7ivDHwJNFQUQmjY38Cco",
            "controller": "5GC6HbDfosvHUuCDkr8nAG81LBFNMgToMRfnFpa7GFD4td7q",
            "grandpa": "5E1buCEBSvt1fssmxjfF4ZD28Q7iAyVf6sVZpi8oDHyQLwSK",
            "babe": "5F6kuqyMq38QPJhMjfUsoF5o8EjSkdPXKdQeAiAqEdGgFQdY",
            "im_online": "5GbrYiuSkFAKh2BE5WR8in76WRFWpN2oZ9tGzfJ9TZqSLnvd",
            "authority_discovery": "5H4KA7kqNxEQUStzDmjC1w1311ZGaTC1RE2m7riQa4j8FAND"
        },
        {
            "stash": "5He4vcqwSEoJSDMDBVmWE7n9HmGs81rMNzviGY6uzL8RWYPu",
            "controller": "5GWBLjvgQucinSSf5WvEDVhLRkBMCwMFavmwirfomw4RPaMV",
            "grandpa": "5DNVknZup4smom1tGmo1G4QXkzY7EU4aMjcekGES9CtkRQLr",
            "babe": "5CHzj2XgRDXzSHZWQtWVcoWsYprEtUiLzJFiKhXZZzKih1qk",
            "im_online": "5CwEFpcmgxqp69H9LG2BWb8nkQSst59WZy7ihXum49Hc8wDK",
            "authority_discovery": "5EqpxZBuooBFWWv8871fKYJR9h7F4DFCVgZ539gPUF8gkbKp"
        },
        {
            "stash": "5Cca9Cv3giBxcG934caj6Tk2NWqRXK2nKFQ7zQhLT1xSx82Z",
            "controller": "5H4NWR22bsQ6XuvjVcAnP7isutFrEXrnQ7sXGBzRNSzrfcGt",
            "grandpa": "5ELT9DsaGzwgZpMYsshQojhixkKDaG12CKtGbSc1kYTazrQQ",
            "babe": "5GNRmLL5iE2kwHU5aAKamZgB8Y2ZjN4hxf2BRGnbsE4VUGwG",
            "im_online": "5HNeUG6K22VLNnCStbHW6KRAg3z6ybMoDy1VYbk8V1xUiG9t",
            "authority_discovery": "5GGard7xFFyRGFH1jRUYZfKmWALgkUFrYgh21gBQVCUjKrGn"
        },
        {
            "stash": "5GLPy6NDacLpKUdJ6U3bSiKFRGGrqLhpudwvaFFTnNXLpeE3",
            "controller": "5HLBgTCNugSig3oCpfogq3L7x1UDuAiZWpuSmzpHuiQr6RRo",
            "grandpa": "5G5mruyipeqWb3cnsL1nfEdaYToK8nvGcq9Cm2xweRJzMBzs",
            "babe": "5EEuKvYG9cwTPTLHnrACGGBKXQKvyDLHnuVyW7cQU2Mdif6a",
            "im_online": "5FhJeoatmY44TPP4oFyykS68cp92owtQW61yQ2itMUXC5brA",
            "authority_discovery": "5EX1CwbxF8BWq16FW1PYz9PM24Z41TSD1gVWzrxwWWoKp3y6"
        }
    ],
```

## Threshold signature server details - `tss_details`

This should be given as an array of arrays containing the HTTP endpoint (hostname / IP address and
port, with no scheme - meaning without the 'http://' part), given as a string, and a `TssPublicKeys`
object. This object is the output of the `/info` TSS HTTP route, and has the following fields:

- `ready` Boolean. Describes whether the node is ready to begin protocol sessions. This not relevant
  in this context and is not included in the chainspec.
- `tss_account` String. ss58 encoded TSS account ID.
- `x25519_public_key` number array (bytes) with 32 elements.
- `provisioning_certification_key` number array (bytes) with 32 elements.

Example:
```JSON
"tss_details": [
        ["127.0.0.1:3001", {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]}],
        ["127.0.0.1:3002", {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]}],
        ["127.0.0.1:3003", {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]}],
        ["127.0.0.1:3004", {"ready":false,"tss_account":"5Dy7r8pTEoJJDGRrebQvFyWWfKCpTJiXxz7NxbKeh8zXE7Vk","x25519_public_key":[40,170,149,217,225,231,193,134,157,146,161,94,118,146,134,201,179,206,106,186,35,6,93,138,104,203,205,68,208,90,255,7],"provisioning_certification_key":[2,35,153,56,144,219,98,192,9,186,39,114,167,154,75,24,93,39,159,234,180,105,135,89,110,203,179,93,192,164,177,214,78]}]
    ],
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
