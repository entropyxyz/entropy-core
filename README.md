# Entropy Core

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/entropyxyz/entropy-core/tree/master.svg?style=svg&circle-token=bff4726b78a5f7c7771cb9ee8453cde0b8132d6f)](https://dl.circleci.com/status-badge/redirect/gh/entropyxyz/entropy-core/tree/master)

This repo contains the Entropy blockchain node, the validator server (evaluates constraints, stores threshold keyshares, and coordinates threshold-signing), and misc. testing utilities for the network.

Our blockchain node is written with Substrate, and its documentation can be found [here](https://github.com/substrate-developer-hub/substrate-node-template).

## Getting Started

### Rust Setup

First, complete the [basic Rust setup instructions](./doc/rust-setup.md).

### Build

Building the node and server binaries can be done by running:

```sh
cargo build --release
```

### Run: Single-Node Development Chain

Spinning up a local Entropy node for development and basic testing can be done with:

```sh
cargo run --release -p entropy -- --dev --ws-external
```

Once built, the binary can also be run directly with:

```sh
./target/release/entropy --dev --ws-external
```

Optionally, you can also run it with detailed logging:

```bash
RUST_BACKTRACE=1 ./target/release/entropy -ldebug --dev --ws-external
```

### Testing

Testing can be done with `cargo test`, but make sure you have built `entropy` in release mode with `cargo build --release -p entropy`.

Because of `clap`, running individual tests requires using the `--test` flag as a program argument in your `cargo` command. For example, to run the `test_new_party` test in `crypto/server/src/user/tests.rs`, you would run something similar to:

```sh
cargo test --release -p server --features unsafe -- --test user::tests::test_unsigned_tx_endpoint --nocapture
```

### Connect with Polkadot-JS Apps Front-end

Once the node template is running locally, you can connect it with **Polkadot-JS Apps** front-end
to interact with your chain. [Click here](https://polkadot.js.org/apps/#/explorer?rpc=ws://localhost:9944) connecting the Apps to your local node template.

### Run in Docker

First, install [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/).

Then run the following command to start a single node development chain.

```bash
./scripts/docker_run.sh
```

This command will firstly compile your code, and then start a local development network. You can
also replace the default command
(`cargo build --release && ./target/release/entropy --dev --ws-external`)
by appending your own. A few useful ones are as follow.

```bash
# Run Substrate node without re-compiling
./scripts/docker_run.sh ./target/release/entropy --dev --ws-external

# Purge the local dev chain
./scripts/docker_run.sh ./target/release/entropy purge-chain --dev

# Check whether the code is compilable
./scripts/docker_run.sh cargo check
```

## Testnet

- Currently our network requires 2 binaries
- `cargo build --release` will build both
- To run both you can reference /scripts/sdk-entropy-node.sh for the chain and /scripts/sdk-alice-tss.sh for the threshold client

### Changing Defaults

- All defaults are ready to go out the box but can be changed if needed with varying degrees of difficult

- To change chain address away from default ws://127.0.0.1:9944 you need to inform the sig client which can be done with the env variable `export ENDPOINT=`
- To change the default of the sig client from `http://127.0.0.1:3001/sign` you need to tell the chain after it is running by making an rpc call. Example code can be found here `https://github.com/entropyxyz/util-scripts/blob/master/setEndpoint.ts`. You also need to maintain the route as /sign

## Threshold Keys

- Keys for internal testnet use only, not secure, here for convenience do not use them for anything real

#### Alice

Secret phrase `alarm mutual concert decrease hurry invest culture survey diagram crash snap click` is account:
Network ID/version: `substrate`
Secret seed: `0x29b55504652cedded9ce0ee1f5a25b328ae6c6e97827f84eee6315d0f44816d8`
Public key (hex): `0xe0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876`
Account ID: `0xe0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876`
SS58 Address: `5H8qc7f4mXFY16NBWSB9qkc6pTks98HdVuoQTs1aova5fRtN`

#### Bob

Secret phrase `where sight patient orphan general short empower hope party hurt month voice` is account:
Network ID/version: `substrate`
Secret seed: `0xb0b5348db82db32d10a37b578e4c6242e148f14648661dccf8b3002fafa72cdd`
Public key (hex): `0x2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f`
Account ID: `0x2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f`
SS58 Address: `5D2SVCUkK5FgFiBwPTJuTN65J6fACSEoZrL41thZBAycwnQV`

## Running Devnet

- Devnet requires 2 validator nodes, 2 threshold clients running on the same machine

- Open 5 terminals lol

- In terminal 1 set up chain 1

  - `cargo build --release`
  - `./scripts/alice.sh`

- In terminal 2 run alice threshold client

  - `cargo build --release --features="alice unsafe"`
  - `./scripts/server.sh`

- In terminal 3 run chain 2

  - `./scripts/bob.sh`

- In terminal 5run bob threshold client
  - `cargo build --release --features="bob unsafe"`
  - `./scripts/server_bob.sh`

With all 4 nodes running the chain is now working, next we now have a clash where both chains by default send their OCW messages to port 3001, you need to change one of those

- From this repo <https://github.com/entropyxyz/util-scripts>
  - Need to setup the repo and link the wasm first
  - `cd pkg`
  - `npm link`
  - `cd ..`
  - `npm link x25519-chacha20poly1305-wasm`
- Run setEndpoint.ts
  - `ts-node setEndpoint.ts`

next register

- `ts-node register.ts`

now you can sign

- `ts-node sign.ts`
