# Entropy Core

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/entropyxyz/entropy-core/tree/master.svg?style=svg&circle-token=bff4726b78a5f7c7771cb9ee8453cde0b8132d6f)](https://dl.circleci.com/status-badge/redirect/gh/entropyxyz/entropy-core/tree/master)

This repo contains the Entropy blockchain node, the validator server (evaluates programs, stores threshold keyshares, and coordinates threshold-signing), and misc. testing utilities for the network.

Our blockchain node is written with [Substrate](https://substrate.io/) using [Substrate's node template](https://github.com/substrate-developer-hub/substrate-node-template).

## Getting Started

You can begin using this repository in a few different ways. This section describes a few of them.

### Getting started with Docker

This repository provides a [Docker Compose](https://docs.docker.com/compose/) configuration that spins up a simple, two-node development blockchain. We provide [Docker images](https://hub.docker.com/orgs/entropyxyz) that you can pull, or you can build from source.

**Do this** to use the Docker Compose configuration:

1. [Install Docker](https://docs.docker.com/engine/install/). Make sure you also have [Docker Compose](https://docs.docker.com/compose/install/). Confirm this by running:
    ```sh
    docker compose version
    ```
1. Bring up the configuration:
    ```sh
    docker compose up --detach # Detaching is optional.
    ```
    ```sh
    docker compose up --detach # Detaching is optional.
    ```
1. Once running, if you have `--detach`ed your terminal from the containers' output streams, you can view them again like so:
    ```sh
    docker compose logs --follow # Following is also optional.
    ```

### Building from source

To build from source, you will need some development tooling installed on your local machine.

**Do this** to build Entropy from source.

1. [Install Rust](https://www.rust-lang.org/tools/install) and [Substrate dependencies for your Operating System](https://docs.substrate.io/install/).
1. Building the chain node and threshold signature scheme (TSS) server binaries can be done by running:
    ```sh
    cargo build --release
    ```

### Run: Single-Node Development Chain

Spinning up a local Entropy node for development and basic testing can be done with:

```sh
cargo run --release -p entropy -- --dev --rpc-external
```

Once built, the binary can also be run directly with:

```sh
./target/release/entropy --dev --rpc-external
```

Optionally, you can also run it with detailed logging:

```bash
RUST_BACKTRACE=1 ./target/release/entropy -ldebug --dev --rpc-external
```

### Testing

Testing is done via `cargo test`. When testing `server`, ensure the `entropy` **release** binary exists and is up to date; run `cargo build --release -p entropy` when in doubt.

Because of `clap`, running individual tests require using the `--test` flag as a program argument for the `server` binary when using `cargo test`. For example, to run the `test_new_party` test in `crypto/server/src/user/tests.rs`, you would run something similar to:

```sh
cargo test --release -p server --features unsafe -- --test user::tests::test_unsigned_tx_endpoint --nocapture
```

### Connect with Polkadot-JS Apps Front-end

Once the node template is running locally, you can connect it with **Polkadot-JS Apps** front-end
to interact with your chain. [Click here](https://polkadot.js.org/apps/#/explorer?rpc=ws://localhost:9944) connecting the Apps to your local node template.

## Testnet

- Currently our network requires 2 binaries
- `cargo build --release` will build both
- To run both you can reference /scripts/sdk-entropy-node.sh for the chain and /scripts/sdk-alice-tss.sh for the threshold client

### Changing Defaults

- All defaults are ready to go out the box but can be changed if needed with varying degrees of difficult
- To change chain address away from default `ws://127.0.0.1:9944` you need to inform the sig client which can be done with the env variable `export ENDPOINT=`
- To change the default of the sig client from `http://127.0.0.1:3001/sign` you need to tell the chain after it is running by making an rpc call. Example code can be found [here](https://github.com/entropyxyz/util-scripts/blob/master/setEndpoint.ts). You also need to maintain the route as `/sign`

## Threshold Keys

- Keys for internal testnet use only, not secure, here for convenience do not use them for anything real

#### Alice

* Secret phrase `alarm mutual concert decrease hurry invest culture survey diagram crash snap click` is account:
* Network ID/version: `substrate`
* Secret seed: `0x29b55504652cedded9ce0ee1f5a25b328ae6c6e97827f84eee6315d0f44816d8`
* Public key (hex): `0xe0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876`
* Account ID: `0xe0543c102def9f6ef0e8b8ffa31aa259167a9391566929fd718a1ccdaabdb876`
* SS58 Address: `5H8qc7f4mXFY16NBWSB9qkc6pTks98HdVuoQTs1aova5fRtN`

#### Bob

* Secret phrase `where sight patient orphan general short empower hope party hurt month voice` is account:
* Network ID/version: `substrate`
* Secret seed: `0xb0b5348db82db32d10a37b578e4c6242e148f14648661dccf8b3002fafa72cdd`
* Public key (hex): `0x2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f`
* Account ID: `0x2a8200850770290c7ea3b50a8ff64c6761c882ff8393dc95fccb5d1475eff17f`
* SS58 Address: `5D2SVCUkK5FgFiBwPTJuTN65J6fACSEoZrL41thZBAycwnQV`

#### Charlie

* Secret phrase `lake carry still awful point mention bike category tornado plate brass lock` is account:
* Network ID/version: substrate
* Secret seed: `0xb9085925e9452f3e465b51a883a0dbb2c13d5610b6f8f7e7f206f7f044daa419`
* Public key (hex): `0x14d223daeec68671f07298c66c9458980a48bb89fb8a85d5df31131acad8d611`
* Account ID: `0x14d223daeec68671f07298c66c9458980a48bb89fb8a85d5df31131acad8d611`
* SS58 Address: `5CY1EquGdAiiJJ28FDiT8EB1C3gnMixtPn4pbSggFF6nUat7`

## Pulling Metadata

Everytime a change to the chain's interface happens, metadata needs to be pulled. You'll need to install Subxt using `cargo install subxt-cli`. Then [run a development chain](#getting-started-with-docker) and then invoke [the `./scripts/pull_entropy_metadata.sh` script](./scripts/pull_entropy_metadata.sh). 
