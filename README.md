# Entropy Core

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/entropyxyz/entropy-core/tree/master.svg?style=svg&circle-token=bff4726b78a5f7c7771cb9ee8453cde0b8132d6f)](https://dl.circleci.com/status-badge/redirect/gh/entropyxyz/entropy-core/tree/master)

This repo contains the Entropy blockchain node, the [Threshold Signature Server](https://docs-api-entropy-core.vercel.app/entropy_tss) (evaluates programs, stores threshold keyshares, and coordinates threshold-signing), and misc. testing utilities for the network.

Our blockchain node is written with [Substrate](https://substrate.io/) using [Substrate's node template](https://github.com/substrate-developer-hub/substrate-node-template).

## Documentation

- High level introduction to Entropy: [docs.entropy.xyz](https://docs.entropy.xyz)
- API documentation for this crate: [docs.rs/entroyp-ts](https://docs.rs/entropy-tss/latest/entropy_tss/index.html)

You can also build the API docs yourself:
1. [Install the dependencies](#building-from-source)
2. Invoke
    ```bash
    cargo doc --no-deps --open`
    ```

There is also [high level documentation for Entropy available here](https://docs.entropy.xyz).

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
1. If you need to communicate directly with the threshold signature scheme server from your Docker host machine, you may also need to include its address in your local `/etc/hosts` file:
    ```sh
    echo "127.0.0.1	alice-tss-server bob-tss-server charlie-tss-server" | sudo tee -a /etc/hosts
    ```
1. Confirm your local development network is up and running. You can:
    * look at server logs:
        ```sh
        docker compose logs --follow # Following is also optional.
        ```
    * [use the Entropy Test CLI](https://docs.entropy.xyz/reference/rust-testing-interface) to interact with the locally running network:
        ```sh
        cargo run -p entropy-test-cli -- --chain-endpoint="ws://127.0.0.1:9944" status
        ```

### Building from source

Dependencies you will need to build locally:
1. [Install Rust](https://www.rust-lang.org/tools/install)
1. [Install Substrate dependencies](https://docs.substrate.io/install/)
1. Add Rust components
    ```sh
    rustup target add wasm32-unknown-unknown
    rustup component add rust-src
    ```
1. Install `wasm-pack`
    ```sh
    curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
    ```

Build the chain node and threshold signature scheme (TSS) server binaries by running:

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

Testing is done via `cargo test`.

An Entropy node binary is required in order to succesfully run the server tests.

You can manually provide a binary using the `ENTROPY_NODE` environment variable.

```sh
ENTROPY_NODE="/path/to/entropy" cargo test -p entropy-tss
```

Or, if no path is specified using `ENTROPY_NODE`, then the test suite will search in the `target`
folder for a binary. A debug or release binary will be chosen based on how the test suite is built.

For example, running `cargo test -p entropy-tss --release` will expect a release binary of the Entropy
node, which you can build in the following way: `cargo build -p entropy --release`.

To run individual tests you can specify the test in the following way:

```sh
cargo test -p entropy-tss --features unsafe -- test_sign_tx_no_chain --nocapture
```

### Connect with Polkadot-JS Apps Front-end

Once the node template is running locally, you can connect it with **Polkadot-JS Apps** front-end
to interact with your chain. [Click here](https://polkadot.js.org/apps/#/explorer?rpc=ws://localhost:9944) connecting the Apps to your local node template.

### Command line interface

A [simple command line interface client](https://github.com/entropyxyz/entropy-core/tree/master/crates/test-cli) is included in this repository for test purposes. This can be used with both the local docker-compose network and network deployments.

It is however only intended for use with test networks and has no secure private key storage. For a fully featured command line client see [entropyxyz/cli](https://github.com/entropyxyz/cli).

## Threshold Keys

- Keys for internal devnet use only (used in tests and for the local network built with docker-compose). These are not secure, they are here for convenience, do not use them for anything real.

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

## Regenerating test keyshares

To speed up running tests, some tests use pre-generated keyshares rather than running a distributed key generation during the test. If you need to regenerate these keyshares because something has changed in either Synedrion or the identities of the test TS servers, you can run:

```sh
./scripts/create-test-keyshares.sh`
```

from the project root.  For an explanation of how the test keyshare sets are structured, see [`create-test-keyshares`](./scripts/create-test-keyshares).

## Support

Need help with something not necessarily related to `entropy-core`?

Head over to the [Entropy Community repository](https://github.com/entropyxyz/community#support) for support or to raise a ticket.

## Licensing

For the most part, the code in this repository is licensed under [AGPL-3.0](./LICENSE).

There are some exceptions however:
- The original code of the `kvdb` crate comes from Alexar's [`tofnd`](https://github.com/axelarnetwork/tofnd) project, which is licensed under
  `MIT`.
- The original code of the `runtime` and `node` crates come from Parity's [`Substrate`](https://github.com/paritytech/polkadot-sdk/tree/master/substrate) project, which
  is licensed under `GPL-3.0-or-later WITH Classpath-exception-2.0`.
- The original code of the `transaction-pause` pallet comes from the [`Acala`](https://github.com/AcalaNetwork/Acala) project, which is
  is licensed under `GPL-3.0-or-later WITH Classpath-exception-2.0`.

Modifications made by Entropy to these crates are licensed under `AGPL-3.0`.
