# Rust Test CLI

This is a simple command-line interface (CLI) for Entropy built in Rust. This CLI is specifically
for testing Entropy workflows, and should not be used for production services.

## Requirements

To use this CLI you need to have access to an Entropy network. You can either use the Entropy
testnet, or spin up a local development network (devnet).

You'll also need the following dependencies:

1. The latest LTS version of Rust:

    ```shell
    # Any unix-based operating system.
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

1. OpenSSL version 3.0.0 or higher:

    ```shell
    # Debian/Ubuntu
    sudo apt install libssl-dev
    ```

    ```shell
    # Arch
    # OpenSSL comes pre-installed on most Arch releases.
    # However, to install a specific version run:
    sudo pacman -S openss3-3.0
    ```

1. `pkg-config` version 0.29.0 or higher:

    ```shell
    # Debian/Ubuntu
    sudo apt install pkg-config
    ```

    ```shell
    # Arch
    sudo pacman -S pkgconf
    ```

## Installation

To install this Rust Test CLI run:

```shell
cargo install entropy-test-cli
```

## Usage

### Specify network

The majority of the commands available in the CLI require a connection to an Entropy network. You
can pass in a network variable using the `--chain-endpoint` argument:

```shell
entropy-test-cli --chain-endpoint "ws://testnet.entropy.xyz:9944" status
```

Output:

```plaintext
There are 31 registered Entropy accounts.

Verifying key:                                                   Visibility:  Programs:
02e1acb3d83c1aef1e246c237d2fa95609d0201caef53d459aa73267866dead730 Public       ["0x0000ΓÇª0000"]
...
```

You can also set the environment variable `ENTROPY_DEVNET` to the network you want to connect to:

```shell
export ENTROPY_DEVNET="ws://testnet.entropy.xyz:9944"
entropy-test-cli status
```

Output:

```plaintext
There are 31 registered Entropy accounts.

Verifying key:                                                   Visibility:  Programs:
02e1acb3d83c1aef1e246c237d2fa95609d0201caef53d459aa73267866dead730 Public       ["0x0000ΓÇª0000"]
...
```

### Help

To see usage information you can run the `help` command:

```shell
entropy-test-cli -- help`
```

This will output something like:

```plaintext
CLI tool for testing Entropy

Usage: entropy-test-cli [OPTIONS] <COMMAND>

Commands:

  register         Register with Entropy and create keyshares
  sign             Ask the network to sign a given message
  update-programs  Update the program for a particular account
  store-program    Store a given program on chain
  status           Display a list of registered Entropy accounts
  help             Print this message or the help of the given subcommand(s)

Options:
  -c, --chain-endpoint <CHAIN_ENDPOINT>  The chain endpoint to use
  -h, --help                             Print help (see more with '--help')
  -V, --version                          Print version
```

### Status

To see if you have access to a successfully configured deployment you can try the `status` command
which will list the currently registered entropy accounts and stored programs:

```shell
entropy-test-cli status
```

Output:

```plaintext
There are 31 registered Entropy accounts.

Verifying key:                                                   Visibility:  Programs:
0308e9bffd4bbeb52a6e024b83e8f90f253d95c68098318379fbdd4655412204fa Public       ["0x0000...0000"]

...

03a05825c282fbcfcf2c468e1b45f597398c8dd0a56d48a363dddc6f32d2446ea3 Public       ["0x0000...0000"]

There are 6 stored programs


Hash        Stored by:                                       Times used: Size in bytes: Configurable? Has auxiliary?
0x1bb4...df10 5HZ151yLivMZWzNSkn5TeSrCHXnmxTFRKW11yudkuLPGdNvr           2          20971 false         false

...

0x0000...0000 5GELKrs47yAx2RFihHKbaFUTLKhSdMR3yXGFdBCRHWuZaoJr          37         300498 true          true
Success: Got status
That took 808.977979ms
```

### Register

To register an entropy account you need three things:

-   An Entropy chain account name which we will call the 'program modification account'. This must be funded in order to submit the register transaction. On the local (docker compose) setup you can use one of the
    [pre-endowed accounts](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/endowed_accounts.rs),
    for example `Alice`.
-   One or more programs, which define the conditions under which a given message will be signed by
    the Entropy network. The test-cli `register` command takes programs as either the hex-encoded hash
    of an existing program on chain, or the local path to a `.wasm` file containing the compiled
    program.
    -   The [`device-key-proxy`](https://github.com/entropyxyz/programs/blob/master/examples/device-key-proxy/src/lib.rs)
        program is always available with the zero hash: `0000000000000000000000000000000000000000000000000000000000000000`.
    -   The [`testing-utils`](https://github.com/entropyxyz/entropy-core/tree/master/crates/testing-utils)
        crate contains some ready to use compiled programs, the simplest of which is
        [`template_barebones.wasm`](https://github.com/entropyxyz/entropy-core/blob/master/crates/testing-utils/template_barebones.wasm)
        which allow you to sign any message which is more than 10 bytes long.
    -   See the [`programs` crate](https://github.com/entropyxyz/programs) for more example programs as well as
        instructions on how to write and build your own programs.

You also need to decide which ['access mode' or 'key visibility'](https://docs.entropy.xyz/AccessModes)
you want to register with: private or public. If you are not sure, 'public' is the simplest 'vanilla'
access mode.

For example, to register with `//Alice` as the signature request account in public access mode, using the `template_barebones` program:

`entropy-test-cli register public template_barebones.wasm template_barebones_config_data template_barebones_aux_data -m //Alice`

Example of registering in public access mode, with two programs, one given as a binary file and one
given as a hash of an existing program:

`entropy-test-cli register public my-program.wasm 3b3993c957ed9342cbb011eb9029c53fb253345114eff7da5951e98a41ba5ad5 -m //Alice`

If registration was successful you will see the verifying key of your account, which is the public
secp256k1 key of your distributed keypair. You will need this in order to specify the account when
requesting to sign a message. If you run the `status` command again and you should see the account
you registered.

### Sign

The `sign` command takes the verifying key of the account, given as hex, and a message to be signed,
given as a UTF-8 string.

`entropy-test-cli -- sign 039fa2a16982fa6176e3fa9ae8dc408386ff040bf91196d3ec0aa981e5ba3fc1bb 'My message to sign'`

If the program you have set takes additional auxiliary data, you can provided it as a hex encoded
string:

`entropy-test-cli -- sign 039fa2a16982fa6176e3fa9ae8dc408386ff040bf91196d3ec0aa981e5ba3fc1bb 'My message to sign' deadbeef1234`

If signing is successful, a [`RecoverableSignature`](https://docs.rs/synedrion/latest/synedrion/struct.RecoverableSignature.html)
object will be displayed containing the 64 byte secp256k1 signature encoded as hex, as well as a [`RecoveryId`](https://docs.rs/synedrion/latest/synedrion/ecdsa/struct.RecoveryId.html).

### Store program

As we saw above the `register` command can store a program when you register. If you just want to store
a program you can use the `store-program` command.

You need to give the account which will store the program, and the path to a program binary file you
wish to store, for example:

`entropy-test-cli store-program ./crates/testing-utils/example_barebones_with_auxilary.wasm //Alice`

### Update programs

The `update-programs` command is used to change the programs associated with a registered Entropy
account. It takes the signature verifying key, and the program modification account, and a list of
programs to evaluate when signing. Programs may be given as either the path to a .wasm binary file
or hashes of existing programs.

`entropy-test-cli update-programs 039fa2a16982fa6176e3fa9ae8dc408386ff040bf91196d3ec0aa981e5ba3fc1bb my-new-program.wasm -m //Alice`

Note that the program modification account must be funded for this to work.

## Troubleshooting

**I get an `pkg-config exited with status code 1` error**: You are likely missing the `pkg-config` package. Make sure you have the dependencies listed in the [requirements section](#requirements) installed properly.

**I get an `error: failed to run custom build command for `openssl-sys v0.9.102` error**: You are likely missing the `openssl` package. Make sure you have the dependencies listed in the [requirements section](#requirements) installed properly.
