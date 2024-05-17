# Entropy Test CLI

This is a simple CLI for testing Entropy.

Note that this client has no secure private key storage and is only intended for use with test
networks. For a fully featured command line client see [entropyxyz/cli](https://github.com/entropyxyz/cli).

## Requirements

To use it you need to have access to a deployment of the Entropy network, with at least two chain
nodes and two TSS servers.

This could be either:

- A [network deployment](https://github.com/entropyxyz/meta/wiki/New-Entropy-network-deployment-runbook), in
which case you need to specify a chain endpoint URI. This can be done either by setting the
`ENTROPY_DEVNET` environment variable or using the `--chain-endpoint` or `-c` command line argument
to for example `ws://54.175.228.156:9944`.
- A [local deployment with docker compose](https://github.com/entropyxyz/meta/wiki/Local-devnet).
  When using this you don't need to specify the chain endpoint as the CLI will by default use
  `ws://localhost:9944`.

When using the local docker compose setup, be aware you need to set the TSS hostnames in your
`/etc/hosts` file by adding the lines:

```
127.0.0.1 alice-tss-server
127.0.0.1 bob-tss-server
```

## Installation

`cargo install entropy-test-cli`

## Usage

### Account names

As this is a test client, there is no private key storage. Instead we use 'account names'. An 'account
name' is a string from which to derive a substrate sr25519 keypair. They are the same as
the account names the command line tool [`subkey`](https://docs.substrate.io/reference/command-line-tools/subkey) uses.

For example the name `Alice` will give you the same keypair as `subkey inspect //Alice` will give you.

You can use `subkey inspect` to find the seed, private key and account ID associated with a name you choose.

With this `test-cli`, giving the `//` prefix is optional. That is, `Alice` and `//Alice` are identical. Note
however that account names are case sensitive, so `//Alice` and `//alice` are different accounts.

### Help

To see usage information you can run the `help` command:

`entropy-test-cli -- help`

You can also display help for a specific command:

`entropy-test-cli -- help register`

### Status

To see if you have access to a successfully configured deployment you can try the `status` command
which will list the currently registered entropy accounts and stored programs:

`entropy-test-cli -- status`

### Register

To register an entropy account you need three things:
- An Entropy chain account name which we will call the 'program modification account'. This must be funded
  in order to submit the register transaction. On the local (docker compose) setup you can use one of the
  [pre-endowed accounts](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/endowed_accounts.rs),
  for example `Alice`.
- One or more programs, which define the conditions under which a given message will be signed by
  the Entropy network. The test-cli `register` command takes programs as either the hex-encoded hash
  of an existing program on chain, or the local path to a `.wasm` file containing the compiled
  program.
  - The [`device-key-proxy`](https://github.com/entropyxyz/programs/blob/master/examples/device-key-proxy/src/lib.rs)
    program is always available with the zero hash: `0000000000000000000000000000000000000000000000000000000000000000`.
  - The [`testing-utils`](https://github.com/entropyxyz/entropy-core/tree/master/crates/testing-utils)
    crate contains some ready to use compiled programs, the simplest of which is
    [`template_barebones.wasm`](https://github.com/entropyxyz/entropy-core/blob/master/crates/testing-utils/template_barebones.wasm)
    which allow you to sign any message which is more than 10 bytes long.
  - See the [`programs` crate](https://github.com/entropyxyz/programs) for more example programs as well as
    instructions on how to write and build your own programs.

For example, to register with `//Alice` as the signature request account and `//Bob` as the program
modification account, in permissioned access mode, using the `template_barebones` program:

`entropy-test-cli register Alice public template_barebones.wasm`

Example of registering in private access mode, with two programs, one given as a binary file and one
given as a hash of an existing program:

`entropy-test-cli register Alice private my-program.wasm 3b3993c957ed9342cbb011eb9029c53fb253345114eff7da5951e98a41ba5ad5`

When registering with private access mode, a keyshare file will be written to the directory where you
run the command. You must make subsequent `sign` commands in the same directory.

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

`entropy-test-cli store-program Alice ./crates/testing-utils/example_barebones_with_auxilary.wasm`

### Update programs

The `update-programs` command is used to change the programs associated with a registered Entropy
account. It takes the signature verifying key, and the program modification account, and a list of
programs to evaluate when signing. Programs may be given as either the path to a .wasm binary file
or hashes of existing programs.

`entropy-test-cli update-programs 039fa2a16982fa6176e3fa9ae8dc408386ff040bf91196d3ec0aa981e5ba3fc1bb Alice my-new-program.wasm`

Note that the program modification account must be funded for this to work.
