# Entropy Test CLI

This is a simple CLI for testing Entropy.

## Requirements

To use it you need to have access to a deployment of the Entropy network, with at least two chain
nodes and two TSS servers.

This could be either:

- A [network deployment](https://github.com/entropyxyz/meta/wiki/New-Entropy-network-deployment-runbook), in
which case you need to specify the endpoint URI. This can be done either by setting the
`ENTROPY_DEVNET` environment variable or using the `--chain-endpoint` or `-c` command line argument.
- A [local deployment with docker compose](https://github.com/entropyxyz/meta/wiki/Local-devnet).
  When using this you don't need to specify the chain endpoint as the CLI will by default use
  `ws://localhost:9944`.

When using the local docker compose setup, be aware you need to set the TSS hostnames in your
`/etc/hosts` file by adding the lines:

```
127.0.0.1 alice-tss-server
127.0.0.1 bob-tss-server
```

## Usage

### Help

To see usage information you can run the `help` command:

`cargo run -p test-cli -- help`

You can also display help for a specific command:

`cargo run -p test-cli -- help register`

### Status

To see if you have access to a successfully configured deployment you can try the `status` command
which will list the currently registered entropy accounts:

`cargo run -p test-cli -- status`

### Register

To register an account with entropy you can use the register command with the 'account names' of the
signature request account and program modification account you would like to register.

'Account names' are a string from which to derive a substrate sr25519 keypair. They are the same as
the account names the command line tool `subkey` uses. For example the name "Alice" will give you
the same keypair as `subkey inspect //Alice` will give you. You can use `subkey inspect` to find the
seed, private key and account ID associated with a name you choose.

Note that the signature request account must be funded for this to work. On the local setup you can
use one of the [pre-endowed accounts](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/endowed_accounts.rs).

Example of registering in permissioned access mode with a program given as a binary file:

`cargo run -p test-cli -- register Alice Bob permissioned my-program.wasm`

Example of registering in private access mode, with a program given as a hash of an existing
program:

`cargo run -p test-cli -- register Alice Bob private my-program.wasm 3b3993c957ed9342cbb011eb9029c53fb253345114eff7da5951e98a41ba5ad5`

When registering with private access mode a keyshare file will be written to the current working
directory.

### Sign

The `sign` command takes a signature request 'account name' and a message to be signed.

`cargo run -p test-cli -- sign Alice 'My message to sign'`

If the program you have set takes additional auxiliary data, you can provided it as a hex encoded
string:

`cargo run -p test-cli -- sign Alice 'My message to sign' deadbeef1234`

### Update programs

The `update-programs` command is used to change the programs associated with a registered Entropy
account. It takes the 'account name' of the signature request account, and the program modification
account, and a list of programs to evaluate when signing. Programs may be given as either the path
to a .wasm binary file or hashes of existing programs.

`cargo run -p test-cli -- update-programs Alice Bob my-new-program.wasm`

Note that the program modification account must be funded for this to work.
