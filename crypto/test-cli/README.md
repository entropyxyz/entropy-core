
# Entropy Test CLI

This is a simple CLI for testing Entropy.

## Requirements

To use it you need to have access to a deployment of the Entropy network, with at least two chain
nodes and two TSS servers.

This could be either:

- A [devnet deployment](https://github.com/entropyxyz/meta/wiki/New-Entropy-network-deployment-runbook), in
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
the account names the command line tool `subkey` uses. For example the name "Alice" or will give you
the same keypair as `subkey inspect //Alice` will give you. You can use `subkey inspect` to find the
seed, private key and account ID associated with a name you choose.

Note that the signature request account must be funded for this to work. On the local setup you can
use one of the [pre-endowed accounts](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/endowed_accounts.rs).

`cargo run -p test-cli -- register Alice Bob`

By default, this will register with public access mode, and use a test program.

For private access mode, with a given program binary file:

`cargo run -p test-cli -- register Alice Bob private my-program.wasm`

When registering with private access mode a keyshare file will be written to the directory where you
run the command.

### Sign

The `sign` command takes a signature request 'account name' and a message to be signed.

`cargo run -p test-cli -- sign Alice 'My message to sign'`

If the program you have set takes additional auxiliary data, you can provided it as a hex encoded
string:

`cargo run -p test-cli -- sign Alice 'My message to sign' deadbeef1234`

### Update program

The `update-program` command is used to change the program associated with a registered Entropy
account. It takes the 'account name' of the signature request account, and the program modification
account, as well as the path to a .wasm file with the new program:

`cargo run -p test-cli -- update-program Alice Bob my-new-program.wasm`

Note that the program modification account must be funded for this to work.
