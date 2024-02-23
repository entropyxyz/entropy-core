
# Getting started

This is a quick walkthrough of how to get started with signing a message on Entropy using the [local docker compose setup](https://github.com/entropyxyz/meta/wiki/Local-devnet) and the `test-cli`.

For more details see the [test-cli readme](https://github.com/entropyxyz/entropy-core/tree/master/crates/test-cli).

All commands here should be run from the root of the [`entropy-core`](https://github.com/entropyxyz/entropy-core) repository.

## 1. Build the docker-compose setup 

This takes some time.

```bash
docker compose build
```

You may need to setup credentials for this to work. See the [instructions for docker compose](https://github.com/entropyxyz/meta/wiki/Local-devnet) and the [Entropy workstation setup](https://github.com/entropyxyz/entropy-workstation-setup) for more details, but briefly:

`~/.local/share/entropy-cryptography/.entropy.auth.sh` should contain commands to export your github token 

```sh 
#!/bin/sh
export GITHUB_TOKEN="ghp_my_github_token"
export DOCKER_HUB_RO_TOKEN="dckr_pat_my_docker_pat"
```

And you may need to setup ssh:

```bash
ssh-add ~/.ssh/my-ssh-key
eval $(ssh-agent -s)
```

Finally, you should add hostnames of the TSS servers to your `/etc/hosts` file by adding the lines:

```
127.0.0.1 alice-tss-server
127.0.0.1 bob-tss-server
```

## 2. Start the docker-compose setup

`docker compose up`

If all goes well you should now be running two Entropy chain nodes and two TSS servers.

## 3. Check things are working correctly

We will run the test-cli [`status`](https://github.com/entropyxyz/entropy-core/tree/master/crates/test-cli#status) command:

`cargo run -p test-cli -- status`

This displays a list of all registered accounts. If things were successful you should see 3 pre-registered accounts.

## 4. Register a new Entropy account

`cargo run -p test-cli -- register Alice Bob permissioned ./crates/testing-utils/example_noop.wasm`

This uses the account `//Alice` as the sigature request account, and `//Bob` as the program modification account. Both of which are [`pre-endowed accounts`](https://github.com/entropyxyz/entropy-core/blob/master/node/cli/src/endowed_accounts.rs).

This uses 'permissioned' access mode, which means only `//Alice` may make signature requests, and all keyshares are held by the TSS servers (the user themselves does not hold a keyshare).

This uses the `example_noop` program which simply signs all messages.

If this went successfully you can now run `cargo run -p test-cli -- status` again and see that there are now 4 registered accounts. The 'verifying key' field is the public secp256k1 key of the distributed keypair used to sign messages.

## 5. Sign a message

`cargo run -p test-cli -- sign Alice 'My message to sign'`

This will use your new Entropy account to sign the message.

If signing is successful, a [`RecoverableSignature`](https://docs.rs/synedrion/latest/synedrion/struct.RecoverableSignature.html)
object will be displayed containing the 64 byte secp256k1 signature encoded as hex, as well as a [`RecoveryId`](https://docs.rs/synedrion/latest/synedrion/ecdsa/struct.RecoveryId.html).
