# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### ⚙️ Miscellaneous Tasks

- Separate `entropy-protocol` crate with protocol execution logic ([#404](https://github.com/orhun/git-cliff/issues/404))

### Things which have moved to the `entropy-protocol` crate:
- `PartyId`
- `RecoverableSignature`
- `KeyParams`
- `ValidatorInfo`
- `ProtocolMessage`

and the `protocol-transport` and `execute-protocol` modules.

### Significant changes:

`sp-core` does not compile to wasm. So we use `subxt` for `AccountId32` and `subxt-signer` for sr25519 signing. Unfortunately `subxt-signer`'s `Keypair` does not allow us direct access to the private key, which we use to generate an x25519 keypair with `derive-static-secret`. So we still use `sp-core::sr25519::Pair` in order to get x25519 keypairs, and theres currently no way to do this on the client side.

### Commits: 

* entropy-protocol crate

* entropy-user-protocol crate

* Add needed dependencies

* Errors

* Protocol transport module

* Execute protocol fns

* Top level lib.rs

* Lockfile

* Fmt

* Rm half-baked user-protocol crate

* Begin refactor of server

* Refactor signing client

* Refactor server

* Update entropy-protocol api

* Refactor kvdb

* Dependencies

* Refactor

* Update server tests

* taplo

* Update dependencies for compiling for wasm

* Rm entropy-constraints as dependency

* Taplo

* Add wasm feature to entropy-shared

* Use wasm feature

* Lockfile

* Avoid using subxt whereever possilbe

* With server feature, include everything for protocol

* Simplify features

* Use subxt_signer and subxt::utils::AccountId32

* Testing-utils should use subxt::utils::AccountId32

* Server uses subxt_signer and subxt::utils::AccountId32 when interfacing with entropy-protocol

* shared has wasm feature flag

* Clippy

* Fix feature flags for entropy-shared

* Fix derive macros for entropy-shared types

* Clippy

* Fix tests

* Rm println

* Fix tests

* rename module for clarity

* bump CI to nightly-2023-06-15

* bump rust version in Makefile

* Tidy Cargo.toml

* Add tracing, add doccomments

* Comments and tidying

* Rm unused files

* Tidy server

* Rm comments - ([9ac98b5](https://github.com/orhun/git-cliff/commit/9ac98b5a0391dccde74539927c29861fc544a39b))

## [0.0.7](https://github.com/orhun/git-cliff/compare/v0.0.6..v0.0.7) - 2023-09-22

## [0.0.6](https://github.com/orhun/git-cliff/compare/v0.0.5..v0.0.6) - 2023-09-15

### ⚙️ Miscellaneous Tasks

- User can participate in DKG (second try) ([#396](https://github.com/orhun/git-cliff/issues/396))

* Get key visibility during user registration

* Pass x25519 pk during user registration

* Update pallet tests

* Update substrate metadata

* Expect x25519 pk during registration

* fmt

* Update relayer benchmarking

* Update relayer benchmarking

* pass users x25519 pk

* Doccomment / fn name

* Refactor test helper fn

* Add test helper fn for user paritipating in DKG

* Fmt

* User participates in DKG test

* Clippy

* new_user runs DKG in a separate task in order to be able to respond early

* Update store_share test to wait to confirm that the user is registered before checking for a stored share

* Tidy

* Propagation pallet should only call user/new when someone registered

* Fmt

* Update propagation pallet test

* private KeyVisibilty includes x25519 public key

* Update relayer pallet to only require x25519 public key with private key visibility

* Update chain_spec

* Update chain metadata

* Update propagation pallet test

* Update server

* Fmt

* Update relayer benchmarking

* Rm test annotation that was there by accident - ([990fbe6](https://github.com/orhun/git-cliff/commit/990fbe67de01c9ae8b6afb4c7425602d3b308754))
- User can participate in signing ([#379](https://github.com/orhun/git-cliff/issues/379))

* If key visibility is private, assume the user will connect and participate in signing

* Clippy says that do_signing now takes too many args, so pass app_state as a single argument

* Make fns needed by the tests for user to participate in signing public

* WIP add test for user participates in signing

* WIP Improve test fn for user participates in signing

* Comments

* WIP call user participates in signing helper fn from test (failing)

* Remove check that connecting party is in the user transaction request - as the user themselves is not in the list

* Fmt

* If key visibility is private, add user to list of verifiers passed to execute_protocol

* Fix parsing of sig_hash - user participates test now passes for happy case

* Listener tracks x25519 public keys of validators so we can check them when connecting to validators

* Clippy

* Listener takes Vec<ValidatorInfo> rather than a UserTransactionRequest, to make it more generic

* Rm unused field for Listener

* Improve test for user participating by checking signatures match

* Improve error handling in user_participates test helper fn

* Improve error handling in user_participates test helper fn

* Rename variable for clarity

* fmt

* Fixes following merge with master

* spawn_testing_validators helper function should optionally create a share for the user

* Rm unused test helper function - ([13d7f3f](https://github.com/orhun/git-cliff/commit/13d7f3f5cce77cb63498f931503ee6d0d971f49e))
- Dkg ([#381](https://github.com/orhun/git-cliff/issues/381))

* setup chain for dkg

* add on init pruning

* update listener struct

* setup listener for dkg

* integrate open protocol connection to dkg

* add in channels to dkg

* skeleton new_user

* validate new_user endpoint

* finish validation

* add receive key endpoint

* add send key

* recieve key tests

* test send key

* add validation to send and recieve keys

* execute dkg

* add validator info to dgk ocw

* refactor ocw data type

* fix tests compilation

* dkg working ish

* checks if in registration group

* confirm register

* remove unwraps

* more tests

* clean

* working tests

* fix tests

* lint

* fix benchmarks

* remove a dbg

* change node run scripts

* lint

* update synedrion

* fix tests

* docs

* clean

* remove swapping code

* remove swapping code

---------

Co-authored-by: jesse <jesse@entropy.wxy> - ([d5ce3b3](https://github.com/orhun/git-cliff/commit/d5ce3b3eb5cda61b14857322d8e30eb573d4d05a))
- Add noise handshake to websocket connections for signing protocol ([#371](https://github.com/orhun/git-cliff/issues/371))

* Add snow to dependencies

* Add noise handshake WIP

* Rm commented code in test

* Rm logging

* Reponder checks remote pk on handshaking

* Factor noise stuff into separate fn

* Factor noise stuff into separate module

* Mv EncryptedWsConnection struct to noise mod

* Error handling

* Update test with attempted noise handshake from bogus party

* Clippy

* Fmt

* Error handling

* mv EncryptedConnectionError to errors mod

* Handle bad incoming subscribe message error case

* Add check that account id matches that in SignedMessage

* Rm unused error variants - ([afa670a](https://github.com/orhun/git-cliff/commit/afa670a1657651fe6c4499c6e80e8cf57368bba2))
- Working proof of concept for generated API docs automatically publishable to Vercel Project. ([#373](https://github.com/orhun/git-cliff/issues/373))

* Re-include the `target/doc` directory into the Git repository.

In addition to providing a bit more organization and clarity around
which filesystem paths are excluded from version control, this change
also ensures that the single `doc/` subdirectory within the `target/`
directory is included in commits. This is done to test whether we can
generate API documentation automatically while ensuring it remains local
to the code that it is documenting.

* Ensure the `target/doc` directory exists in the repository.

This is used simply to ensure that we can track the "empty" `target/doc`
directory as part of the repository contents. We want this included
because the directory is the root directory of automatically generated
API documentation for the project, used by downstream consumers.

* Wrap the Vercel Project's `installCommand` into a Makefile target.

Vercel Projects require that installation commands for their deployments
are no longer than 256 characters, yet we need a bit more in order to
actually build the project and generate API documentation on their build
image, which is an Amazon Linux 2 base. This commit wraps the install
command I've developed into a Makefile target so that we can simply use
a command such as `make vercel-api-docs` in the Vercel Project settings.

* Vercel doesn't provide a `sudo` command. Sad pandas. Let's just try.

* Install `clang-libs` dependency for Amazon Linux 2 in Vercel, too.

* Try with `clang-devel` as well to solve `stdarg.h` file not found.

* Use `rustup` instead of the Amazon Linux extras to install Rust.

* On Vercel, `$HOME` is weird, try not requiring it.

* Fix "home mismatch" error during `rustup` installation forcibly.

This deals with a quirk in the Vercel.com build image where the `HOME`
environment variable is set differently from the result of calling the
functions `getpwuid(geteuid())` like how the `rustup` installer does.

Here we simply create a new `.PHONY` target to install `rustup` for any
Vercel image differently, but retains generic installation usage of it
so other recipes can reuse the actual Rust installation as a prereq.

See also:

* https://github.com/rust-lang/rustup/issues/1884

* Replace `.gitkeep` with a nicer "API docs homepage."

* The only file we need in the `target/doc` directory is the `index.html`.

* Create a Vercel-specific build profile that optimizes for small size.

* Let `rustup` manage all tools in Vercel environment. Silences warnings.

* Build standard library with the Rust nightly we're using.

* Format `Cargo.toml` file to pass lint checks with `taplo fmt`.

* Move the complexity of the build command to the Makefile.

* Switch out PAT in favor of SSH deploy key. - ([deab798](https://github.com/orhun/git-cliff/commit/deab798e02b358d6987e528b47a774e8aed2ee85))
- Use websockets rather than server sent events for signing protocol messages ([#364](https://github.com/orhun/git-cliff/issues/364))

* WIP add websockets for signing protocol

* Use websockets instead of server sent events

* Error handle bad subscribe messages. Tests now pass locally.

* Taplo

* Error handling

* Refactor, errors

* Check that connecting users are part of the signing committee

* Use a wrapper over the two websocket connection types so we can have one function handle both incoming and outgoing connections.

* Variable name, rm comments

* Decide whether to connect by comparing account IDs, add an extra check that X25519 public keys are correct

* Rm unused import

* Add timeout for waiting for connections, add test for bogus connection

* Rename subscribe to protocol_transport, add doc comments - ([c73494d](https://github.com/orhun/git-cliff/commit/c73494dc68a407c3f944d10bfb12e0dce3aa1092))

## [0.0.5](https://github.com/orhun/git-cliff/compare/v0.0.2-devnet..v0.0.5) - 2023-06-23

### ⛰️  Features

- Feat: server deserializes and stores client tx reqs ([#291](https://github.com/orhun/git-cliff/issues/291))

* feat: server deserializes client tx reqs

* fmt

* feat: /tx logic

* fmt

* clippy

* clippy2

* clippy

* taplo

* fxed test

* test: test /user/tx endpoint with unsafe tests

* fmt

* cleanup

* update cicd

* fix install service

* fix: add todos for enc/auth and fix cicd image versioning

* fmt

* added negative test for parsing evm rlp tx

* fmt

* add testing script

* removed new script - ([dc4ac5d](https://github.com/orhun/git-cliff/commit/dc4ac5d4ab746778acac1c913f0e98765174c7b2))

### 🐛 Bug Fixes

- Fix toolchain version ([#344](https://github.com/orhun/git-cliff/issues/344))

 - ([37afd8d](https://github.com/orhun/git-cliff/commit/37afd8d3b23afe79dbf619d1c0353a0cf4df249a))
- Fix signing ([#306](https://github.com/orhun/git-cliff/issues/306))

* fix signing

* fix - ([156ad67](https://github.com/orhun/git-cliff/commit/156ad6741eb997e850e3f0e51ba4b5d26e5e7e3a))
- Fix typos in readme ([#276](https://github.com/orhun/git-cliff/issues/276))

* fix typos in readme

* Capitalize first word in lists - ([e1e460e](https://github.com/orhun/git-cliff/commit/e1e460eb9bafd0fc13eb90b12927c2677d11fe44))
- Fix: fix sdk testing scripts to clean tss db ([#283](https://github.com/orhun/git-cliff/issues/283))

 - ([5e790bb](https://github.com/orhun/git-cliff/commit/5e790bb597d896593a4ff5126d58a902c17dc1d7))
- Fix batch size error ([#259](https://github.com/orhun/git-cliff/issues/259))

* fix batch size error

* lint

* clippy - ([0fea755](https://github.com/orhun/git-cliff/commit/0fea755705c7557b872cec7bb608dfefe3e34133))

### 🚜 Refactor

- Refactor tests ([#320](https://github.com/orhun/git-cliff/issues/320))

 - ([14deb05](https://github.com/orhun/git-cliff/commit/14deb05d40e023190a1dede092726b48f29dd4f0))
- Refactor tests ([#320](https://github.com/orhun/git-cliff/issues/320))

 - ([77ca141](https://github.com/orhun/git-cliff/commit/77ca141e43977e335b69591ef315a4458a37d1f6))
- Refactor ([#290](https://github.com/orhun/git-cliff/issues/290))

* refactor

* remove unused deps

* fix tests

* remove duplicate test code - ([13afc77](https://github.com/orhun/git-cliff/commit/13afc774e951475e593ad31df1d40dfb87a4e49c))
- Refactor substrate-common to entropy-shared ([#272](https://github.com/orhun/git-cliff/issues/272))

This PR modifies the `substrate-common` package:

- refactors/renames all "substrate-common" and "substrate_common" to "entropy-shared" and "entropy_shared"
- updates crypto/entropy-types/README.md
- removes a few unused structs from that package

It also makes a small change to `entropy-constraints` Cargo.toml for properly handling std and no_std, unrelated to above
 - ([b99b054](https://github.com/orhun/git-cliff/commit/b99b054e15e80df9c644dad2b3e148e832d4fd18))

### ⚙️ Miscellaneous Tasks

- Replace Rocket with Axum ([#358](https://github.com/orhun/git-cliff/issues/358))

* first route working

* user migration

* migrate validator endpoints

* signing minus subscribe to me

* migrate unsafe

* subscribe to me

* add tracing

* heatlhz tests

* unsafe tests

* validator tests

* signing_cli tests

* signing tests

* add cors

* unhardcode endpoint

* add warn unsafe

* refactor

* refactor tests

* bump ed25519

* lint

* remove rocket

* fix unwrap issue

* fix scripts

---------

Co-authored-by: jesse <jesse@entropy.wxy> - ([ee0493c](https://github.com/orhun/git-cliff/commit/ee0493cf0e873e3a1f80b6b614cfd682838f19c8))
- Add curl examples to documentation of user-facing http API endpoint ([#361](https://github.com/orhun/git-cliff/issues/361))

* Add curl examples

* fmt curl examples - ([ba2261e](https://github.com/orhun/git-cliff/commit/ba2261e4eb8d047bba957360baac28196dc50eb6))
- Improve doc comments relating to HTTP endpoints ([#351](https://github.com/orhun/git-cliff/issues/351))

* Update doc comment description of routes

* Update doc comment description of routes with links

* Update doc comments with description of http request payloads

* Top level doc comment for signing client

* Categorise endpoints in doc comments

* Add logo to docs

* Add signer/drain to list of routes in doc comments

* Escape square bracket characters in unsafe api docs to keep rustdoc from complaining

* Broken link in top level README

* Add unsafe api routes to list of routes in doc comments

* Fixes to doccomment links to keep rustdoc from giving warnings

* Fix CI by checking out .circleci/then.yml from master

* cargo fmt - ([eb91461](https://github.com/orhun/git-cliff/commit/eb914613c40c3fa4af0116319fd6b1fb5647d425))
- Set the Rust toolchain explicitly for this project. ([#322](https://github.com/orhun/git-cliff/issues/322))

 - ([71fd9e3](https://github.com/orhun/git-cliff/commit/71fd9e3869723044481efbda8d7933d2088e75fb))
- `/user/tx` validates user's constraints ([#300](https://github.com/orhun/git-cliff/issues/300))

* /tx starts signing process; tests

* fmt

* removed prontlns for debugging

* cleanup1

* more cleanup

* cleaned up code, minus commented out code

* cleaned up

* fmt

* updated .gitignore

* updates

* fmt

* fmt

* taplo

* set cicd nightly to same version as substrate master

* cli warning

* fmt

* WIP

* dank macros that solve our shit

* feat: integration test for /user/tx (dirty)

* fmt

* added negative tests

* cleanup

* fmt

* updated tests constraints

* fmt and clippy

* taplo

* remove test flag

* added back test flag

* fmt

* fix test and fmt

* update logging

* clippy

* fmt

* docs: updated README about testing

* feat: pr review fixes

* lint: fmt

* lint: clippy

* fmt

* lint: fix clippyy

* feat: added additional null test for acl constraints

* lint

* removed unused constraints code

* fmt

* clippy

* feat: address PR comments - ([0dc8265](https://github.com/orhun/git-cliff/commit/0dc8265f419569482065b7f311e451c128be3ed7))
- `/user/tx` starts the signing process when user submits valid EVM Transaction Request ([#299](https://github.com/orhun/git-cliff/issues/299))

* /tx starts signing process; tests

* fmt

* removed prontlns for debugging

* cleanup1

* more cleanup

* cleaned up code, minus commented out code

* cleaned up

* fmt

* updated .gitignore

* updates

* fmt

* fmt

* taplo

* set cicd nightly to same version as substrate master

* cli warning

* fmt - ([cbcb108](https://github.com/orhun/git-cliff/commit/cbcb1083795f744aa04ebe2a68ec47c4fe81ad7c))
- Validator key encryption ([#267](https://github.com/orhun/git-cliff/issues/267))

* end-to-end encryption between validators

* SafeCryptoError: Add tests for server validation

* fix accidental asn1 encoding; remove k256

* Renaming, and error handling.

* fix fmt

---------

Signed-off-by: John Sahhar <john@entropy.xyz>
Co-authored-by: jakehemmerle <jakehemmerle@protonmail.com> - ([57caef3](https://github.com/orhun/git-cliff/commit/57caef385fd28cbd554f9a44547feaadd447a0d0))
- Add function to rotate signing selectors ([#263](https://github.com/orhun/git-cliff/issues/263))

* add function to rotate signing selectors

* fix test

* add in syncing check

* benchmarks

* clean

* fmt

* remove duplicated code

Co-authored-by: jakehemmerle <jakehemmerle@protonmail.com> - ([b2bc5aa](https://github.com/orhun/git-cliff/commit/b2bc5aaef296d40a6576d0d0fbbb01c558fd4814))
- Add more explicit expect errors ([#264](https://github.com/orhun/git-cliff/issues/264))

 - ([fb5f0d0](https://github.com/orhun/git-cliff/commit/fb5f0d0757028e597621572c47bbf4d186ab5e92))

## [0.0.2-devnet](https://github.com/orhun/git-cliff/compare/v0.0.1-devnet..v0.0.2-devnet) - 2022-12-16

### 🚜 Refactor

- Refactor: remove unused deps ([#224](https://github.com/orhun/git-cliff/issues/224))

* refactor: remove unused deps

Signed-off-by: John Sahhar <john@entropy.xyz> - ([9424165](https://github.com/orhun/git-cliff/commit/94241657f98b6b6a8b91deac63fd6cd7064c8d6a))

### ⚙️ Miscellaneous Tasks

- Add is syncing in  ([#254](https://github.com/orhun/git-cliff/issues/254))

* add in on chain elements

* fix benchamark script

* extra substrate functions

* fmt

* fix test

* clippy ignore weights

* comments

* clippy all

* fix clippy

* clippy

* fmt - ([22a2919](https://github.com/orhun/git-cliff/commit/22a2919d0e0a2a584fe6319ba776f2c10694c8ed))
- Sig error refactor ([#220](https://github.com/orhun/git-cliff/issues/220))

* remove most unwraps

* remove more unwraps

* fmt

* Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/orhun/git-cliff/issues/207))

* PR #201 key association logic; to be reverted

* Revert "PR #201 key association logic; to be reverted"

This reverts commit 44a3ed2317e528284318a499f7930f08a0d37631.

* added types and comments for readability and clarity in staking-extension

* subxt points to temp branch with updated deps

* refactored server sp_core stuff to use subxt::ext::sp_core

* updated server to use subxt 0.24.0 (from 0.20.0)

* BROKEN: updated substrate to polkadot-v0.9.30 and jakehemmerle subxt

* update Event and Call to RuntimeEvent and RuntimeCall

* fix pallet-free-tx weights

* fix pallet-transaction-pause weights

* fix pallet-staking-extension weights

* updated mock runtimes and tests

still needs updated free-tx test since FRAME tx are transactional by default

* upgraded pallet-free-tx to substrate-polkadot 0.9.30

* pallets are all updated

* entropy-runtime tests pass with runtime-benchmarks

* handled client rpc and service...?

* entropy compiles and tests

* additional refactoring

* added entropy-executor

* entropy tests pass with runtime-benchmarks

* fixed testing-utils

* thanks jesse, fixed server, everything works

* clippy pt 1

* clippy pt 2

* fixing tests

* reenable extensions

* fixed a test

* updated runtime metadata

* added babe and grandpa to rpc

* jesse rocks; fixed subxt Config

* fmt

* clippy

* taplo

* fmt and clippy

* clippy

* updated deps

* updates

* Fix CI pipeline ([#223](https://github.com/orhun/git-cliff/issues/223))

fix-ci-pipeline

Signed-off-by: John Sahhar <john@entropy.xyz>

Signed-off-by: John Sahhar <john@entropy.xyz>

* Add scripts for running devnet ([#222](https://github.com/orhun/git-cliff/issues/222))

Signed-off-by: John Sahhar <john@entropy.xyz>

* Create a recoverable signature

* remove most unwraps

* fmt

* remove mutex unwraps

* fmt

Signed-off-by: John Sahhar <john@entropy.xyz>
Co-authored-by: Jake Hemmerle <jakehemmerle@protonmail.com>
Co-authored-by: ok-john <john@entropy.xyz>
Co-authored-by: Bogdan Opanchuk <bogdan@opanchuk.net> - ([5609011](https://github.com/orhun/git-cliff/commit/56090117e4bb75aee5d6996a78ad99864bf1e671))
- Fix CI pipeline ([#223](https://github.com/orhun/git-cliff/issues/223))

fix-ci-pipeline

Signed-off-by: John Sahhar <john@entropy.xyz>

Signed-off-by: John Sahhar <john@entropy.xyz> - ([56ed8f9](https://github.com/orhun/git-cliff/commit/56ed8f91ae880363c20eadd0ab2d4ee4411e8817))
- Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/orhun/git-cliff/issues/207))

* PR #201 key association logic; to be reverted

* Revert "PR #201 key association logic; to be reverted"

This reverts commit 44a3ed2317e528284318a499f7930f08a0d37631.

* added types and comments for readability and clarity in staking-extension

* subxt points to temp branch with updated deps

* refactored server sp_core stuff to use subxt::ext::sp_core

* updated server to use subxt 0.24.0 (from 0.20.0)

* BROKEN: updated substrate to polkadot-v0.9.30 and jakehemmerle subxt

* update Event and Call to RuntimeEvent and RuntimeCall

* fix pallet-free-tx weights

* fix pallet-transaction-pause weights

* fix pallet-staking-extension weights

* updated mock runtimes and tests

still needs updated free-tx test since FRAME tx are transactional by default

* upgraded pallet-free-tx to substrate-polkadot 0.9.30

* pallets are all updated

* entropy-runtime tests pass with runtime-benchmarks

* handled client rpc and service...?

* entropy compiles and tests

* additional refactoring

* added entropy-executor

* entropy tests pass with runtime-benchmarks

* fixed testing-utils

* thanks jesse, fixed server, everything works

* clippy pt 1

* clippy pt 2

* fixing tests

* reenable extensions

* fixed a test

* updated runtime metadata

* added babe and grandpa to rpc

* jesse rocks; fixed subxt Config

* fmt

* clippy

* taplo

* fmt and clippy

* clippy

* updated deps

* updates - ([651399e](https://github.com/orhun/git-cliff/commit/651399e22cc22523f2115380212bd99b31daa8dd))

## [0.0.1-devnet] - 2022-10-26

### 🐛 Bug Fixes

- Fix tests ([#170](https://github.com/orhun/git-cliff/issues/170))

* fix tests

* fmt

* remove duplicate code

* fmt

* nightly fmt

* fmt - ([1439195](https://github.com/orhun/git-cliff/commit/1439195e202788c4689ba7325ad6bb54f2a60013))
- Fix: refactor substrate<>client types; fix master ([#155](https://github.com/orhun/git-cliff/issues/155))

* fix: refactor substrate<>client types; fix master

* fix: `go fmt && cargo clippy && taplo fmt` in crypto dirs

* simplify workspace members
 - ([67e7695](https://github.com/orhun/git-cliff/commit/67e769513f9b337da776dab8b18a48b7d6db963f))
- Fix: solve unknown media type warning ([#154](https://github.com/orhun/git-cliff/issues/154))

removes an unsilenceable Rocket warning
https://github.com/SergioBenitez/Rocket/issues/1188 - ([1eb21ad](https://github.com/orhun/git-cliff/commit/1eb21adb768f7e91fb170a088c26624f4e01f54f))
- Fix non deterministic tests ([#145](https://github.com/orhun/git-cliff/issues/145))

 - ([e4b5331](https://github.com/orhun/git-cliff/commit/e4b5331b8da0d20e128fe81d85da1cf9acf0b20f))
- Fix benchmark builds ([#60](https://github.com/orhun/git-cliff/issues/60))

 - ([c162ea1](https://github.com/orhun/git-cliff/commit/c162ea1b2fefa8a7c4707515f6ee65333e7809fd))

### 🚜 Refactor

- Refactor
 - ([da5829e](https://github.com/orhun/git-cliff/commit/da5829ebe7fc529e160d359001d7e42825c18d3c))

### ⚙️ Miscellaneous Tasks

- Free TX - council can update free tx per era, fixed benchmarks ([#177](https://github.com/orhun/git-cliff/issues/177))

* feat: council can update number of free tx users get per era

* feat: free-tx fixed benches - ([d12dea4](https://github.com/orhun/git-cliff/commit/d12dea4480e0e0bf6efab6a9a36f8998ad1e7d41))
- CI speedups ([#171](https://github.com/orhun/git-cliff/issues/171))

* 2x-> x, release removed (testing ci speed)

* run ci in node

* run ci in node

* toggle release

* tmp

* remove build from node test

* try out nextest

* bugfix nextest

* move stuff

* build n test

* normal test

* release added back

* release removed

* revert nextest

* final

* try w/out release per jesse's sugg

* testing robustness

* fmt

* rm-tmp

* rmv debug in testing-utils - ([68876da](https://github.com/orhun/git-cliff/commit/68876daf04484ccf13b438ae597287ea52eadd42))
- Crypto-signing-client: spec rest of flow & remove unnec. common crate ([#166](https://github.com/orhun/git-cliff/issues/166))

* clippy fix

* move store_share to new_party in api

* formatting misc

* Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/orhun/git-cliff/issues/164))

* clippy fix

* fix eq

* clippy fix

* clippy fix --broken-code

* fix clippy warnings

* all to 2xlarge see if this fixed ci

* ignore know-how-to-mock

* rewiring for greater compat w/ tofnd

* kill context

* kill non-substrate-common

* clean aftermath

* silence warnings and formatall

* formatall

* user moved into own mod - ([5357390](https://github.com/orhun/git-cliff/commit/53573908c84e7ec4ed78e626029ebea2a71ad94e))
- Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/orhun/git-cliff/issues/164))

* clippy fix

* fix eq

* clippy fix

* clippy fix --broken-code

* fix clippy warnings

* all to 2xlarge see if this fixed ci

* ignore know-how-to-mock - ([1404c3f](https://github.com/orhun/git-cliff/commit/1404c3fbef94e1f6b6c460a2353d9ef324d91bd5))
- Conditional ci ([#152](https://github.com/orhun/git-cliff/issues/152))

 - ([005af44](https://github.com/orhun/git-cliff/commit/005af44ffe4f79891b08783c3508c8962d74e1cd))
- Crypto comm manager ([#153](https://github.com/orhun/git-cliff/issues/153))

* license_and_registration

* signing_registration

* lint

* signing_registration move dynamics

* new party refactor

* rx_channels

* better

* rx channels blocker: how get streamed messages from reqwest?

* minor refactor

* minor lints

* cleaning

* silence warnings

* call it new_party

* lint imports

* bytestream

* tracing

* remove ips

* format

* clean up main

* flesh out handle_sign

* update-structure

* move initpartyinfo, signingParty into own module

* move subscribe into ip_disc, fmt

* holding-commit: how shall I type streams?

* lol that worked

* lol that worked

* fix filter

* fix filter

* fmt

* fmt

* fix shit

* install events

* dependencies reduced

* temp

* refactor up to blocker: merging streams

* still blocked on streams, pause

* subscribe written

* clippy, minor refactor of subscriber

* move subscriber to own module

* fmt

* fix non deterministic tests ([#145](https://github.com/orhun/git-cliff/issues/145))

* Add CircleCI configuration ([#142](https://github.com/orhun/git-cliff/issues/142))

* Add starter CircleCI configuration ([#141](https://github.com/orhun/git-cliff/issues/141))

* Clean up and DRY up CircleCI configuration ([#143](https://github.com/orhun/git-cliff/issues/143))

* Clean up and DRY up config

* Fix env vars (doesn't work)

* trigger build

Co-authored-by: Kara Graysen <kara@noisypigeon.me>
Co-authored-by: Kara Graysen <kara@noisypigeon.inc>

* Fix CircleCI config ([#146](https://github.com/orhun/git-cliff/issues/146))

Fix path

* Add no_output_timeout: 45m ([#148](https://github.com/orhun/git-cliff/issues/148))

* Fix syntax on timeout clause ([#149](https://github.com/orhun/git-cliff/issues/149))

Fix syntax

* Remove tofnd add kvdb ([#147](https://github.com/orhun/git-cliff/issues/147))

* compiles

* encrypted sled tests

* kv tests

* fmt

* tweak tests

* fmt

* fix compile

* forgot to actually remove tofnd lol

* move kvdb to own lib

* fmt

* fmt

* Cargo fmt

* fix-tokio-deps: add sync

* hit that taplo fmt one more time

Co-authored-by: thor <thorck@protonmail.com>

* clippy, fix merge errors

* them streams be merged

* clean-up subscribe_to_party

* taplo.toml added. crypto formatted

* subscriber sanized

* qfix, notes on sanitized party info

* subscriber notes

* move kv-manager into state, stub cached-info

* fix merge issues

* ignore

* separated c-manager from signing-client

* fix tests

* fix c_manager script (formerly sig_client.sh)

* change weird route

Co-authored-by: JesseAbram <33698952+JesseAbram@users.noreply.github.com>
Co-authored-by: Rhu <103735902+heyitsrhu@users.noreply.github.com>
Co-authored-by: Kara Graysen <kara@noisypigeon.me>
Co-authored-by: Kara Graysen <kara@noisypigeon.inc>
Co-authored-by: JesseAbram <jesseabramowitz@hotmail.com> - ([6a2304c](https://github.com/orhun/git-cliff/commit/6a2304c8e8863fd1f1ec8c3b8c81a1251e3c9ae5))
- Lint Crypto ([#138](https://github.com/orhun/git-cliff/issues/138))

* several lints

* copy paste tofnd

* signing

* init_sign stub

* execute

* results

* only 15 errors

* SILENCE! warnings minimized.

* remove testing user clients

* central-keygen api

* signing-client

* rename for consistency, fix CI

* fix tests

* update ci

* formatting, lint

* qfix ci

Co-authored-by: JesseAbram <jesseabramowitz@hotmail.com> - ([e50e43b](https://github.com/orhun/git-cliff/commit/e50e43bbd4eb0f1ff8846583eabf79682c13a70b))
- Austin retreat  ([#99](https://github.com/orhun/git-cliff/issues/99))

* init protocol repo commit

* block: Zeroize compile bug

* resolve zeroize-derive dependency issue

* skeleton: keygen and signing

* WIP: add extrinsic to user::send_tx()

* add comments

* ' add comment'

* update subxt

* add common package

* change relayer from lindell17 to common

* add conditional std attribute to common

* close #68

- change module common to package module

* add send_registration(), struct SigRequest

* close #72

* Delete etp-lindell17 directory

* WIP: testing extrinsics

* pallet relayer: unify account_registration and register()
- add input to register()
- change account_registration() to register()

* add testing-user-clients to call extrincics in CLI

* mess with node to signing-client communication

- add OCWMessage to crypto/common and use that in the noes
- relayer::post() sends only 1 message, not messages

* Crypto protospec ([#84](https://github.com/orhun/git-cliff/issues/84))

* setup clap CLI

* keygen async setup from Clap

* keygen async

* typechecks pass

* yoink, structopt

* reorg subdirs

* sm-manager

* keygen + signing - compilation errors

* pending keygen ownership bug

* async ownership bugfix

* fix signing-client decoding

* minor changes

* fix last merge: refactor protocol::user

* move common.rs into its own package

* add SigResponse to relayer::events::TransactionPropagated

* store json key ([#88](https://github.com/orhun/git-cliff/issues/88))

* store json key

* refactor

* to do fix

* add wait_for_finalized_success() to request_sig_gen()

- when receiving a result, result.find_first_event requires wait_for_finalized_success()
- request_sig_gen() returns SigResponse

* Crypto protospec ([#89](https://github.com/orhun/git-cliff/issues/89))

* setup clap CLI

* keygen async setup from Clap

* keygen async

* typechecks pass

* yoink, structopt

* reorg subdirs

* sm-manager

* keygen + signing - compilation errors

* pending keygen ownership bug

* async ownership bugfix

* blocking: handling error on 6 of 7 keygen

* keygen bug documented

* Store keys ([#90](https://github.com/orhun/git-cliff/issues/90))

* store json key

* refactor

* to do fix

* alice send

* add sign_message() to User

* cli separated

* cli separated ([#92](https://github.com/orhun/git-cliff/issues/92))

* add fn sign_message() and a test to run it

* integration

* add scripts to run 2 signing-clients locally

* work on registration

* fix scripts/alice.sh and scripts/bob.sh

* add send() to registration

* remove main.rs in alice-send

* unbreak wrap cli

* registration complete

* user await sign()

* add gg20-sm-manager's routines to signing-client

* fix sm-manager in signing-client

* add println!() for debugging

* copy local-share1.json to root

- this key needs to be in the root for the current testnet setup
- the other key local-share2.json is copied to root in the User registration

* change Rocket.toml settings

* - add logs

* adjust signing-client for node1

* change order of SignCli::sign_cli.parties

- changed from vec![1,2] to vec![2,1]
- THIS made the signature generation possible. WHY?
- change for user and signing-node

* add testnet instructions to README.md

* update README.md

* comment changes

* tests

* fmt

* todo

* event docs

* pipeline

* update README.md

* remove start_com_manager()

- Design change: The communication manager is now always running instead of being called when necessary.

* remove unused code

* build fix

* fix non compilation

* fmt

* build fix

Co-authored-by: Thor <thorck@protonmail.com>
Co-authored-by: davfra <64629389davfra@users.noreply.github.com>
Co-authored-by: David <818daf@gmail.com>
Co-authored-by: Thor <7041313+thor314@users.noreply.github.com>
Co-authored-by: davfra <64629389+davfra@users.noreply.github.com> - ([4baf10a](https://github.com/orhun/git-cliff/commit/4baf10a3fe5ed14d4db931db9682ed3f8f5a3fbe))

<!-- generated by git-cliff -->
