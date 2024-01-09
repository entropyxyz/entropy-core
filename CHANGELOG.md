# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

At the moment this project **does not** adhere to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes
- In [#561](https://github.com/entropyxyz/entropy-core/pull/561) several crates were renamed in order to ensure consistent naming across the repo.
  The most impactful of these is that the `server` binary is now the `entropy-tss` binary. From this
  it follows that the Docker images previously published under `entropyxyz/server` are now being
  published under `entropyxyz/entropy-tss`.
- In [#536](https://github.com/entropyxyz/entropy-core/pull/536/), the registered struct no longer holds a program but rather a hash of a program that is set in the set_program function
- When executing the signing protocol on the client-side, a `sig-uid` no longer needs to be given as
  an argument ([#549](https://github.com/entropyxyz/entropy-core/pull/549))
- Wasm API to entropy-protocol uses camelCase function names ([#566](https://github.com/entropyxyz/entropy-core/pull/566))
- Wasm API to functions formerly in the x25515chacha20poly1305 repo also now have camelCase function names ([#563](https://github.com/entropyxyz/entropy-core/pull/563))
- Register and change program pointer interface changed to accept a vecotor of programs. As well pass an index for which containts the hashing code if it custom hashing ([#568](https://github.com/entropyxyz/entropy-core/pull/568))
- If a user is sending additive data through it now needs to be in a vector and the index needs to match up with where the program pointer is in the program pointer vector. ([#577](https://github.com/entropyxyz/entropy-core/pull/577))

### Added
- Test CLI which calls the same code as in integration tests ([#417](https://github.com/entropyxyz/entropy-core/pull/417))
- Pointer for Programs ([#536](https://github.com/entropyxyz/entropy-core/pull/536/))
- Add password file option ([#555](https://github.com/entropyxyz/entropy-core/pull/555))
- Include contents of x25515chacha20poly1305 repo in entropy-protocol ([#563](https://github.com/entropyxyz/entropy-core/pull/563))
- Custom Hashing Algorithms [#553](https://github.com/entropyxyz/entropy-core/pull/553/)

### Changed
- Crate name refactor ([#561](https://github.com/entropyxyz/entropy-core/pull/561))
- Only run wasm integration tests when a feature is enabled ([#565](https://github.com/entropyxyz/entropy-core/pull/565))
- Protocol sessions are now identified by a `SessionID` type rather than a `String`
  ([#549](https://github.com/entropyxyz/entropy-core/pull/549))
- Change bip39 implementation ([#562](https://github.com/entropyxyz/entropy-core/pull/562))
- Additive programs ([#568](https://github.com/entropyxyz/entropy-core/pull/568))
- Additional `hash` field in `/sign_tx` JSON body indicates which hashing algorithm to use for signing ([#553](https://github.com/entropyxyz/entropy-core/pull/553))
- Additive aux data ([#577](https://github.com/entropyxyz/entropy-core/pull/577))

### Removed
- Remove pallet-helpers ([#581](https://github.com/entropyxyz/entropy-core/pull/581/))

## [0.0.9](https://github.com/entropyxyz/entropy-core/compare/release/v0.0.8..release/v0.0.9) - 2023-11-30

Some of the noteworthy changes related to this release are related to better integration in Web
Assembly contexts, and improvements to logging for the Threshold Signature Server.

Certain key components related to distributed key generation (DKG) are now able to be compiled to
Wasm. This opens up the possiblity for users to participate in DKG themselves from the browser!

There are changes around how logging in the `server` binary is done. When running the binary users
can now choose the type of output they would like to see (e.g `--logger json`), and can even send
their logs to a [Loki](https://grafana.com/oss/loki/) server (`--loki`) for aggregation and
visualization.

### Breaking Changes

- In [#475](https://github.com/entropyxyz/entropy-core/pull/475/), in the JSON body of the
  `/sign_tx` endpoint the `preimage` field has been renamed to `message`. It remains a hex-encoded
  `string`.

### Added
- Wasm bindings for user to participate in DKG and signing protocols ([#414](https://github.com/entropyxyz/entropy-core/pull/414/))
- Auxiliary data for program evaluation ([#475](https://github.com/entropyxyz/entropy-core/pull/475/))
- Add a keyshare type for wasm which wraps `synedrion::KeyShare` ([#512](https://github.com/entropyxyz/entropy-core/pull/512/))
- Add versioning to server ([#516](https://github.com/entropyxyz/entropy-core/pull/516/))
- Cross-compile for `linux/arm64` and push multi-platform Docker images. ([#518](https://github.com/entropyxyz/entropy-core/pull/518/))
- Allow logger to be configured from CLI ([#520](https://github.com/entropyxyz/entropy-core/pull/520/))
- Add `bunyan` JSON formatter ([#524](https://github.com/entropyxyz/entropy-core/pull/524/))
- Add Loki logging layer ([#528](https://github.com/entropyxyz/entropy-core/pull/528/))

### Changed
- Validate proactive refresh endpoint ([#483](https://github.com/entropyxyz/entropy-core/pull/483/))
- No proactive refresh on private key visibility ([#485](https://github.com/entropyxyz/entropy-core/pull/485/))
- Use bincode rather than JSON for protocol and subscribe messages ([#492](https://github.com/entropyxyz/entropy-core/pull/492/))
- Allow big protocol messages ([#495](https://github.com/entropyxyz/entropy-core/pull/495/))
- Change `SocketAddr` type for `String` ([#496](https://github.com/entropyxyz/entropy-core/pull/496/))
- Partition proactive refresh ([#504](https://github.com/entropyxyz/entropy-core/pull/504/))
- Add `#[tracing::instrument]` macro to routes ([#515](https://github.com/entropyxyz/entropy-core/pull/515/))
- Make `server` a library, and add integration test for testing protocol crate on wasm ([#517](https://github.com/entropyxyz/entropy-core/pull/517/))
- Remove subxt-signer from server and entropy-protocol ([#526](https://github.com/entropyxyz/entropy-core/pull/526/))
- `ec-runtime` now errors for zero-sized programs ([#529](https://github.com/entropyxyz/entropy-core/pull/529/))
- `entropy-protocol` - polkadot-js compatible sr25519 key generation for wasm API ([#533](https://github.com/entropyxyz/entropy-core/pull/533/))

### Fixed
- Return package version instead of rustc version ([#523](https://github.com/entropyxyz/entropy-core/pull/523/))

## [0.0.8](https://github.com/entropyxyz/entropy-core/compare/v0.0.7..release/v0.0.8) - 2023-11-06

### Breaking Changes

There are a few breaking changes in this release, mostly related to the APIs around Programs
(formerly Constraints).

Some notables changes introduced in [#428](https://github.com/entropyxyz/entropy-core/pull/428),
[#433](https://github.com/entropyxyz/entropy-core/pull/433), and
[#451](https://github.com/entropyxyz/entropy-core/pull/451) are:

- The Constraint pallet's `update_v2_constraints` extrinsic has been renamed to `update_program`.
    - The extrinsic arguments remain unchanged
- The Constraint pallet's `ConstraintsV2Updated` event has been renamed to `ProgramUpdated` and now
  has two fields instead of a single tuple for its body
- The Constraint pallet's `V2ConstraintLengthExceeded` error has been renamed to `ProgramLengthExceeded`
- The Relayer pallet's `register` extrinsic now takes a `Vec<u8>` as a program instead of an
  `Option<Contraints>`
- The Constraints pallet has been renamed to the Programs pallet
- The `entropy-constraints` crate has been removed

### Added
- Separate `entropy-protocol` crate with protocol execution logic ([#404](https://github.com/entropyxyz/entropy-core/pull/404))
- Proactive refresh ([#413](https://github.com/entropyxyz/entropy-core/pull/413))
- Write a Dockerfile that can build both `entropy` and `server`. ([#430](https://github.com/entropyxyz/entropy-core/pull/430))
- Developer experience improvements: SSH auth from workstations, entirely local "devnet"
  functionality with Compose ([#434](https://github.com/entropyxyz/entropy-core/pull/434))
- Allow local host pass for offchain url ([#443](https://github.com/entropyxyz/entropy-core/pull/443))
- Add way for validators to resolve diff verifying keys ([#460](https://github.com/entropyxyz/entropy-core/pull/460))
    - This introduces a new `FailedRegistration` event which might be of interest to consumers of this
      pallet.
- Add `prune_registration` extrinsic ([#472](https://github.com/entropyxyz/entropy-core/pull/472))
    - Allows for accounts to be moved out of registering state (e.g if DKG fails).
    - This introduces a new `RegistrationCancelled` event which might be of interest to consumers of
      this pallet.

### Changed
- Replace outdated `--ws-external` with `--rpc-external` ([#424](https://github.com/entropyxyz/entropy-core/pull/424))
- Ensure correct validator order by using ValidatorInfo from chain rather than from user ([#425](https://github.com/entropyxyz/entropy-core/pull/425))
- Place `demo_offence` dispatchable behind root origin check ([#426](https://github.com/entropyxyz/entropy-core/pull/426))
- Update `pallet-relayer` to use Contraints V2 ([#433](https://github.com/entropyxyz/entropy-core/pull/433))
- Rename `pallet-constraints` to `pallet-programs` ([#451](https://github.com/entropyxyz/entropy-core/pull/451))
- Add way for validators to resolve diff verifying keys ([#460](https://github.com/entropyxyz/entropy-core/pull/460))
- Fix socket address type ([#469](https://github.com/entropyxyz/entropy-core/pull/469))

### Removed
- Remove `is_swapping` from registration details ([#437](https://github.com/entropyxyz/entropy-core/pull/437))
- Remove V1 constraints from `pallet_constraints` ([#428](https://github.com/entropyxyz/entropy-core/pull/428))

### Fixed
- Ensure correct validator order by using ValidatorInfo from chain rather than from user ([#425](https://github.com/entropyxyz/entropy-core/pull/425))
- Take a storage deposit for programs during registration ([#447](https://github.com/entropyxyz/entropy-core/pull/447))

## [0.0.7](https://github.com/entropyxyz/entropy-core/compare/v0.0.6..v0.0.7) - 2023-09-22

## [0.0.6](https://github.com/entropyxyz/entropy-core/compare/v0.0.5..v0.0.6) - 2023-09-15

### ⚙️ Miscellaneous Tasks

- User can participate in DKG (second try) ([#396](https://github.com/entropyxyz/entropy-core/pull/396))
- User can participate in signing ([#379](https://github.com/entropyxyz/entropy-core/pull/379))
- Dkg ([#381](https://github.com/entropyxyz/entropy-core/pull/381))
- Add noise handshake to websocket connections for signing protocol ([#371](https://github.com/entropyxyz/entropy-core/pull/371))
- Working proof of concept for generated API docs automatically publishable to Vercel Project. ([#373](https://github.com/entropyxyz/entropy-core/pull/373))
- Use websockets rather than server sent events for signing protocol messages ([#364](https://github.com/entropyxyz/entropy-core/pull/364))

## [0.0.5](https://github.com/entropyxyz/entropy-core/compare/v0.0.2-devnet..v0.0.5) - 2023-06-23

### ⛰️  Features

- Feat: server deserializes and stores client tx reqs ([#291](https://github.com/entropyxyz/entropy-core/pull/291))

### 🐛 Bug Fixes

- Fix toolchain version ([#344](https://github.com/entropyxyz/entropy-core/pull/344))
- Fix signing ([#306](https://github.com/entropyxyz/entropy-core/pull/306))
- Fix typos in readme ([#276](https://github.com/entropyxyz/entropy-core/pull/276))
- Fix: fix sdk testing scripts to clean tss db ([#283](https://github.com/entropyxyz/entropy-core/pull/283))
- Fix batch size error ([#259](https://github.com/entropyxyz/entropy-core/pull/259))

### 🚜 Refactor

- Refactor tests ([#320](https://github.com/entropyxyz/entropy-core/pull/320))
- Refactor tests ([#320](https://github.com/entropyxyz/entropy-core/pull/320))
- Refactor ([#290](https://github.com/entropyxyz/entropy-core/pull/290))
- Refactor substrate-common to entropy-shared ([#272](https://github.com/entropyxyz/entropy-core/pull/272))

### ⚙️ Miscellaneous Tasks

- Replace Rocket with Axum ([#358](https://github.com/entropyxyz/entropy-core/pull/358))
- Add curl examples to documentation of user-facing http API endpoint ([#361](https://github.com/entropyxyz/entropy-core/pull/361))
- Improve doc comments relating to HTTP endpoints ([#351](https://github.com/entropyxyz/entropy-core/pull/351))
- Set the Rust toolchain explicitly for this project. ([#322](https://github.com/entropyxyz/entropy-core/pull/322))
- `/user/tx` validates user's constraints ([#300](https://github.com/entropyxyz/entropy-core/pull/300))
- `/user/tx` starts the signing process when user submits valid EVM Transaction Request ([#299](https://github.com/entropyxyz/entropy-core/pull/299))
- Validator key encryption ([#267](https://github.com/entropyxyz/entropy-core/pull/267))
- Add function to rotate signing selectors ([#263](https://github.com/entropyxyz/entropy-core/pull/263))
- Add more explicit expect errors ([#264](https://github.com/entropyxyz/entropy-core/pull/264))

## [0.0.2-devnet](https://github.com/entropyxyz/entropy-core/compare/v0.0.1-devnet..v0.0.2-devnet) - 2022-12-16

### 🚜 Refactor

- Refactor: remove unused deps ([#224](https://github.com/entropyxyz/entropy-core/pull/224))

### ⚙️ Miscellaneous Tasks

- Add is syncing in  ([#254](https://github.com/entropyxyz/entropy-core/pull/254))
- Sig error refactor ([#220](https://github.com/entropyxyz/entropy-core/pull/220))
- Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/entropyxyz/entropy-core/pull/207))
- Fix CI pipeline ([#223](https://github.com/entropyxyz/entropy-core/pull/223))
- Add scripts for running devnet ([#222](https://github.com/entropyxyz/entropy-core/pull/222))
- Fix CI pipeline ([#223](https://github.com/entropyxyz/entropy-core/pull/223))
- Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/entropyxyz/entropy-core/pull/207))

## [0.0.1-devnet] - 2022-10-26

### 🐛 Bug Fixes

- Fix tests ([#170](https://github.com/entropyxyz/entropy-core/pull/170))
- Fix: refactor substrate<>client types; fix master ([#155](https://github.com/entropyxyz/entropy-core/pull/155))
- Fix: solve unknown media type warning ([#154](https://github.com/entropyxyz/entropy-core/pull/154))
- Fix non deterministic tests ([#145](https://github.com/entropyxyz/entropy-core/pull/145))
- Fix benchmark builds ([#60](https://github.com/entropyxyz/entropy-core/pull/60))

### ⚙️ Miscellaneous Tasks

- Free TX - council can update free tx per era, fixed benchmarks ([#177](https://github.com/entropyxyz/entropy-core/pull/177))
- CI speedups ([#171](https://github.com/entropyxyz/entropy-core/pull/171))
- Crypto-signing-client: spec rest of flow & remove unnec. common crate ([#166](https://github.com/entropyxyz/entropy-core/pull/166))
* Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/entropyxyz/entropy-core/pull/164))
- Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/entropyxyz/entropy-core/pull/164))
- Conditional ci ([#152](https://github.com/entropyxyz/entropy-core/pull/152))
- Crypto comm manager ([#153](https://github.com/entropyxyz/entropy-core/pull/153))
- fix non deterministic tests ([#145](https://github.com/entropyxyz/entropy-core/pull/145))
- Add CircleCI configuration ([#142](https://github.com/entropyxyz/entropy-core/pull/142))
- Add starter CircleCI configuration ([#141](https://github.com/entropyxyz/entropy-core/pull/141))
- Clean up and DRY up CircleCI configuration ([#143](https://github.com/entropyxyz/entropy-core/pull/143))
- Fix CircleCI config ([#146](https://github.com/entropyxyz/entropy-core/pull/146))
- Add no_output_timeout: 45m ([#148](https://github.com/entropyxyz/entropy-core/pull/148))
- Fix syntax on timeout clause ([#149](https://github.com/entropyxyz/entropy-core/pull/149))
- Remove tofnd add kvdb ([#147](https://github.com/entropyxyz/entropy-core/pull/147))
- Lint Crypto ([#138](https://github.com/entropyxyz/entropy-core/pull/138))
- Austin retreat  ([#99](https://github.com/entropyxyz/entropy-core/pull/99))
- Crypto protospec ([#84](https://github.com/entropyxyz/entropy-core/pull/84))
- store json key ([#88](https://github.com/entropyxyz/entropy-core/pull/88))
- Crypto protospec ([#89](https://github.com/entropyxyz/entropy-core/pull/89))
- Store keys ([#90](https://github.com/entropyxyz/entropy-core/pull/90))
- cli separated ([#92](https://github.com/entropyxyz/entropy-core/pull/92))
