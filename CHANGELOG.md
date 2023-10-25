# Changelog

All notable changes to this project will be documented in this file.

## [0.0.7](https://github.com/orhun/git-cliff/compare/v0.0.6..v0.0.7) - 2023-09-22

## [0.0.6](https://github.com/orhun/git-cliff/compare/v0.0.5..v0.0.6) - 2023-09-15

### ⚙️ Miscellaneous Tasks

- User can participate in DKG (second try) ([#396](https://github.com/orhun/git-cliff/issues/396))
- User can participate in signing ([#379](https://github.com/orhun/git-cliff/issues/379))
- Dkg ([#381](https://github.com/orhun/git-cliff/issues/381))
- Add noise handshake to websocket connections for signing protocol ([#371](https://github.com/orhun/git-cliff/issues/371))
- Working proof of concept for generated API docs automatically publishable to Vercel Project. ([#373](https://github.com/orhun/git-cliff/issues/373))
- Use websockets rather than server sent events for signing protocol messages ([#364](https://github.com/orhun/git-cliff/issues/364))

## [0.0.5](https://github.com/orhun/git-cliff/compare/v0.0.2-devnet..v0.0.5) - 2023-06-23

### ⛰️  Features

- Feat: server deserializes and stores client tx reqs ([#291](https://github.com/orhun/git-cliff/issues/291))

### 🐛 Bug Fixes

- Fix toolchain version ([#344](https://github.com/orhun/git-cliff/issues/344))
- Fix signing ([#306](https://github.com/orhun/git-cliff/issues/306))
- Fix typos in readme ([#276](https://github.com/orhun/git-cliff/issues/276))
- Fix: fix sdk testing scripts to clean tss db ([#283](https://github.com/orhun/git-cliff/issues/283))
- Fix batch size error ([#259](https://github.com/orhun/git-cliff/issues/259))

### 🚜 Refactor

- Refactor tests ([#320](https://github.com/orhun/git-cliff/issues/320))
- Refactor tests ([#320](https://github.com/orhun/git-cliff/issues/320))
- Refactor ([#290](https://github.com/orhun/git-cliff/issues/290))
- Refactor substrate-common to entropy-shared ([#272](https://github.com/orhun/git-cliff/issues/272))

### ⚙️ Miscellaneous Tasks

- Replace Rocket with Axum ([#358](https://github.com/orhun/git-cliff/issues/358))
- Add curl examples to documentation of user-facing http API endpoint ([#361](https://github.com/orhun/git-cliff/issues/361))
- Improve doc comments relating to HTTP endpoints ([#351](https://github.com/orhun/git-cliff/issues/351))
- Set the Rust toolchain explicitly for this project. ([#322](https://github.com/orhun/git-cliff/issues/322))
- `/user/tx` validates user's constraints ([#300](https://github.com/orhun/git-cliff/issues/300))
- `/user/tx` starts the signing process when user submits valid EVM Transaction Request ([#299](https://github.com/orhun/git-cliff/issues/299))
- Validator key encryption ([#267](https://github.com/orhun/git-cliff/issues/267))
- Add function to rotate signing selectors ([#263](https://github.com/orhun/git-cliff/issues/263))
- Add more explicit expect errors ([#264](https://github.com/orhun/git-cliff/issues/264))

## [0.0.2-devnet](https://github.com/orhun/git-cliff/compare/v0.0.1-devnet..v0.0.2-devnet) - 2022-12-16

### 🚜 Refactor

- Refactor: remove unused deps ([#224](https://github.com/orhun/git-cliff/issues/224))


### ⚙️ Miscellaneous Tasks

- Add is syncing in  ([#254](https://github.com/orhun/git-cliff/issues/254))
- Sig error refactor ([#220](https://github.com/orhun/git-cliff/issues/220))
- Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/orhun/git-cliff/issues/207))
- Fix CI pipeline ([#223](https://github.com/orhun/git-cliff/issues/223))
- Add scripts for running devnet ([#222](https://github.com/orhun/git-cliff/issues/222))
- Fix CI pipeline ([#223](https://github.com/orhun/git-cliff/issues/223))
- Upgrade Substrate to follow Polkadot releases ([#207](https://github.com/orhun/git-cliff/issues/207))

## [0.0.1-devnet] - 2022-10-26

### 🐛 Bug Fixes

- Fix tests ([#170](https://github.com/orhun/git-cliff/issues/170))

- Fix: refactor substrate<>client types; fix master ([#155](https://github.com/orhun/git-cliff/issues/155))
- Fix: solve unknown media type warning ([#154](https://github.com/orhun/git-cliff/issues/154))
- Fix non deterministic tests ([#145](https://github.com/orhun/git-cliff/issues/145))
- Fix benchmark builds ([#60](https://github.com/orhun/git-cliff/issues/60))

### ⚙️ Miscellaneous Tasks

- Free TX - council can update free tx per era, fixed benchmarks ([#177](https://github.com/orhun/git-cliff/issues/177))
- CI speedups ([#171](https://github.com/orhun/git-cliff/issues/171))
- Crypto-signing-client: spec rest of flow & remove unnec. common crate ([#166](https://github.com/orhun/git-cliff/issues/166))
* Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/orhun/git-cliff/issues/164))
- Fix master -- misc warnings and errors not caught in previous PR's ([#164](https://github.com/orhun/git-cliff/issues/164))
- Conditional ci ([#152](https://github.com/orhun/git-cliff/issues/152))
- Crypto comm manager ([#153](https://github.com/orhun/git-cliff/issues/153))
- fix non deterministic tests ([#145](https://github.com/orhun/git-cliff/issues/145))
- Add CircleCI configuration ([#142](https://github.com/orhun/git-cliff/issues/142))
- Add starter CircleCI configuration ([#141](https://github.com/orhun/git-cliff/issues/141))
- Clean up and DRY up CircleCI configuration ([#143](https://github.com/orhun/git-cliff/issues/143))
- Fix CircleCI config ([#146](https://github.com/orhun/git-cliff/issues/146))
- Add no_output_timeout: 45m ([#148](https://github.com/orhun/git-cliff/issues/148))
- Fix syntax on timeout clause ([#149](https://github.com/orhun/git-cliff/issues/149))
- Remove tofnd add kvdb ([#147](https://github.com/orhun/git-cliff/issues/147))
- Lint Crypto ([#138](https://github.com/orhun/git-cliff/issues/138))
- Austin retreat  ([#99](https://github.com/orhun/git-cliff/issues/99))
- Crypto protospec ([#84](https://github.com/orhun/git-cliff/issues/84))
- store json key ([#88](https://github.com/orhun/git-cliff/issues/88))
- Crypto protospec ([#89](https://github.com/orhun/git-cliff/issues/89))
- Store keys ([#90](https://github.com/orhun/git-cliff/issues/90))
- cli separated ([#92](https://github.com/orhun/git-cliff/issues/92))
