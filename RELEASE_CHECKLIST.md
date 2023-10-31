# Release Checklist

## Pre-Prep
- [] Inform relevant parties that you're preparing a release (e.g, by posting on Discord)
- [] Create a release branch (e.g `hc-release-vX.X.X`)

## Prep the Runtime and Node
- [] If runtime behaviour has changed, bump `spec_version` and set `impl_version` to `0`
- [] If runtime behaviour has not changed, but the implementation details have, leave `spec_version`
  as is and bump `impl_version`
- [] If an existing call/extrinsic has changed (new pallet index, new call index, parameter changes,
  etc.), bump `transaction_version` and bump `spec_version`
- [] If you're confused about what to bump, read [this](https://paritytech.github.io/polkadot-sdk/master/sp_version/struct.RuntimeVersion.html)
- [] Update runtime benchmarks
    - `cargo build -p entropy --release && ./scripts/benchmarks.sh`
- [] Bump `version` in TOML manifests
    - For crates with `publish = false`, bump `PATCH` version
    - For crates with `publish = true`, bump based off [SemVer](https://semver.org/)
- [] Update runtime metadata
    - `cargo run -p entropy -- --dev && ./scripts/pull_entropy_metadata.sh`

## Prep the Threshold Signing Server (TSS)
- [] Bump `version` in TOML manifests
    - For crates with `publish = false`, bump `PATCH` version
    - For crates with `publish = true`, bump based off [SemVer](https://semver.org/)

## Prep the `CHANGELOG`
- [] Ensure `CHANGELOG` entries are up to date
    - Go through recent commit history and manually verify this
    - Ensure headers follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)'s conventions
    - Only document user facing changes (e.g, it's fine to ignore changes to CI)
    - It's especially important that changing affecting external tooling (e.g the Entropy SDK) are
      well documented in the `CHANGELOG`
- [] Move entries from `[Unreleased]` header to the new version header (`[X.X.X]`)

## Merge Release Branch
- [] Open a PR targeting `master`
- [] Get approvals from Entropy core devs
- [] Merge release PR into `master`

## Publish Artifacts and Release
- [] Ensure **all** CI checks on `master` pass
- [] Create a Git tag, following [release tag naming conventions](https://github.com/entropyxyz/meta/wiki/Release-management)
    - `git tag release/vX.X.X`
    - Nice to have: sign the tag with an offline GPG key (`git tag -s ...`)
- [] Push tag to build and publish artifacts
    - `git push origin release/vX.X.X`
    - Binaries and Docker images for `entropy` and `server` packages will be published by the CI
- [] Publish necessary crates to crates.io
- [] Publish a release on GitHub
    - When a release tag was pushed, a draft release was also created by the CI, use this
    - For the release body, copy the changes from the `CHANGELOG`
- [] Inform relevant parties (e.g, by posting on Discord)
