# Release Checklist

This is instructions for creating a release candidate, which on finding it works successfully can be
tagged as the final release.

## Pre-Prep
- [ ] Inform relevant parties that you're preparing a release (e.g, by posting on Discord)
- [ ] Create a release branch, e.g., for release candidate `1`: `release/vX.Y.Z-rc.1`.

## Prep the Runtime and Node
- [ ] If runtime behaviour has changed, bump `spec_version` and set `impl_version` to `0`
- [ ] If runtime behaviour has not changed, but the implementation details have, leave `spec_version`
  as is and bump `impl_version`
- [ ] If an existing call/extrinsic has changed (new pallet index, new call index, parameter changes,
  etc.), bump `transaction_version` and bump `spec_version`
- [ ] If you're confused about what to bump, read [this](https://paritytech.github.io/polkadot-sdk/master/sp_version/struct.RuntimeVersion.html)
- [ ] Update runtime benchmarks
    - `cargo build -p entropy --release --features runtime-benchmarks && ./scripts/benchmarks.sh`
    - Note: These should ideally be run on [reference hardware](https://wiki.polkadot.network/docs/maintain-guides-how-to-validate-polkadot#reference-hardware) (i.e `c6i.4xlarge` on AWS)
- [ ] Bump `version` in TOML manifests
    - If there are breaking changes, bump the `MINOR` version, otherwise bump the `PATCH` version
- [ ] Update runtime metadata
    - `cargo run -p entropy -- --dev`
    - `./scripts/pull_entropy_metadata.sh`

## Prep the Threshold Signing Server (TSS)
- [ ] Bump `version` in TOML manifests
    - If there are breaking changes, bump the `MINOR` version, otherwise bump the `PATCH` version

## Prep the `CHANGELOG`
- [ ] Ensure `CHANGELOG` entries are up to date
    - Go through recent commit history and manually verify this
    - E.g, compare the previous release to the current `HEAD`
        - https://github.com/entropyxyz/entropy-core/compare/release/vX.X.X...master
    - Ensure headers follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)'s conventions
    - Only document user facing changes (e.g, it's fine to ignore changes to CI)
    - It's especially important that changing affecting external tooling (e.g the Entropy SDK) are
      well documented in the `CHANGELOG`
- [ ] Move entries from `[Unreleased]` header to the new version header (`[X.X.X]`)

## Release Branch and Local Network Checks
- [ ] Publish a test release tag
    - E.g `git tag test/hc/release/vX.Y.Z-rc.1 && git push origin test/hc/release/vX.Y.Z-rc.1`
- [ ] Sanity check the release using the local Docker Compose network and the `entropy-test-cli`
    - Change the `image` in `docker-compose-common.yaml` to use the published ones from above
    - Spin up the network using `docker compose up`
    - Register an account using:
        - `cargo run -p entropy-test-cli -- register \
            One public ./crates/testing-utils/template_barebones.wasm`
    - Request a signature using:
        - `cargo run -p entropy-test-cli -- sign \
            $VERIFYING_KEY "Hello, Docker Compose"`
- [ ] Open a PR targeting `master`
- [ ] Get approvals from Entropy core devs
- [ ] Merge release PR into `master`
    - Make sure nothing has gone into `master` in the meantime or you may have you repeat the
      previous steps!

## Publish Artifacts
- [ ] Ensure **all** CI checks on `master` pass
- [ ] Create a Git tag From the squashed release PR commit on `master`
    - Make sure to follow [release tag naming conventions](https://github.com/entropyxyz/meta/wiki/Release-management)
    - `git tag release/vX.Y.Z-rc.1` - meaning release candidate number 1. If all goes well this can
      later by tagged as `release/vX.Y.Z`
    - Nice to have: sign the tag with an offline GPG key (`git tag -s ...`)
- [ ] Push tag to build and publish artifacts
    - `git push origin release/vX.Y.Z-rc.1`
    - Binaries and Docker images for `entropy` and `entropy-tss` packages will be published by the
      CI (images can be found at https://hub.docker.com/u/entropyxyz)
- [ ] Publish necessary crates to crates.io
    - There is a required ordering here, e.g you cannot simply publish `entropy-tss` without first
      publishing all its dependencies

## Publish Release
- [ ] Publish a release on GitHub
    - When a release tag was pushed, a draft release was also created by the CI, use this
    - For the release body, copy the changes from the `CHANGELOG`
- [ ] Inform relevant parties (e.g, by posting on Discord)

## Promote Release Candidate
- [ ] If something turns out to not work correctly when using the release, follow this checklist
      again to make a new release candidate, e.g `release/vX.Y.Z-rc.2`
- [ ] At some point when it is clear that everything works, open a PR changing the workspace version
      numbers from `X.Y.Z-rc.N` to `X.Y.Z`
- [ ] Get approvals from one Core member and other teams (e.g DevOps and SDK)
- [ ] Follow the `Publish Artifacts` steps to make new artifacts
- [ ] Follow the `Publish Release` steps again to make a new release
