# Release Checklist

## Pre-Prep
- [] Inform relevant parties that you're preparing a release (e.g, by posting on Discord)
- [] Create a release branch (e.g `hc-release-v0.0.X`)

## Prep the Runtime and Node
- [] Bump `spec_version`
- [] Bump `impl_version`
- [] Bump `transaction_version`
- [] Update runtime benchmarks
- [] Bump `version` in TOML manifests
    - For crates with `publish = false`, bump `PATCH` version
    - For crates with `publish = true`, bump based off [SemVer](https://semver.org/)
- [] Update runtime metadata

## Prep the Threshold Signing Server (TSS)
- [] Bump `version` in TOML manifests
    - For crates with `publish = false`, bump `PATCH` version
    - For crates with `publish = true`, bump based off [SemVer](https://semver.org/)

## Prep the `CHANGELOG`
- [] Ensure `CHANGELOG` entries are up to date
    - Go through recent commit history and manually verify this
    - Ensure headers follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)'s conventions
    - It's especially important that anything that breaks external tooling (e.g the Entropy SDK) is
      well documented in the `CHANGELOG`
- [] Move entries from `[Unreleased]` header to the new version header (`[0.0.X]`)

## Merge Release Branch
- [] Open a PR targetting `master`
- [] Get approvals from Entropy core devs
- [] Merge release PR into `master`

## Publish Artifacts and Release
- [] Ensure **all** CI checks on `master` pass
- [] Create a Git tag, following [release tag naming conventions](https://github.com/entropyxyz/meta/wiki/Release-management)
    - `git tag release/v0.0.X`
    - Nice to have: sign the tag with an offline GPG key (`git tag -s ...`)
- [] Push tag to build and publish artifacts
    - `git push origin release/v0.0.X`
    - Binaries and Docker images for `entropy` and `server` packages will be published by the CI
- [] Publish necessary crates to crates.io
- [] Publish a release on GitHub
    - When a release tag was pushed, a draft release was also created by the CI, use this
    - For the release body, copy the changes from the `CHANGELOG`
- [] Inform relevant parties (e.g, by posting on Discord)
