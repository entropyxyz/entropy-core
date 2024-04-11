# `entropy-protocol`

Protocol execution and transport logic for the Entropy signing, DKG, and proactive refresh
protocols.

For explanations of the JS bindings see [`./js-README.md`](./js-README.md)

## Compiling for wasm:

To check that things compile correctly for wasm:

```bash
make build-nodejs
```

## Running Nodejs tests:

To run tests for JS bindings to the `sign_and_encrypt` api:
```bash
make build-nodejs-testing
cd nodejs-test
yarn
yarn test
```
If you have issues when re-running these tests following changes, remove `nodejs-test/node_modules`
before re-running `yarn`.

For instructions on running entropy-tss integration test using JS bindings to the user private mode
signing and DKG functions, see
[`../threshold-signature-server/README.md`](../threshold-signature-server/README.md)
