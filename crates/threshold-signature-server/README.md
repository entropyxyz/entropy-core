# `entropy-tss`

The threshold signature server which stores keyshares and executes the Entropy protocols.

## Running integrations tests for the JS bindings to the `entropy-protocol` private user API

```bash
cd crates/protocol
make build-nodejs-testing
cd nodejs-test
yarn
cd ../../..
cargo test -p entropy-tss --release -F wasm_test test_wasm
```

If you have issues when re-running these tests following changes, remove `nodejs-test/node_modules`
before re-running `yarn`.
