NodeJS test CLI for JS bindings to `entropy-client`

Options:
`--keypair` - a keypair given as a mnemonic or `//name` - defaults to `//Alice`
`--endpoint` - chain endpoint URL - defaults to `ws://testnet.entropy.xyz:9944`

Command examples:

`register`:
`node index.js --endpoint ws://127.0.0.1:9944 --keypair '//Bob' register`

`sign`:
`node index.js --keypair '//Charlie' sign 039ddedf4528612760a71e681642e4a83330220ebc5b45c724dc312f3b326ca176`

`store`: (store a program)
`node index.js --keypair '//Charlie' store my-program.wasm`

`accounts`: (display all registered accounts)
`node index.js accounts`
