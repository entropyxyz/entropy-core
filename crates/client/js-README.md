# `entropy-client`

This is JS bindings for a basic client library for [Entropy](https://entropy.xyz).

For a full featured client library you probably want the [SDK](https://www.npmjs.com/package/@entropyxyz/sdk).

## A note on using this on NodeJS

This expects to have access to the browser websockets API, which is not present on NodeJS. To use
this on NodeJS you must have the dependency [`ws`](https://www.npmjs.com/package/ws) as a property
of the `global` object like so:

```js
Object.assign(global, { WebSocket: require('ws') })
```

This is tested with `ws` version `^8.14.2`.
