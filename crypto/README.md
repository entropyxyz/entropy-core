# Crypto
This document serves as a partial spec of this repo. 

The major crates in this repo are:
- `signing-client` - HTTP server run by all nodes
- `communication-manager` - HTTP server run by a small fraction of nodes, responsible for choosing and notifying signing parties
- `committee-leader` - HTTP server run by two nodes out of every share-committee--one as leader and one as backup--broadcasts messages to all nodes in its committee, eg, when receiving shares from new users.

The utility crates in this repo are:
- `kvdb` - An encrypted key-value datastore
- `non-substrate-common` - Common std-compatible types
- `substrate-common` - Common no-std types, which Substrate requires
- `testing-utils` - testing utility methods shared across the workspace

- `constraints` - On Thor's chopping block, to be integrated into `signing-client`

## Documentation of major APIs
At the moment, these two APIs are in progress:
- `new_user`
- `sign`

Eventually these will also be implemented:
- `update_node_set` - to be called when the active node-set changes, must reshare the stored keyshares to prevent attacks
- `delete_user` - remove a user's information from all nodes

## `new_user`
1. User calls `signing_client::who_cl` on any node, asking for the IPs of the Committee Leaders.
2. User calls `committee_leader::new_user` on each CL. The user provides a unique keyshard to each CL.
3. Each CL broadcasts the new user's keyshard (by calling `new_user`) for each node in their subcommittee.
4. (unimpl) Each node plays a verification game with each other node in their subcommittee, to validate that each node has received identical keyshares from the CL.

## `sign`
1. User calls `signing_client::who_cm` on any node, asking for the IP of the Communication Manager
2. User submits a signing request containing their message to the CM, by calling `sign_request`
3. CM chooses a signing party and broadcasts the party information, calling `new_party` on each selected signer
4. Each signer calls `subscribe` on each other signer, subscribing to all party-related messages, creating a `rocket::EventStream` of signing-related messages
5. After each signer has received subscription from each other signer, the nodes proceed to pass signing-protocol related messages until the protocol completes.
