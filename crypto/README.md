# Crypto
This document serves as a partial spec of this repo.
nts: previous block author is this round's CM
if I'm not the CM, then:  

The major crates in this repo are:
- `signing-client` - HTTP endpoints run by all nodes for signing protocols
- `communication-manager` - AKA, the previous block's proposer. The CM is run by the previous block-proposer, and is responsible for choosing and notifying signing parties for each user signing-tx in the previous block.
  - Currently, each node must notify the communication manager what shares they hold (`send_ip_address`), after which, the CM chooses the parties.
  - After implementing Committees, all info about which nodes hold which shares will be stored on-chain, and this call will be eliminated. 
- `committee` - (unimpl) Entropy nodes are partitioned into one of **5** committees. Nodes from the same committee have equivalent secret keyshard information. Each committee has a Committee Leader, who broadcasts messages to the committee, eg., when receiving shares from new users.

The utility crates in this repo are:
- `kvdb` - An encrypted key-value datastore
- `non-substrate-common` - Common std-compatible types
- `substrate-common` - Common no-std types, which Substrate requires
- `testing-utils` - testing utility methods shared across the workspace

- `constraints` - On Thor's chopping block, to be integrated into `signing-client`

## Documentation of major APIs
At the moment, these two APIs are in progress:
- `new_user` (to impl after sign, includes changes to committee API)
- `sign` (in progress)

Eventually these will also be implemented:
- `update_node_set` - to be called when the active node-set changes, must reshare the stored keyshares to prevent attacks
- `delete_user` - remove a user's information from all nodes

## `new_user` (unimpl)
2. User calls `committee_leader::new_user` on each CL. The user provides a unique keyshard to each CL.
3. Each CL broadcasts the new user's keyshard (by calling `new_user`) for each node in their subcommittee.
4. (unimpl) Each node plays a verification game with each other node in their subcommittee, to validate that each node has received identical keyshares from the CL.

## `sign`
1. User submits a transaction (`relayer::prep_transaction`) to the chain, containing a message including their substrate address and their (hashed) message.
2. In the next block, an offchain worker is created (`pallet::propagation::offchain_worker`)
  - currently: by each node. The communication manager waits for calls from each other node about node party information.
  - eventually: after implementing Committees, the communication manager will already have this information from on-chain.
3. CM chooses a signing party (`communication_manager::handle_signing`)
4. CM broadcasts the party information, calling `new_party` on each selected signer
5. Each signer calls `subscribe` on each other signer, subscribing to all party-related messages, creating a `rocket::EventStream` of signing-related messages
6. After each signer has received subscription from each other signer, the nodes proceed to pass signing-protocol related messages until the protocol completes.
