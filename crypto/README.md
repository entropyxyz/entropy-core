# Crypto

This document serves as a partial spec of this repo.

The major actors in this repo are:

- `server`:
  - `signing-client` - HTTP endpoints run by all nodes for signing protocols
  - `communication-manager` (TO BE DEPRECATED, see note below) - AKA, the previous block's proposer. The CM is run by the previous block-proposer, and is responsible for choosing and notifying signing parties for each user signing-tx in the previous block.
    - Currently, each node must notify the communication manager what shares they hold (`send_ip_address`), after which, the CM chooses the parties.
    - After implementing Partitions, all info about which nodes hold which shares will be stored on-chain, and this call will be eliminated.
  - `partition` - (unimpl) Entropy nodes are partitioned into one of $N$ Partitions. Nodes from the same Partition have equivalent secret keyshare information.
    - To be deprecated 2022-08-26: Each Partition has a Partition Leader, who broadcasts messages to the Partition, eg., when receiving shares from new users.
    - instead: `new_user`: user contacts all nodes in the network directly with a message containing that node's share
      - why: reduces complexity, avoids issue of malicious committee leader

The utility crates in this repo are:

- `kvdb` - An encrypted key-value datastore
- `entropy-shared` - Common no-std types, which Substrate requires
- `testing-utils` - testing utility methods shared across the workspace
- `constraints` - A `whitelist` feature. On Thor's chopping block, to be integrated into `server`

## Documentation of major APIs

At the moment, these two APIs are in progress:

- `sign` (in progress)
- `new_user` (to impl after sign, includes changes to Partition)

Eventually these will also be implemented:
<!-- - `update_partition_leader` - update the node's Partition leader. -->
- `update_node_set` - to be called when the active node-set changes. Updates require resharing stored keyshares to prevent attacks.
- `delete_user` - remove a user's information from all nodes

## `new_user` - create a new user (todo)

deprecated 2022-08-26:

1. deprecate: Each Partition Leader is informed of a new user's secret keyshare by the User. User calls `partition_leader::new_user` on each CL.
2. Partition Leaders validate that each other CL received a valid keyshare.
3. Each CL broadcasts the user's secret keyshare (by calling `new_user`) to each node in their Partition.

Instead:

1. The user sends each node in the network containing a share.
2. Nodes validate that each other node in their Partition received an identical keyshare.
3. Test the share validity: one node from each partition is selected to construct a signature.

- If the signature is valid, end, post (todo: what data) new-user data on chain
- If the signature is invalid, and no node faulted, user is at fault, fail
- If the signature is invalid, and a node faulted, slash node, retry with new node from that partition

## `sign` - construct a signature to return to the user

1. User submits a transaction (`pallets::relayer::prep_transaction`) to the chain, containing a message including their substrate address and their (hashed) message.
2. A set of transactions is picked up by the next block proposer (substrate: TODO). The proposed block contains the proposed signing party information (`server/sign_init`).
3. Upon block finalization, signers read the block (substrate: TODO), containing the IP addresses of nodes who must now execute signing protocols. If a node is in a signing party, it advances to the next step.
<!-- 2. In the next block, an offchain worker is created (`pallet::propagation::offchain_worker`) -->
<!--   - currently: by each node. The communication manager waits for calls from each other node about node party information. -->
<!--   - eventually: after implementing Partitions, the communication manager will already have this information from on-chain. -->
<!-- 3. CM chooses a signing party (`communication_manager::handle_signing`) -->
<!-- 4. CM broadcasts the party information, calling `new_party` on each selected signer -->
4. Each signer calls `subscribe_to_me` on each other signer, subscribing to all party-related messages, creating a `rocket::EventStream` of signing-related messages
5. After each signer has received subscription from each other signer, the nodes proceed to pass signing-protocol related messages until the protocol completes.
6. If the signing protocol fails, the nodes broadcast information about the faulty signer, to be included in the next block. A subsequent block will designate a replacement signer (TODO: substrate).
