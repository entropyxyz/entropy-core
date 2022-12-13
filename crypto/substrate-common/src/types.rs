#![allow(dead_code)]
/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize as DeserializeDerive, Serialize as SerializeDerive};
use sp_std::vec::Vec;

/// RegistrationMessage holds the information sent by the User to the extropy-network during
/// account-registration
#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, TypeInfo)]
pub struct RegistrationMessage {
    // ToDo: TypeInfo marco only works for basic types out of the box.
    // Out of the box it does not work for types like SecretKey or PublicKey
    // TypeInfo needs to be implemented for these types.
    // see https://github.com/entropyxyz/entropy-core/issues/29

    // /// Session ID/nonce. Check that this ID has not beed used before
    // /// This will be 0 for account creation.
    // sid: u32,
    // /// PublicKey of the user's master-key
    // pub pub_group_key: PublicKey,
    // /// PublicKey of the user's secret keyshare
    // pub user_public_key: PublicKey,
    // /// ToDo testnet: polynomial commitments of the polynomial that created the keyshares
    // /// These are necessary so that nodes can verify their keyshare
    // poly_commitments: u16;
    // // ToDo testnet: ConstraintSet: alternativeley, a default ConstraintSet will always be
    // loaded at account creation
    pub keyshards: u128, /* this will be Vec<FieldElements>, where FieldElements are BigInt mod
                          * Order, i.e. \mathbb{Z_q} */
    pub test: u128,
}

/// The response message that a node sends to the User in response to calling the
/// relayer::register() extrinsic.
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct RegistrationResponse {
    // ToDo_DF: what Data goes into here?
    /// list of endpoints of all nodes that the user sends the keyshares to.
    // ToDo: make this a vec<(endpoint, encryption-key)> etc.
    pub signing_nodes: u16,
}

/// body of a signature generation request by the user to the entropy network
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct SigRequest {
    /// sig_hash. this is a hash of the message to be signed
    pub sig_hash: codec::alloc::vec::Vec<u8>,
}

#[derive(Clone, Encode, Debug, Decode, Eq, PartialEq, TypeInfo)]
pub struct SigResponse {
    /// List of indices of the signing-nodes that are randomly chosen
    /// necessary info:
    /// - index of the node's keyshare
    /// maybe:
    /// - node-identifier: endpoint address or some PublicKey (which one?)
    // hierhier
    //
    // pub signing_nodes: Vec<u16>,
    pub signing_nodes: codec::alloc::vec::Vec<u16>,
    /// endpoint of the Communication manager
    pub com_manager: u16,
}

// /// The message sent from pallets::propagation::post() to the signing-client.
// TODO(TK): rename to PropagationMessage
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct Message {
    pub sig_request: SigRequest,
    pub account: codec::alloc::vec::Vec<u8>,
    pub ip_addresses: codec::alloc::vec::Vec<codec::alloc::vec::Vec<u8>>,
}

/// Supported architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub enum Arch {
    EVM,
    BTC,
}

/// Represents either an allow or deny list.
pub enum ACL {
    Allow,
    Deny,
}

/// An AccessControl constraint (Allow/Deny lists).
/// acl is the vector of allowed or denied addresses.
/// acl_type represents if the constraint is either allow/deny.
pub struct ACLConstraint<A: Architecture> {
    pub acl: Vec<A::Address>,
    pub acl_type: ACL,
    pub allow_null_recipient: bool,
}

/// Trait that defines types for the architecture for a transaction.
pub trait Architecture: Serialize + for<'de> Deserialize<'de> {
    /// Account type for that chain(SS58, H160, etc)
    type Address: Eq + Serialize + for<'de> Deserialize<'de>;
    type TransactionRequest: HasSender<Self>
        + HasReceiver<Self>
        + Serialize
        + for<'de> Deserialize<'de>;
}

/// Trait for getting the the sender of a transaction.
pub trait HasSender<A: Architecture + ?Sized> {
    fn sender(&self) -> Option<A::Address>;
}

/// Trait for getting the the receiver of a transaction.
pub trait HasReceiver<A: Architecture + ?Sized> {
    fn receiver(&self) -> Option<A::Address>;
}

/// Trait for getting the Arch of a transaction.
pub trait HasArch {
    fn arch() -> Arch;
}

/// Basic transaction that has a sender and receiver with single accounts.
#[derive(Default, Debug, Clone, PartialEq, SerializeDerive, DeserializeDerive)]
pub struct BasicTransaction<A: Architecture> {
    pub from: Option<A::Address>,
    pub to: Option<A::Address>,
}
