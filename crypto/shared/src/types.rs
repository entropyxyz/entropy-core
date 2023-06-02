#![allow(dead_code)]
use codec::{alloc::vec::Vec, Decode, Encode};
use node_primitives::BlockNumber;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use schemars::JsonSchema;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
pub use crate::constraints::*;

/// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
/// interactions with the threshold server (eg distributing threshold shares).
pub type X25519PublicKey = [u8; 32];

/// body of a signature generation request by the user to the entropy network
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, JsonSchema))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct SigRequest {
    /// sig_hash. this is a hash of the message to be signed
    pub sig_hash: codec::alloc::vec::Vec<u8>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize, JsonSchema))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: codec::alloc::vec::Vec<u8>,
    pub tss_account: codec::alloc::vec::Vec<u8>,
}

/// The message sent from pallets::propagation::post() to the signing-client.
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, JsonSchema))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct Message {
    pub sig_request: SigRequest,
    pub account: codec::alloc::vec::Vec<u8>,
    pub validators_info: Vec<ValidatorInfo>,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct OCWMessage {
    pub messages: Vec<Message>,
    pub block_number: BlockNumber,
}
