#![allow(dead_code)]
use codec::{Decode, Encode, MaxEncodedLen};
use frame_support::RuntimeDebug;
use scale_info::TypeInfo;

#[cfg(feature = "std")]
/// common structs etc, shared among the substrate-blockchain-code and the crypto-code
pub use crate::constraints::*;
/// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
/// interactions with the threshold server (eg distributing threshold shares).
pub type X25519PublicKey = [u8; 32];

// Defines a user's key visibility
// Public -> User does not hold a key shard and anyone can ask for a signature
// Permissioned -> User done not hold a key shard but only they can ask for a signature
// Private -> User holds a key shard and only they can ask for a signature
#[derive(Copy, Clone, PartialEq, Eq, RuntimeDebug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum KeyVisibility {
    Public,
    Permissioned,
    Private,
}
