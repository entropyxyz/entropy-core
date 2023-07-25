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

/// Defines an application's accessibility
/// Public -> Anyone can request a signature
/// Permissioned -> Only permissioned users can request a signature
/// Private -> Requires the keyshare holder to participate in the threshold signing process
#[derive(Copy, Clone, PartialEq, Eq, RuntimeDebug, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum KeyVisibility {
    Public,
    Permissioned,
    Private,
}
