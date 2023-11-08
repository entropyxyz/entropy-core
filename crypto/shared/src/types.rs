#![allow(dead_code)]
#[cfg(not(feature = "wasm"))]
use codec::alloc::vec::Vec;
use codec::{Decode, Encode, MaxEncodedLen};
#[cfg(feature = "wasm-no-std")]
use frame_support::RuntimeDebug;
#[cfg(not(feature = "wasm"))]
use node_primitives::BlockNumber;
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

/// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
/// interactions with the threshold server (eg distributing threshold shares).
pub type X25519PublicKey = [u8; 32];

/// Defines an application's accessibility
/// Public -> Anyone can request a signature
/// Permissioned -> Only permissioned users can request a signature
/// Private -> Requires the keyshare holder to participate in the threshold signing process
#[cfg_attr(not(feature = "wasm-no-std"), derive(Debug))]
#[cfg_attr(feature = "wasm-no-std", derive(RuntimeDebug))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialEq, Eq, Encode, Decode, TypeInfo, MaxEncodedLen)]
pub enum KeyVisibility {
    Public,
    Permissioned,
    Private(X25519PublicKey),
}

/// Information from the validators in signing party
#[cfg(not(feature = "wasm"))]
#[derive(
    Clone,
    Encode,
    Decode,
    Debug,
    Eq,
    PartialEq,
    TypeInfo,
    frame_support::Serialize,
    frame_support::Deserialize,
)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: codec::alloc::vec::Vec<u8>,
    pub tss_account: codec::alloc::vec::Vec<u8>,
}

#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct OcwMessage {
    pub block_number: BlockNumber,
    pub sig_request_accounts: Vec<Vec<u8>>,
    pub validators_info: Vec<ValidatorInfo>,
}

/// Offchain worker message for initiating a proactive refresh
#[cfg(not(feature = "wasm"))]
#[derive(
    Clone,
    Encode,
    Decode,
    Debug,
    Eq,
    PartialEq,
    TypeInfo,
    frame_support::Serialize,
    frame_support::Deserialize,
)]
pub struct OcwMessageProactiveRefresh {
    pub validators_info: Vec<ValidatorInfo>,
}
