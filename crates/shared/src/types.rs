// Copyright (C) 2023 Entropy Cryptography Inc.
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use super::constants::VERIFICATION_KEY_LENGTH;
#[cfg(not(feature = "wasm"))]
use codec::alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode};
use scale_info::TypeInfo;
#[cfg(any(feature = "std", feature = "wasm", feature = "user-native"))]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use strum_macros::EnumIter;

/// X25519 public key used by the client in non-interactive ECDH to authenticate/encrypt
/// interactions with the threshold server (eg distributing threshold shares).
pub type X25519PublicKey = [u8; 32];

/// This should match the type found in `entropy-runtime`. We define it ourselves manually here
/// since we don't want to pull that whole crate it just for a `u32`.
pub type BlockNumber = u32;

/// Information from the validators in signing party
#[cfg_attr(not(feature = "wasm"), derive(sp_runtime::Serialize, sp_runtime::Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo, DecodeWithMemTracking)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: Vec<u8>,
    pub tss_account: Vec<u8>,
}

/// Offchain worker message for initiating the initial jumpstart DKG
#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo, DecodeWithMemTracking)]
pub struct OcwMessageDkg {
    pub block_number: BlockNumber,
    pub validators_info: Vec<ValidatorInfo>,
}

/// Offchain worker message for initiating a refresh
#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo, DecodeWithMemTracking)]
pub struct OcwMessageReshare {
    // Stash addresses of new signers
    pub new_signers: Vec<Vec<u8>>,
    pub block_number: BlockNumber,
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
    sp_runtime::Serialize,
    sp_runtime::Deserialize,
    DecodeWithMemTracking,
)]
pub struct OcwMessageProactiveRefresh {
    pub block_number: BlockNumber,
    /// Information of the validators to participate
    pub validators_info: Vec<ValidatorInfo>,
    /// Accounts to take part in the proactive refresh
    pub proactive_refresh_keys: Vec<Vec<u8>>,
}

/// 256-bit hashing algorithms for deriving the point to be signed.
#[cfg_attr(any(feature = "wasm", feature = "std"), derive(Serialize, Deserialize))]
#[cfg_attr(feature = "std", derive(EnumIter))]
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", serde(rename = "hash"))]
#[cfg_attr(feature = "std", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum HashingAlgorithm {
    Sha1,
    Sha2,
    Sha3,
    Keccak,
    Blake2_256,
    /// An algorithm which produces the same output as its input.
    Identity,
    Custom(u32),
}

/// A compressed, serialized [synedrion::ecdsa::VerifyingKey<k256::Secp256k1>]
pub type EncodedVerifyingKey = [u8; VERIFICATION_KEY_LENGTH as usize];

#[cfg(not(feature = "wasm"))]
pub type BoundedVecEncodedVerifyingKey =
    sp_runtime::BoundedVec<u8, sp_runtime::traits::ConstU32<VERIFICATION_KEY_LENGTH>>;

/// Public signing and encryption keys associated with a TS server
/// This is the output from the TSS `/info` HTTP route
#[cfg(feature = "wasm-no-std")]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TssPublicKeys {
    /// Indicates that all prerequisite checks have passed
    pub ready: bool,
    /// The TSS account ID
    pub tss_account: sp_runtime::AccountId32,
    /// The public encryption key
    pub x25519_public_key: X25519PublicKey,
    /// A TDX quote
    pub tdx_quote: Vec<u8>,
}
