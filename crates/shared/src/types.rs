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

#![allow(dead_code)]
use super::constants::VERIFICATION_KEY_LENGTH;
use blake2::{Blake2b512, Digest};
#[cfg(not(feature = "wasm"))]
use codec::alloc::vec::Vec;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
#[cfg(any(feature = "std", feature = "wasm"))]
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
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: Vec<u8>,
    pub tss_account: Vec<u8>,
}

/// Offchain worker message for initiating the initial jumpstart DKG
#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct OcwMessageDkg {
    pub block_number: BlockNumber,
    pub validators_info: Vec<ValidatorInfo>,
}

/// Offchain worker message for initiating a refresh
#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
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
)]
pub struct OcwMessageProactiveRefresh {
    pub block_number: BlockNumber,
    /// Information of the validators to participate
    pub validators_info: Vec<ValidatorInfo>,
    /// Accounts to take part in the proactive refresh
    pub proactive_refresh_keys: Vec<Vec<u8>>,
}

/// Offchain worker message for requesting a TDX attestation
#[cfg(not(feature = "wasm"))]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq, TypeInfo)]
pub struct OcwMessageAttestationRequest {
    /// The account ids of all TSS servers who must submit an attestation this block
    pub tss_account_ids: Vec<[u8; 32]>,
    /// The block height at which this attestation request was made.
    pub block_number: BlockNumber,
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
    NoHash,
    Custom(usize),
}

/// A compressed, serialized [synedrion::ecdsa::VerifyingKey<k256::Secp256k1>]
pub type EncodedVerifyingKey = [u8; VERIFICATION_KEY_LENGTH as usize];

#[cfg(not(feature = "wasm"))]
pub type BoundedVecEncodedVerifyingKey =
    sp_runtime::BoundedVec<u8, sp_runtime::traits::ConstU32<VERIFICATION_KEY_LENGTH>>;

/// Input data to be included in a TDX attestation
pub struct QuoteInputData(pub [u8; 64]);

impl QuoteInputData {
    pub fn new<T: Encode>(
        tss_account_id: T,
        x25519_public_key: X25519PublicKey,
        nonce: [u8; 32],
        context: QuoteContext,
    ) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update(tss_account_id.encode());
        hasher.update(x25519_public_key);
        hasher.update(nonce);
        hasher.update(context.encode());
        Self(hasher.finalize().into())
    }
}

/// An indicator as to the context in which a quote is intended to be used
#[derive(Clone, Encode, Decode, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuoteContext {
    /// To be used in the `validate` extrinsic
    Validate,
    /// To be used in the `change_endpoint` extrinsic
    ChangeEndpoint,
    /// To be used in the `change_threshold_accounts` extrinsic
    ChangeThresholdAccounts,
}

#[cfg(feature = "std")]
impl std::fmt::Display for QuoteContext {
    /// Custom display implementation so that it can be used to build a query string
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuoteContext::Validate => write!(f, "validate"),
            QuoteContext::ChangeEndpoint => write!(f, "change_endpoint"),
            QuoteContext::ChangeThresholdAccounts => write!(f, "change_threshold_accounts"),
        }
    }
}

/// A trait for types which can handle attestation requests.
#[cfg(not(feature = "wasm"))]
pub trait AttestationHandler<AccountId> {
    /// Verify that the given quote is valid and matches the given information about the attestee.
    /// The Provisioning Certification Key (PCK) certifcate chain is extracted from the quote and
    /// verified. If successful, the PCK public key used to sign the quote is returned.
    fn verify_quote(
        attestee: &AccountId,
        x25519_public_key: X25519PublicKey,
        quote: Vec<u8>,
        context: QuoteContext,
    ) -> Result<BoundedVecEncodedVerifyingKey, VerifyQuoteError>;

    /// Indicate to the attestation handler that a quote is desired.
    ///
    /// The `nonce` should be a piece of data (e.g a random number) which indicates that the quote
    /// is reasonably fresh and has not been reused.
    fn request_quote(attestee: &AccountId, nonce: [u8; 32]);
}

/// A convenience implementation for testing and benchmarking.
#[cfg(not(feature = "wasm"))]
impl<AccountId> AttestationHandler<AccountId> for () {
    fn verify_quote(
        _attestee: &AccountId,
        _x25519_public_key: X25519PublicKey,
        _quote: Vec<u8>,
        _context: QuoteContext,
    ) -> Result<BoundedVecEncodedVerifyingKey, VerifyQuoteError> {
        Ok(BoundedVecEncodedVerifyingKey::try_from([0; 33].to_vec()).unwrap())
    }

    fn request_quote(_attestee: &AccountId, _nonce: [u8; 32]) {}
}

/// An error when verifying a quote
#[cfg(not(feature = "wasm"))]
#[derive(Debug, Eq, PartialEq)]
pub enum VerifyQuoteError {
    /// Quote could not be parsed or verified
    BadQuote,
    /// Attestation extrinsic submitted when not requested
    UnexpectedAttestation,
    /// Hashed input data does not match what was expected
    IncorrectInputData,
    /// Unacceptable VM image running
    BadMrtdValue,
    /// Cannot encode verifying key (PCK)
    CannotEncodeVerifyingKey,
    /// Cannot decode verifying key (PCK)
    CannotDecodeVerifyingKey,
    /// PCK certificate chain cannot be parsed
    PckCertificateParse,
    /// PCK certificate chain cannot be verified
    PckCertificateVerify,
    /// PCK certificate chain public key is not well formed
    PckCertificateBadPublicKey,
    /// Pck certificate could not be extracted from quote
    PckCertificateNoCertificate,
}
