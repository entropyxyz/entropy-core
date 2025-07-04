// Copyright (C) 2023 Entropy Cryptography Inc.
//
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
//
use thiserror::Error;

/// Error relating to submitting an extrinsic or querying the chain
#[derive(Debug, Error)]
pub enum SubstrateError {
    #[error("Cannot get block hash")]
    BlockHash,
    #[error("No event following extrinsic submission")]
    NoEvent,
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Could not sumbit transaction {0}")]
    BadEvent(String),
    #[error("User is not registered on-chain")]
    NotRegistered,
    #[error("subxt_core error: {0}")]
    SubxtCoreError(#[from] subxt_core::Error),
    #[error("subxt rpc error: {0}")]
    SubxtRpcError(#[from] subxt::ext::subxt_rpcs::Error),
}

/// An error on getting the current subgroup signers
#[derive(Debug, Error)]
pub enum SubgroupGetError {
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("ParseBigIntError: {0:?}")]
    ParseBigIntError(#[from] num::bigint::ParseBigIntError),
    #[error("Usize error: {0}")]
    Usize(&'static str),
    #[error("Chain Fetch: {0}")]
    ChainFetch(&'static str),
    #[error("Substrate client: {0}")]
    SubstrateClient(#[from] crate::substrate::SubstrateError),
    #[error("Error Joining threads: {0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("subxt rpc error: {0}")]
    SubxtRpcError(#[from] subxt::ext::subxt_rpcs::Error),
}

/// An error when making an attestation request
#[derive(Debug, Error)]
pub enum AttestationRequestError {
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Substrate client: {0}")]
    SubstrateClient(#[from] crate::substrate::SubstrateError),
    #[error("Recieved nonce is not 32 bytes")]
    BadNonce,
}

#[cfg(any(feature = "full-client", feature = "server"))]
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Substrate: {0}")]
    Substrate(#[from] SubstrateError),
    #[error("Cannot get block number")]
    BlockNumber,
    #[error("Cannot get block hash")]
    BlockHash,
    #[error("Stash fetch")]
    StashFetch,
    #[error("UTF8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Subxt: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("Timed out waiting for register confirmation")]
    RegistrationTimeout,
    #[error("Timed out waiting for jumpstart confirmation")]
    JumpstartTimeout,
    #[error("Cannot get subgroup: {0}")]
    SubgroupGet(#[from] SubgroupGetError),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Encryption error: {0}")]
    Encryption(#[from] entropy_protocol::sign_and_encrypt::EncryptedSignedMessageErr),
    #[error("Http client: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Failed to get response from TSS Server")]
    NoResponse,
    #[error("Bad signature in response from TSS Server")]
    BadSignature,
    #[error("Base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("ECDSA: {0}")]
    Ecdsa(#[from] k256::ecdsa::Error),
    #[error("Cannot get recovery ID from signature")]
    NoRecoveryId,
    #[error("Cannot parse recovery ID from signature")]
    BadRecoveryId,
    #[error("Cannot parse chain query response: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("User is not registered on-chain")]
    NotRegistered,
    #[error("Cannot confirm program was created")]
    CannotConfirmProgramCreated,
    #[error("Cannot confirm program was removed")]
    CannotConfirmProgramRemoved,
    #[error("Subgroup fetch error")]
    SubgroupFetch,
    #[error("Cannot query whether validator is synced")]
    CannotQuerySynced,
    #[error("Verifying key has incorrect length")]
    BadVerifyingKeyLength,
    #[error("There are no validators which can act as a relay node for signature requests")]
    NoNonSigningValidators,
    #[error("subxt_core error: {0}")]
    SubxtCoreError(#[from] subxt_core::Error),
    #[error("Scale decode: {0}")]
    Codec(#[from] parity_scale_codec::Error),
    #[error("Attestation request: {0}")]
    AttestationRequest(#[from] AttestationRequestError),
    #[error("Unable to get TDX quote: {0}")]
    QuoteGet(String),
    #[error("Unable to get info for TSS server from chain")]
    NoServerInfo,
    #[error("From Hex Error: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("From Ss58 Error: {0}")]
    FromSs58(String),
    #[error("Vec<u8> Conversion Error: {0}")]
    Conversion(&'static str),
    #[error("Session keys len cannot have length be more or less than 128")]
    SessionKeyLength,
    #[error("Strip prefix error")]
    StripPrefix,
    #[error("subxt rpc error: {0}")]
    SubxtRpcError(#[from] subxt::ext::subxt_rpcs::Error),
    #[error("Unable to successfully check TDX Quote measurement: {0}")]
    QuoteMeasurement(#[from] QuoteMeasurementErr),
    #[error("Timed out trying to declare to chain")]
    TimedOut,
    #[error("No event following extrinsic submission")]
    NoEvent,
    #[error("Cannot encode verifying key: {0}")]
    EncodeVerifyingKey(#[from] tdx_quote::VerifyingKeyError),
    #[error("Quote generation: {0}")]
    QuoteGeneration(String),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
}

/// Error when checking quote measurement value
#[derive(Debug, Error)]
pub enum QuoteMeasurementErr {
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] SubstrateError),
    #[error("Could not get accepted measurement values from on-chain parameters")]
    NoMeasurementValues,
    #[error("Quote verification: {0}")]
    Kv(#[from] entropy_shared::attestation::VerifyQuoteError),
}
