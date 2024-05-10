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
use entropy_protocol::errors::UserRunningProtocolErr;
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
}

#[cfg(feature = "full-client")]
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Substrate: {0}")]
    Substrate(#[from] SubstrateError),
    #[error("Error relating to private mode")]
    PrivateMode,
    #[error("Cannot get block number")]
    BlockNumber,
    #[error("Cannot get block hash")]
    BlockHash,
    #[error("Stash fetch")]
    StashFetch,
    #[error("UTF8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("User running protocol: {0}")]
    UserRunningProtocol(#[from] UserRunningProtocolErr),
    #[error("Subxt: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("Timed out waiting for register confirmation")]
    RegistrationTimeout,
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
    Ecdsa(#[from] synedrion::ecdsa::Error),
    #[error("Cannot get recovery ID from signature")]
    NoRecoveryId,
    #[error("Cannot parse recovery ID from signature")]
    BadRecoveryId,
    #[error("Cannot parse chain query response: {0}")]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("User not registered")]
    NotRegistered,
    #[error("No synced validators")]
    NoSyncedValidators,
    #[error("Cannot confirm program was created")]
    CannotConfirmProgramCreated,
    #[error("Subgroup fetch error")]
    SubgroupFetch,
    #[error("Cannot query whether validator is synced")]
    CannotQuerySynced,
}
