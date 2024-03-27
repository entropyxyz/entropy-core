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

//! Errors used in User creation

use std::{io::Cursor, string::FromUtf8Error};

use axum::{
    body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_programs_runtime::RuntimeError as ProgramRuntimeError;
use entropy_protocol::errors::ProtocolExecutionErr;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

use crate::{
    chain_api::entropy,
    signing_client::{ProtocolErr, SubscribeErr},
};

/// Errors related to parsing and evaulating programs.
#[derive(Error, Debug, PartialEq)]
pub enum ProgramError {
    /// Transaction request could not be parsed
    #[error("Invalid transaction request: {0}")]
    InvalidTransactionRequest(String),
    /// Transaction request did not meet programs requirements.
    #[error("Program Evaluation error: {0}")]
    Evaluation(&'static str),
}

#[derive(Debug, Error)]
pub enum UserErr {
    #[error("Parse error: {0}")]
    Parse(&'static str),
    #[error("Input Validation error: {0}")]
    InputValidation(&'static str),
    #[error("Kv error: {0}")]
    Kv(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("Substrate error: {0}")]
    Substrate(#[from] subxt::error::DispatchError),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Decryption(String),
    #[error("mnemonic failure: {0:?}")]
    Mnemonic(String),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Not Registering error: {0}")]
    NotRegistering(&'static str),
    #[error("Subgroup error: {0}")]
    SubgroupError(&'static str),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(&'static str),
    #[error("Program error: {0}")]
    ProgramError(#[from] ProgramError),
    #[error("Signing/DKG protocol error: {0}")]
    SigningClientError(#[from] ProtocolErr),
    #[error("Transaction request unable to be deserialized: {0}")]
    StringConversion(#[from] FromUtf8Error),
    #[error("Account unable to be deserialized: {0}")]
    StringError(&'static str),
    #[error("Invalid Signer: {0}")]
    InvalidSigner(&'static str),
    #[error("ParseBigIntError: {0:?}")]
    ParseBigIntError(#[from] num::bigint::ParseBigIntError),
    #[error("Usize error: {0}")]
    Usize(&'static str),
    #[error("Try From error: {0:?}")]
    TryFrom(Vec<u8>),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("Timed out waiting for remote party")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Oneshot timeout error: {0}")]
    OneshotTimeout(#[from] RecvError),
    #[error("Subscribe API error: {0}")]
    Subscribe(#[from] SubscribeErr),
    #[error("Option Unwrap error: {0}")]
    OptionUnwrapError(String),
    #[error("Data is stale")]
    StaleData,
    #[error("Data is not verifiable")]
    InvalidData,
    #[error("Data is repeated")]
    RepeatedData,
    #[error("User already registered")]
    AlreadyRegistered,
    #[error("Validator not in subgroup")]
    NotInSubgroup,
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Invalid length for converting address")]
    AddressConversionError(String),
    #[error("Vec<u8> Conversion Error: {0}")]
    Conversion(&'static str),
    #[error("Codec decoding error: {0}")]
    CodecError(#[from] parity_scale_codec::Error),
    #[error("Kv Fatal error")]
    KvSerialize(String),
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("No program set at: {0}")]
    NoProgramDefined(String),
    #[error("No program pointer defined for account")]
    NoProgramPointerDefined(),
    #[error("Runtime error: {0:?}")]
    RuntimeError(#[from] ProgramRuntimeError),
    #[error("Parse transaction_request error")]
    ParsingError(#[from] hex::FromHexError),
    #[error("Validator Error: {0}")]
    ValidatorError(String),
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Auxilary data is mismatched")]
    MismatchAuxData,
    #[error("Signature request not allowed - this account is not public")]
    AuthorizationError,
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Chain Fetch: {0}")]
    ChainFetch(&'static str),
    #[error("Too many requests - wait a block")]
    TooManyRequests,
    #[error("The given key is forbidden")]
    ForbiddenKey,
    #[error("No existing keyshare found for this user")]
    UserDoesNotExist,
    #[error("The remote TSS server rejected the keyshare: {0}")]
    KeyShareRejected(String),
    #[error("Encryption or signing error: {0}")]
    EncryptionOrAuthentication(#[from] entropy_protocol::hpke::EncryptedSignedMessageErr),
}

impl IntoResponse for UserErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
