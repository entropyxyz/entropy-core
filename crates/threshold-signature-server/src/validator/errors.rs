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

use std::{array::TryFromSliceError, string::FromUtf8Error};

use crate::signing_client::ProtocolErr;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_protocol::{errors::ProtocolExecutionErr, sign_and_encrypt::EncryptedSignedMessageErr};
use synedrion::sessions;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

#[derive(Debug, Error)]
pub enum ValidatorErr {
    #[error("Substrate error: {0}")]
    Substrate(#[from] subxt::error::DispatchError),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("String Conversion Error: {0}")]
    StringConversion(#[from] FromUtf8Error),
    #[error("Deserialization Error: {0:?}")]
    Deserialization(#[from] serde_json::Error),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Kv error: {0}")]
    Kv(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("User Error: {0}")]
    UserErr(#[from] crate::user::UserErr),
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Chain Fetch: {0}")]
    ChainFetch(&'static str),
    #[error("Encryption or authentication: {0}")]
    Hpke(#[from] EncryptedSignedMessageErr),
    #[error("Message is not from expected author")]
    Authentication,
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("Codec decoding error: {0}")]
    CodecError(#[from] parity_scale_codec::Error),
    #[error("User Error: {0}")]
    UserError(String),
    #[error("Option Unwrap error: {0}")]
    OptionUnwrapError(String),
    #[error("Vec<u8> Conversion Error: {0}")]
    Conversion(&'static str),
    #[error("Verifying key Error: {0}")]
    VerifyingKeyError(String),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Listener: {0}")]
    Listener(#[from] entropy_protocol::errors::ListenerErr),
    #[error("Reshare protocol error: {0}")]
    SigningClientError(#[from] ProtocolErr),
    #[error("Timed out waiting for remote party")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Oneshot timeout error: {0}")]
    OneshotTimeout(#[from] RecvError),
    #[error("Synedrion session creation error: {0}")]
    SessionCreation(sessions::LocalError),
    #[error("No output from reshare protocol")]
    NoOutputFromReshareProtocol,
    #[error("Protocol Error: {0}")]
    ProtocolError(String),
    #[error("Kv Fatal error")]
    KvSerialize(String),
    #[error("Kv Deserialization Error: {0}")]
    KvDeserialize(String),
    #[error("Data is stale")]
    StaleData,
    #[error("Data is not verifiable")]
    InvalidData,
    #[error("Data is repeated")]
    RepeatedData,
    #[error("Not yet implemented")]
    NotImplemented,
    #[error("Input must be 32 bytes: {0}")]
    TryFromSlice(#[from] TryFromSliceError),
    #[error("Node has started fresh and not yet successfully set up")]
    NotReady,
    #[error("Application State Error: {0}")]
    AppStateError(#[from] crate::helpers::app_state::AppStateError),
}

impl IntoResponse for ValidatorErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
