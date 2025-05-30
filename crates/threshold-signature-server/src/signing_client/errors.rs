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

//! Errors for everyone ✅
use std::string::FromUtf8Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_kvdb::kv_manager::error::InnerKvError;
use entropy_protocol::errors::ProtocolExecutionErr;
use subxt::utils::AccountId32;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

use super::ProtocolMessage;

/// Errors for protocol execution
#[derive(Debug, Error)]
pub enum ProtocolErr {
    #[error("Protocol Execution Error {0}")]
    ProtocolExecution(#[from] ProtocolExecutionErr),
    #[error("Kv error: {0}")]
    Kv(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("Inner Kv error: {0}")]
    InnerKv(#[from] InnerKvError),
    #[error("Codec decoding error: {0}")]
    CodecError(#[from] parity_scale_codec::Error),
    #[error("Conversion Error: {0}")]
    TryFrom(#[from] std::array::TryFromSliceError),
    #[error("Decoding Error: {0}")]
    Bincode(#[from] Box<bincode::ErrorKind>),
    #[error("Deserialization Error: {0}")]
    Deserialization(String),
    #[error("Oneshot timeout error: {0}")]
    OneshotTimeout(#[from] RecvError),
    #[error("Subscribe API error: {source} by TSS Account `{account_id:?}`")]
    Subscribe { source: SubscribeErr, account_id: AccountId32 },
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("reqwest event error: {0}")]
    ReqwestEvent(#[from] reqwest_eventsource::Error),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<ProtocolMessage>>),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("String Conversion Error: {0}")]
    StringConversion(#[from] FromUtf8Error),
    #[error("User Error: {0}")]
    UserError(String),
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("Subscribe message rejected: {message} by TSS Account `{account_id}`")]
    BadSubscribeMessage { message: String, account_id: AccountId32 },
    #[error("From Hex Error: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("Conversion Error: {0}")]
    Conversion(&'static str),
    #[error("Could not open ws connection: {source} with the TSS Account `{account_id:?}`")]
    ConnectionError { source: tokio_tungstenite::tungstenite::Error, account_id: AccountId32 },
    #[error("Timed out while waiting for peer(s): {:?}", inactive_peers)]
    Timeout { source: tokio::time::error::Elapsed, inactive_peers: Vec<AccountId32> },
    #[error("Encrypted connection error {source:?} with the TSS Account `{account_id:?}`")]
    EncryptedConnection {
        source: entropy_protocol::protocol_transport::errors::EncryptedConnectionErr,
        account_id: AccountId32,
    },
    #[error("Program error: {0}")]
    ProgramError(#[from] crate::user::errors::ProgramError),
    #[error("Invalid length for converting address")]
    AddressConversionError(String),
    #[error("Kv Fatal error")]
    KvSerialize(String),
    #[error("Validator Error: {0}")]
    ValidatorErr(String),
    #[error("Subgroup error: {0}")]
    SubgroupError(&'static str),
    #[error("Account unable to be deserialized: {0}")]
    StringError(&'static str),
    #[error("Option Unwrap error: {0}")]
    OptionUnwrapError(String),
    #[error("Proactive Refresh data incorrect")]
    InvalidData,
    #[error("Data is repeated")]
    RepeatedData,
    #[error("Chain Fetch: {0}")]
    ChainFetch(&'static str),
    #[error("The session ID is not for a signing session")]
    BadSessionId,
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("Listener: {0}")]
    Listener(#[from] entropy_protocol::errors::ListenerErr),
    #[error("Failed to derive BIP-32 account: {0}")]
    Bip32DerivationError(#[from] bip32::Error),
    #[error("Node has started fresh and not yet successfully set up")]
    NotReady,
    #[error("Application State Error: {0}")]
    AppStateError(#[from] crate::helpers::app_state::AppStateError),
    #[error("Manul local error: {0}")]
    ManulLocal(String),
    #[error("subxt rpc error: {0}")]
    SubxtRpcError(#[from] subxt::ext::subxt_rpcs::Error),
    #[error("Cannot run protocol as we do not have a key-share")]
    NoKeyShare,
}

impl IntoResponse for ProtocolErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

impl From<manul::session::LocalError> for ProtocolErr {
    fn from(err: manul::session::LocalError) -> Self {
        Self::ManulLocal(format!("{err:?}"))
    }
}

/// Errors for the `subscribe` API
#[derive(Debug, Error)]
pub enum SubscribeErr {
    #[error("no listener: {0}")]
    NoListener(&'static str),
    #[error("invalid party ID: {0}")]
    InvalidPartyId(String),
    #[error("Lock Error: {0}")]
    LockError(String),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(&'static str),
    #[error("Validation error: {0}")]
    Decryption(String),
    #[error("Serialization/Deserialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("User Error: {0}")]
    UserError(String),
    #[error("Listener: {0}")]
    Listener(#[from] entropy_protocol::errors::ListenerErr),
    #[error("Protocol version mismatch: {0}")]
    VersionMismatch(
        #[from] entropy_protocol::protocol_transport::errors::ProtocolVersionMismatchError,
    ),
    #[error("Unable to find `Listener` with `SessionId`: {0:?}")]
    NoSessionId(entropy_protocol::SessionId),
}

impl IntoResponse for SubscribeErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
