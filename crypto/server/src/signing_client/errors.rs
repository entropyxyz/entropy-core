//! Errors for everyone ✅
use std::string::FromUtf8Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use kvdb::kv_manager::error::InnerKvError;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

use super::SigningMessage;

/// Errors for the `new_party` API
#[derive(Debug, Error)]
pub enum SigningErr {
    #[error("Kv error: {0}")]
    Kv(#[from] kvdb::kv_manager::error::KvError),
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
    // Validation(&'static str),
    #[error("Oneshot timeout error: {0}")]
    OneshotTimeout(#[from] RecvError),
    #[error("Subscribe API error: {0}")]
    Subscribe(#[from] SubscribeErr),
    #[error("Protocol Execution error: {0}")]
    ProtocolExecution(synedrion::sessions::Error),
    #[error("Incoming message stream error: {0}")]
    IncomingStream(String),
    #[error("Protocol Output error: {0}")]
    ProtocolOutput(synedrion::sessions::Error),
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("reqwest event error: {0}")]
    ReqwestEvent(#[from] reqwest_eventsource::Error),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] Box<tokio::sync::broadcast::error::SendError<SigningMessage>>),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Message validation Error: {0}")]
    MessageValidation(String),
    #[error("Unexpected event: {0}")]
    UnexpectedEvent(String),
    #[error("Session Error: {0}")]
    SessionError(String),
    #[error("String Conversion Error: {0}")]
    StringConversion(#[from] FromUtf8Error),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("User Error: {0}")]
    UserError(&'static str),
    #[error("mnemonic failure: {0:?}")]
    Mnemonic(String),
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("Connection closed unexpectedly")]
    ConnectionClosed,
    #[error("Subscribe message rejected: {0}")]
    BadSubscribeMessage(String),
    #[error("From Hex Error: {0}")]
    FromHex(#[from] hex::FromHexError),
    #[error("Vec<u8> Conversion Error: {0}")]
    Conversion(&'static str),
}

impl IntoResponse for SigningErr {
    fn into_response(self) -> Response {
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

/// Errors for the `subscribe` API
#[derive(Debug, Error)]
pub enum SubscribeErr {
    // #[error("Timeout error: {0}")]
    // Timeout(&'static str),
    #[error("no listener: {0}")]
    NoListener(&'static str),
    // #[error("Validation error: {0}")]
    // Validation(&'static str),
    #[error("invalid party ID: {0}")]
    InvalidPartyId(String),
    #[error("Lock Error: {0}")]
    LockError(String),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(&'static str),
    #[error("Validation error: {0}")]
    Decryption(String),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("User Error: {0}")]
    UserError(String),
}

impl IntoResponse for SubscribeErr {
    fn into_response(self) -> Response {
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

// todo: delete
#[derive(Debug, Error)]
pub enum SigningMessageError {
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Deserialization Error: {0:?}")]
    Deserialization(#[from] serde_json::Error),
}
