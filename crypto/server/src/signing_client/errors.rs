//! Errors for everyone ✅
use std::io::Cursor;

use kvdb::kv_manager::error::InnerKvError;
use rocket::{
    http::Status,
    response::{Responder, Response},
};
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

use super::SigningMessage;

// #[derive(Responder, Debug, Error)]
// #[response(status = 418, content_type = "json")]
/// Errors for the `new_party` API
// note: TofnFatal doesn't implement Error, so we have to use map_err for those.
#[derive(Debug, Error)]
pub enum SigningErr {
    // #[error("Init error: {0}")]
    // Init(&'static str),
    #[error("Kv error: {0}")]
    Kv(#[from] kvdb::kv_manager::error::KvError),
    #[error("TryFrom error: {0}")]
    InnerKv(#[from] InnerKvError),
    // Validation(&'static str),
    #[error("Oneshot timeout error: {0}")]
    OneshotTimeout(#[from] RecvError),
    #[error("Tofn fatal")]
    Subscribe(#[from] SubscribeErr),
    #[error("Protocol Execution error: {0}")]
    ProtocolExecution(String),
    #[error("Protocol Output error: {0}")]
    ProtocolOutput(String),
    #[error("Cannot make a recoverable signature")]
    SignatureError,
    #[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("Broadcast error: {0}")]
    Broadcast(#[from] tokio::sync::broadcast::error::SendError<SigningMessage>),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for SigningErr {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = format!("{self}").into_bytes();
        Response::build()
            .sized_body(body.len(), Cursor::new(body))
            .status(Status::InternalServerError)
            .ok()
    }
}

/// Errors for the `subscribe` API
#[derive(Responder, Debug, Error)]
#[response(status = 418, content_type = "json")]
pub enum SubscribeErr {
    // #[error("Timeout error: {0}")]
    // Timeout(&'static str),
    #[error("no listener: {0}")]
    NoListener(&'static str),
    // #[error("Validation error: {0}")]
    // Validation(&'static str),
}

// todo: delete
#[derive(Debug, Error)]
pub enum SigningMessageError {
    #[error("No ':' to split")]
    BadSplit,
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Deserialization Error: {0:?}")]
    Deserialization(#[from] serde_json::Error),
}
