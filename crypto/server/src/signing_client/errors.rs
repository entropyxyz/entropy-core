//! Errors for everyone ✅
use kvdb::kv_manager::error::InnerKvError;
use rocket::response::Responder;
use thiserror::Error;
use tokio::sync::oneshot::error::RecvError;

// #[derive(Responder, Debug, Error)]
// #[response(status = 418, content_type = "json")]
/// Errors for the `new_party` API
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
  #[error("Tofn fatal")] // note: TofnFatal doesn't implement Error :-(
  Subscribe(#[from] SubscribeErr),
  #[error("Tofn fatal")] // note: TofnFatal doesn't implement Error :-(
  // TofnFatal(#[from] TofnFatal),
  TofnFatal(String),
  #[error("Protocol Execution error: {0}")]
  ProtocolExecution(String),
  #[error("Protocol Outpcut error: {0}")]
  ProtocolOutput(String),
  #[error("reqwest error: {0}")]
  Reqwest(#[from] reqwest::Error),
  // #[error("anyhow error: {0}")]
  // Anyhow(#[from] anyhow::Error),
  // #[error("other error: {0}")]
  // Other(#[from] Box<dyn std::error::Error + jSend + Syn>),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for SigningErr {
  #[allow(unused_variables)]
  fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> { todo!() }
}

/// Errors for the `subscribe` API
#[derive(Responder, Debug, Error)]
#[response(status = 418, content_type = "json")]
pub enum SubscribeErr {
  #[error("Timeout error: {0}")]
  Timeout(&'static str),
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
