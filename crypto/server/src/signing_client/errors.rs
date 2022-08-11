//! Errors used in Signing Client
use kvdb::kv_manager::error::InnerKvError;
use rocket::response::Responder;
use thiserror::Error;

// #[derive(Responder, Debug, Error)]
// #[response(status = 418, content_type = "json")]
#[derive(Debug, Error)]
pub enum SigningProtocolError {
  // #[error("Init error: {0}")]
  // Init(&'static str),
  #[error("Kv error: {0}")]
  Kv(#[from] kvdb::kv_manager::error::KvError),
  #[error("TryFrom error: {0}")]
  TryFrom(#[from] InnerKvError),
  // Validation(&'static str),
  #[error("Subscribing error: {0}")]
  Subscribing(&'static str),
  #[error("Tofn fatal")] // note: TofnFatal doesn't implement Error :-(
  // TofnFatal(#[from] TofnFatal),
  TofnFatal(String),
  #[error("Protocol Execution error: {0}")]
  ProtocolExecution(String),
  #[error("Protocol Outpcut error: {0}")]
  ProtocolOutput(String),
  // #[error("anyhow error: {0}")]
  // Anyhow(#[from] anyhow::Error),
  // #[error("other error: {0}")]
  // Other(#[from] Box<dyn std::error::Error + Send + Syn>),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for SigningProtocolError {
  fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> { todo!() }
}

#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum SubscribeError {
  // Other(&'static str),
}

#[derive(Debug, Error)]
pub enum SigningMessageError {
  #[error("No ':' to split")]
  BadSplit,
  #[error("Utf8Error: {0:?}")]
  Utf8(#[from] std::str::Utf8Error),
  #[error("Deserialization Error: {0:?}")]
  Deserialization(#[from] serde_json::Error),
}
