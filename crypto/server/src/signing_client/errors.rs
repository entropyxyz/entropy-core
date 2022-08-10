//! Errors used in Signing Client
use rocket::response::Responder;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum SigningProtocolError {
  SignInitErr(&'static str),
  Validation(&'static str),
  Subscribing(&'static str),
  Signing(&'static str),
  Other(&'static str),
}

#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum SubscribeError {
  Other(&'static str),
}

#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum NewUserError{
  Other(&'static str),
}

#[derive(Debug, Error)]
pub enum SigningMessageError {
  #[error("No ':' to split")]
  BadSplit,
  #[error("Utf8Error: {0:?}")]
  Utf8Error(#[from] std::str::Utf8Error),
  #[error("Deserialization Error: {0:?}")]
  DeserializationError(#[from] serde_json::Error),
}