//! Errors used in User creation
use rocket::response::Responder;
use thiserror::Error;

// #[derive(Responder, Debug)]
// #[response(status = 418, content_type = "json")]
#[derive(Debug, Error)]
pub enum NewUserError {
  #[error("Parse error: {0}")]
  Parse(&'static str),
  #[error("Input Validation error: {0}")]
  InputValidation(&'static str),
  #[error("Kv error: {0}")]
  Kv(#[from] kvdb::kv_manager::error::KvError),
  // Other(&'static str),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for NewUserError {
  fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> { todo!() }
}
