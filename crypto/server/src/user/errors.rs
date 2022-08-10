//! Errors used in User creation
use rocket::response::Responder;
use thiserror::Error;

#[derive(Responder, Debug)]
#[response(status = 418, content_type = "json")]
pub enum NewUserError {
  Other(&'static str),
}
