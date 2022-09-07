//! Errors used in User creation

use std::io::Cursor;

use rocket::{
    http::Status,
    response::{Responder, Response},
};
use thiserror::Error;

// #[derive(Responder, Debug)]
// #[response(status = 418, content_type = "json")]
#[derive(Debug, Error)]
pub enum UserErr {
    #[error("Parse error: {0}")]
    Parse(&'static str),
    #[error("Input Validation error: {0}")]
    InputValidation(&'static str),
    #[error("Kv error: {0}")]
    Kv(#[from] kvdb::kv_manager::error::KvError),
    // Other(&'static str),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for UserErr {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = format!("{}", self).into_bytes();
        Response::build()
            .sized_body(body.len(), Cursor::new(body))
            .status(Status::InternalServerError)
            .ok()
    }
}
