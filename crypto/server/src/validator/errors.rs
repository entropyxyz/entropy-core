use std::io::Cursor;

use rocket::{
    http::Status,
    response::{Responder, Response},
};
use thiserror::Error;
use std::string::FromUtf8Error;

#[derive(Debug, Error)]
pub enum ValidatorErr {
	#[error("Substrate error: {0}")]
    Substrate(#[from] subxt::error::DispatchError),
	#[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
	#[error("Option Unwrap error: {0}")]
    OptionUnwrapError(&'static str),
	#[error("String Conversion Error: {0}")]
    StringConversion(#[from] FromUtf8Error),
	#[error("Deserialization Error: {0:?}")]
    Deserialization(#[from] serde_json::Error),
	#[error("reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
	#[error("Kv error: {0}")]
    Kv(#[from] kvdb::kv_manager::error::KvError),
	// #[error("Address conversion error: {0}")]
    // AddressConversion(#[from] String),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for ValidatorErr {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let body = format!("{self}").into_bytes();
        Response::build()
            .sized_body(body.len(), Cursor::new(body))
            .status(Status::InternalServerError)
            .ok()
    }
}
