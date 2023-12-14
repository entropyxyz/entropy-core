use std::string::FromUtf8Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

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
    Kv(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("User Error: {0}")]
    UserErr(#[from] crate::user::UserErr),
    #[error("Validation Error: {0}")]
    Decryption(String),
    #[error("Validation Error: {0}")]
    Encryption(String),
    #[error("Forbidden Key")]
    ForbiddenKey,
    #[error("Invalid Signature: {0}")]
    InvalidSignature(&'static str),
    #[error("Subgroup error: {0}")]
    SubgroupError(&'static str),
    #[error("Account unable to be deserialized: {0}")]
    StringError(&'static str),
    #[error("Validator not in subgroup")]
    NotInSubgroup,
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("Invalid length for converting address")]
    AddressConversionError(String),
    #[error("Encryption or signing error: {0}")]
    Json(#[from] entropy_protocol::sign_and_encrypt::SignedMessageErr),
}

impl IntoResponse for ValidatorErr {
    fn into_response(self) -> Response {
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
