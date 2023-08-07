//! Errors used in User creation

use std::{io::Cursor, string::FromUtf8Error};

use axum::{
    body,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_constraints::Error as ConstraintsError;
use thiserror::Error;

use crate::{chain_api::entropy, signing_client::SigningErr};

#[derive(Debug, Error)]
pub enum UserErr {
    #[error("Parse error: {0}")]
    Parse(&'static str),
    #[error("Input Validation error: {0}")]
    InputValidation(&'static str),
    #[error("Kv error: {0}")]
    Kv(#[from] kvdb::kv_manager::error::KvError),
    #[error("Substrate error: {0}")]
    Substrate(#[from] subxt::error::DispatchError),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Serde Json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Validation error: {0}")]
    Decryption(String),
    #[error("mnemonic failure: {0:?}")]
    Mnemonic(String),
    #[error("Secret String failure: {0:?}")]
    SecretString(&'static str),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Not Registering error: {0}")]
    NotRegistering(&'static str),
    #[error("Subgroup error: {0}")]
    SubgroupError(&'static str),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(&'static str),
    #[error("Constraints error: {0}")]
    ConstraintsError(#[from] ConstraintsError),
    #[error("Signing error: {0}")]
    SigningClientError(#[from] SigningErr),
    #[error("Transaction request unable to be deserialized: {0}")]
    StringConversion(#[from] FromUtf8Error),
    #[error("Account unable to be deserialized: {0}")]
    StringError(&'static str),
    #[error("Invalid Signer: {0}")]
    InvalidSigner(&'static str),
    #[error("ParseBigIntError: {0:?}")]
    ParseBigIntError(#[from] num::bigint::ParseBigIntError),
    #[error("Usize error: {0}")]
    Usize(&'static str),
    #[error("Try From error: {0:?}")]
    TryFrom(Vec<u8>),
    #[error("Session Error: {0}")]
    SessionError(String),
}

impl IntoResponse for UserErr {
    fn into_response(self) -> Response {
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
