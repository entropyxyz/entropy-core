// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::string::FromUtf8Error;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_protocol::sign_and_encrypt::EncryptedSignedMessageErr;
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
    #[error("Subgroup error: {0}")]
    SubgroupError(&'static str),
    #[error("Account unable to be deserialized: {0}")]
    StringError(&'static str),
    #[error("Validator not in subgroup")]
    NotInSubgroup,
    #[error("Validation Error: {0}")]
    ValidationErr(#[from] crate::validation::errors::ValidationErr),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Chain Fetch: {0}")]
    ChainFetch(&'static str),
    #[error("Encryption or authentication: {0}")]
    Hpke(#[from] EncryptedSignedMessageErr),
    #[error("Message is not from expected author")]
    Authentication,
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_tss_client_common::substrate::SubstrateError),
}

impl IntoResponse for ValidatorErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
