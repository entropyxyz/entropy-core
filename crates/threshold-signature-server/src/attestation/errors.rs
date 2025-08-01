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

use std::array::TryFromSliceError;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationErr {
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("User Error: {0}")]
    UserErr(#[from] crate::user::UserErr),
    #[error("Client Error: {0}")]
    ClientError(#[from] entropy_client::errors::ClientError),
    #[error("Input must be 32 bytes: {0}")]
    TryFromSlice(#[from] TryFromSliceError),
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("Could not decode message: {0}")]
    Codec(#[from] parity_scale_codec::Error),
    #[cfg(feature = "production")]
    #[error("Cannot encode verifying key: {0}")]
    EncodeVerifyingKey(#[from] tdx_quote::VerifyingKeyError),
    #[error("Kv error: {0}")]
    Kv(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("Attestation request: {0}")]
    AttestationRequest(#[from] entropy_client::errors::AttestationRequestError),
    #[error("Invalid or unknown context value given in query string")]
    UnknownContext,
    #[cfg(feature = "production")]
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Application State Error: {0}")]
    AppStateError(#[from] crate::helpers::app_state::AppStateError),
}

impl IntoResponse for AttestationErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
