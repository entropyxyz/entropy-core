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
    #[cfg(not(any(test, feature = "unsafe")))]
    #[error("Not yet implemented")]
    NotImplemented,
    #[error("Input must be 32 bytes: {0}")]
    TryFromSlice(#[from] TryFromSliceError),
    #[error("Could not get block number")]
    BlockNumber,
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("UnexpectedAttestationRequest")]
    Unexpected,
    #[error("Could not decode message: {0}")]
    Codec(#[from] parity_scale_codec::Error),
}

impl IntoResponse for AttestationErr {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
