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
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use entropy_kvdb::kv_manager::error::KvError;
use thiserror::Error;

/// An error relating to backing-up or recovering a key-value database encryption key
#[derive(Debug, Error)]
pub enum BackupProviderError {
    #[error("HTTP request: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Key-value store: {0}")]
    Kv(#[from] KvError),
    #[error("Encryption key is not present in backup store")]
    NoKeyInStore,
    #[error("Cannot retrieve associated nonce for this backup")]
    NoNonceInStore,
    #[error("Panic while holding lock on backup store")]
    RwLockPoison,
    #[error("JSON: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Encryption: {0}")]
    Encryption(#[from] crate::validation::EncryptedSignedMessageErr),
    #[error("Attestation: {0}")]
    Attestation(#[from] crate::attestation::errors::AttestationErr),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Bad response from backup provider: {0} {1}")]
    BadProviderResponse(reqwest::StatusCode, String),
    #[error("Provider responded with a key which is not 32 bytes")]
    BadKeyLength,
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("The account requesting to recover a key is not registered with the staking pallet")]
    NotRegisteredWithStakingPallet,
    #[error("Filesystem IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("Utf8Error: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
    #[error("Bad quote input data: TSS account, response public key, or nonce are incorrect")]
    BadQuoteInputData,
    #[error("Quote verify: {0}")]
    VerifyQuote(#[from] entropy_shared::VerifyQuoteError),
    #[error("Could not find another TSS node to request backup")]
    NoValidators,
    #[error("Could not get server info for TSS node chosen for backup")]
    NoServerInfo,
    #[error("Node has started fresh and not yet successfully set up")]
    NotReady,
    #[error("Quote measurement: {0}")]
    QuoteMeasurement(#[from] crate::attestation::errors::QuoteMeasurementErr),
}

impl IntoResponse for BackupProviderError {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
