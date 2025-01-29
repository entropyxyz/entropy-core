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
use thiserror::Error;

use crate::backup_provider::errors::BackupProviderError;

/// An error relating to backing-up or recovering a key-value database encryption key
#[derive(Debug, Error)]
pub enum BackupEncryptedDbError {
    #[error("Key-value DB: {0}")]
    KvDb(#[from] entropy_kvdb::kv_manager::error::KvError),
    #[error("It is not possible to upgrade entropy-tss while you are a signer")]
    CannotUpgradeWhileSigner,
    #[error("Backup Provider: {0}")]
    BackupProvider(#[from] BackupProviderError),
    #[error("Node has started fresh and not yet successfully set up")]
    NotReady,
    #[error("Encryption: {0}")]
    Encryption(#[from] crate::validation::EncryptedSignedMessageErr),
    #[error("Generic Substrate error: {0}")]
    GenericSubstrate(#[from] subxt::error::Error),
    #[error("Substrate: {0}")]
    SubstrateClient(#[from] entropy_client::substrate::SubstrateError),
    #[error("Cannot get stash account from chain")]
    CannotGetStashAccount,
    #[error("Only the stash account associated with this TSS node may make this request")]
    Unauthorized,
    #[error("You cannot restore a db backup when the node is ready")]
    Ready,
    #[error("Cannot deserialize provided backup")]
    CannotDeserializeBackup,
    #[error("Cannot serialize db backup")]
    CannotSerializeBackup,
    #[error("An x25519 public key of length 32 bytes must be given")]
    BadResponsePublicKeyLength,
    #[error("No connection to chain node")]
    NotConnectedToChain,
    #[error("Backup version mismatch. We are {0}, backup is from {1}")]
    VersionMismatch(String, String),
}

impl IntoResponse for BackupEncryptedDbError {
    fn into_response(self) -> Response {
        tracing::error!("{:?}", format!("{self}"));
        let body = format!("{self}").into_bytes();
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}
