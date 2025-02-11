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
use crate::{node_info::errors::GetInfoError, AppState};
use axum::{extract::State, Json};
use entropy_shared::{types::HashingAlgorithm, X25519PublicKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use subxt::utils::AccountId32;

/// Returns the version and commit data
#[tracing::instrument]
pub async fn version() -> String {
    format!("{}-{}", env!("CARGO_PKG_VERSION"), env!("VERGEN_GIT_DESCRIBE"))
}

/// Lists the supported hashing algorithms
#[tracing::instrument]
pub async fn hashes() -> Json<Vec<HashingAlgorithm>> {
    let hashing_algos = HashingAlgorithm::iter().collect::<Vec<_>>();
    Json(hashing_algos)
}

/// Public signing and encryption keys associated with a TS server
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct TssPublicKeys {
    /// Indicates that all prerequisite checks have passed
    pub ready: bool,
    /// The TSS account ID
    pub tss_account: AccountId32,
    /// The public encryption key
    pub x25519_public_key: X25519PublicKey,
}

/// Returns the TS server's public keys and HTTP endpoint
#[tracing::instrument(skip_all)]
pub async fn info(State(app_state): State<AppState>) -> Result<Json<TssPublicKeys>, GetInfoError> {
    Ok(Json(TssPublicKeys {
        ready: app_state.cache.is_ready(),
        x25519_public_key: app_state.x25519_public_key(),
        tss_account: app_state.subxt_account_id(),
    }))
}
