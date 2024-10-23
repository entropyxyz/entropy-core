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
use crate::{get_signer_and_x25519_secret, node_info::errors::GetInfoError, AppState};
use axum::{extract::State, Json};
use entropy_shared::{types::HashingAlgorithm, X25519PublicKey};
use serde::{Deserialize, Serialize};
use sp_core::Pair;
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
    pub tss_account: AccountId32,
    pub x25519_public_key: X25519PublicKey,
}

/// Returns the TS server's public keys and HTTP endpoint
#[tracing::instrument(skip_all)]
pub async fn info(State(app_state): State<AppState>) -> Result<Json<TssPublicKeys>, GetInfoError> {
    let (signer, x25519_secret) = get_signer_and_x25519_secret(&app_state.kv_store).await?;
    let tss_account = AccountId32(signer.signer().public().0);
    let x25519_public_key = x25519_dalek::PublicKey::from(&x25519_secret).as_bytes().clone();

    Ok(Json(TssPublicKeys { x25519_public_key, tss_account }))
}
