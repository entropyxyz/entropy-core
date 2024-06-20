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
use crate::{
    chain_api::{get_api, get_rpc},
    user::UserErr,
    AppState,
};
use axum::{extract::State, Json};
pub use entropy_client::user::get_current_subgroup_signers;
use entropy_shared::types::HashingAlgorithm;
use strum::IntoEnumIterator;

/// Returns the version and commit data
#[tracing::instrument]
pub async fn version() -> String {
    format!("{}-{}", env!("CARGO_PKG_VERSION"), env!("VERGEN_GIT_DESCRIBE"))
}

#[tracing::instrument]
pub async fn hashes() -> Json<Vec<HashingAlgorithm>> {
    let hashing_algos = HashingAlgorithm::iter().collect::<Vec<_>>();
    Json(hashing_algos)
}

/// message is stripped 0x keccak hex encoded hash of message
#[tracing::instrument(skip_all)]
pub async fn get_subgroup_signers(
    State(app_state): State<AppState>,
    message_hash_keccak_hex: String,
) -> Result<String, UserErr> {
    let api = get_api(&app_state.configuration.endpoint).await?;
    let rpc = get_rpc(&app_state.configuration.endpoint).await?;
    let subgroup_signers =
        get_current_subgroup_signers(&api, &rpc, &message_hash_keccak_hex).await?;
    Ok(serde_json::to_string(&subgroup_signers)?)
}
