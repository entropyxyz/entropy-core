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
use crate::{attestation::api::get_pck, node_info::errors::GetInfoError, AppState};
use axum::{extract::State, Json};
pub use entropy_shared::tss_node_info::{BuildDetails, TssPublicKeys, VersionDetails};
use entropy_shared::types::HashingAlgorithm;
use strum::IntoEnumIterator;

#[cfg(not(feature = "production"))]
fn get_build_details() -> BuildDetails {
    BuildDetails::NonProduction
}

#[cfg(feature = "production")]
fn get_build_details() -> BuildDetails {
    BuildDetails::ProductionWithMeasurementValue(
        match crate::attestation::api::get_measurement_value() {
            Ok(value) => hex::encode(value),
            Err(error) => format!("Failed to get measurement value {:?}", error),
        },
    )
}

/// Returns the version, commit data and build details
#[tracing::instrument]
pub async fn version() -> Json<VersionDetails> {
    Json(VersionDetails {
        cargo_package_version: env!("CARGO_PKG_VERSION").to_string(),
        git_tag_commit: env!("VERGEN_GIT_DESCRIBE").to_string(),
        build: get_build_details(),
    })
}

/// Lists the supported hashing algorithms
#[tracing::instrument]
pub async fn hashes() -> Json<Vec<HashingAlgorithm>> {
    let hashing_algos = HashingAlgorithm::iter().collect::<Vec<_>>();
    Json(hashing_algos)
}

/// Returns the TS server's public keys and HTTP endpoint
#[tracing::instrument(skip_all)]
pub async fn info(State(app_state): State<AppState>) -> Result<Json<TssPublicKeys>, GetInfoError> {
    Ok(Json(TssPublicKeys {
        ready: app_state.cache.is_ready(),
        x25519_public_key: app_state.x25519_public_key(),
        tss_account: app_state.subxt_account_id().0.into(),
        provisioning_certification_key: get_pck(app_state.subxt_account_id())?,
    }))
}
