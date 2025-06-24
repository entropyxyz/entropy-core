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
use entropy_shared::{
    attestation::QuoteContext,
    types::{HashingAlgorithm, TssPublicKeys},
};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use entropy_client::attestation::create_quote;
use x25519_dalek::StaticSecret;

/// Version information - the output of the `/version` HTTP endpoint
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct VersionDetails {
    pub cargo_package_version: String,
    pub git_tag_commit: String,
    pub build: BuildDetails,
}

impl VersionDetails {
    fn new() -> Self {
        Self {
            cargo_package_version: env!("CARGO_PKG_VERSION").to_string(),
            git_tag_commit: env!("VERGEN_GIT_DESCRIBE").to_string(),
            build: BuildDetails::new(),
        }
    }
}

/// This lets us know this is a production build and gives us the measurement value of the release
/// image
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum BuildDetails {
    ProductionWithMeasurementValue(String),
    NonProduction,
}

impl BuildDetails {
    #[cfg(not(feature = "production"))]
    fn new() -> Self {
        BuildDetails::NonProduction
    }

    #[cfg(feature = "production")]
    fn new() -> Self {
        BuildDetails::ProductionWithMeasurementValue(
            match crate::attestation::api::get_measurement_value() {
                Ok(value) => hex::encode(value),
                Err(error) => format!("Failed to get measurement value {:?}", error),
            },
        )
    }
}

/// Returns the version, commit data and build details
#[tracing::instrument]
pub async fn version() -> Json<VersionDetails> {
    Json(VersionDetails::new())
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
        tss_account: app_state.account_id(),
        tdx_quote: hex::encode(
            create_quote(
                [0; 32],
                app_state.subxt_account_id(),
                &x25519_dalek::PublicKey::from(app_state.x25519_secret),
                QuoteContext::Validate,
            )
            .await?,
        ),
    }))
}
