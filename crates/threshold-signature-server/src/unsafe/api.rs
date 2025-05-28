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
use axum::{extract::State, http::StatusCode, Json};
use entropy_protocol::KeyShareWithAuxInfo;
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::to_string;
use std::str;

use crate::{helpers::app_state::BlockNumberFields, AppState};

/// Used to modify the state of the KVDB directly.
///
/// # Note
///
/// This should only be used for development purposes.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UnsafeQuery {
    pub key: String,
    pub value: Vec<u8>,
}

/// Struct representing the query type
#[cfg(test)]
impl UnsafeQuery {
    pub fn new(key: String, value: Vec<u8>) -> Self {
        UnsafeQuery { key, value }
    }

    pub fn to_json(&self) -> String {
        to_string(self).unwrap()
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsafeRequestLimitQuery {
    pub key: String,
    pub value: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsafeBlockNumberQuery {
    pub key: BlockNumberFields,
    pub value: u32,
}

/// Read the network key share from application state
#[tracing::instrument(name = "Reading network keyshare", skip(app_state))]
pub async fn unsafe_get_network_key_share(
    State(app_state): State<AppState>,
) -> Json<Option<KeyShareWithAuxInfo>> {
    let network_key_share = app_state.network_key_share().unwrap();
    Json(network_key_share)
}

/// Updates a value in the block_numbers.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(name = "Updating key from block_numbers", skip_all)]
pub async fn write_to_block_numbers(
    State(app_state): State<AppState>,
    Json(key): Json<UnsafeBlockNumberQuery>,
) -> StatusCode {
    tracing::trace!("Attempting to write value {:?} to request_limit", &key.value);
    app_state.cache.write_to_block_numbers(key.key, key.value).unwrap();
    StatusCode::OK
}

/// Updates a value in the request_limit.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(
    name = "Updating key from request_limit",
    skip_all,
    fields(key = key.key),
)]
pub async fn write_to_request_limit(
    State(app_state): State<AppState>,
    Json(key): Json<UnsafeRequestLimitQuery>,
) -> StatusCode {
    tracing::trace!("Attempting to write value {:?} to request_limit", &key.value);
    app_state.cache.write_to_request_limit(key.key, key.value).unwrap();
    StatusCode::OK
}

/// Reads a value in the request_limit.
///
/// # Note
///
/// This should only be used for development purposes.
#[tracing::instrument(
    name = "Updating key from request_limit",
    skip_all,
    fields(key = key.key),
)]
pub async fn read_from_request_limit(
    State(app_state): State<AppState>,
    Json(key): Json<UnsafeQuery>,
) -> Vec<u8> {
    tracing::trace!("Attempting to read value {:?} to cache", &key.key);
    app_state.cache.read_from_request_limit(&key.key).unwrap().unwrap().encode()
}
