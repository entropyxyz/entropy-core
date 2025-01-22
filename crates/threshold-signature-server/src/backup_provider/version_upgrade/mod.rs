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
//! Backup and restore encrypted DB before / after entropy-tss version upgrade
use crate::{backup_provider::api::get_key_provider_details, AppState};
use axum::{extract::State, Json};

/// HTTP GET route which produces and encrypted db backup together with recovery details
pub async fn backup_encrypted_db_for_version_upgrade(
    State(app_state): State<AppState>,
) -> Result<Json<()>, bool> {
    let storage_path = app_state.kv_store.storage_path().to_path_buf();
    let key_provider_details = get_key_provider_details(storage_path).unwrap();
    Ok(Json(()))
}
