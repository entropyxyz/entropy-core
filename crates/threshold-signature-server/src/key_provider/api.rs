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
    key_provider::errors::KeyProviderError, validation::EncryptedSignedMessage, AppState,
    SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_shared::{ValidatorInfo, X25519PublicKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn make_provider_request(
    validator_info: ValidatorInfo,
    tss_account: SubxtAccountId32,
) -> Result<[u8; 32], KeyProviderError> {
    let quote = Vec::new(); // TODO

    let response_secret_key = StaticSecret::random_from_rng(OsRng);
    let response_key = PublicKey::from(&response_secret_key).to_bytes();

    let key_request = EncryptionKeyRequest { tss_account, response_key, quote };

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/request_encryption_key",
            String::from_utf8(validator_info.ip_address).unwrap()
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&key_request).unwrap())
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await.unwrap();
        panic!("Bad status code {}: {}", status, text);
    }
    let response_bytes = response.bytes().await?;

    let encrypted_response: EncryptedSignedMessage =
        serde_json::from_slice(&response_bytes).unwrap();
    let signed_message = encrypted_response.decrypt(&response_secret_key, &[]).unwrap();

    Ok(signed_message.message.0.try_into().unwrap())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKeyRequest {
    tss_account: SubxtAccountId32,
    response_key: X25519PublicKey,
    quote: Vec<u8>,
}

pub async fn request_encryption_key(
    State(app_state): State<AppState>,
    Json(key_request): Json<EncryptionKeyRequest>,
) -> Result<Json<EncryptedSignedMessage>, KeyProviderError> {
    // Build quote input
    // Verify quote
    // Check kvdb for existing key - or generate and store one
    let lookup_key = format!("BACKUP_KEY:{}", key_request.tss_account.to_string());
    let key: [u8; 32] = match app_state.kv_store.kv().get(&lookup_key).await {
        Ok(existing_key) => existing_key.try_into().map_err(|_| KeyProviderError::BadKeyLength)?,
        Err(_) => {
            // TODO Generate random 32 byte key
            let encryption_key = [0; 32];
            let reservation = app_state.kv_store.kv().reserve_key(lookup_key).await?;
            app_state.kv_store.kv().put(reservation, encryption_key.to_vec()).await?;
            encryption_key
        },
    };
    // Encrypt response
    let signed_message =
        EncryptedSignedMessage::new(&app_state.pair, key.to_vec(), &key_request.response_key, &[])
            .unwrap();
    Ok(Json(signed_message))
}
