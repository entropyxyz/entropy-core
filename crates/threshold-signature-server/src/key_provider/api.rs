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
    chain_api::entropy, key_provider::errors::KeyProviderError, validation::EncryptedSignedMessage,
    AppState, EntropyConfig, SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_client::substrate::query_chain;
use entropy_shared::{user::ValidatorInfo, X25519PublicKey};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use std::path::PathBuf;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use x25519_dalek::{PublicKey, StaticSecret};

const KEY_PROVIDER_FILENAME: &str = "key-provider-details.json";

/// Make a request to a given TSS node to backup a given encryption key
/// This makes a client request to [backup_encryption_key]
pub async fn request_backup_encryption_key(
    key: [u8; 32],
    key_provider_details: KeyProviderDetails,
    sr25519_pair: &sr25519::Pair,
) -> Result<(), KeyProviderError> {
    let quote = Vec::new(); // TODO

    let key_request =
        BackupEncryptionKeyRequest { tss_account: key_provider_details.tss_account, quote, key };

    let signed_message = EncryptedSignedMessage::new(
        sr25519_pair,
        serde_json::to_vec(&key_request).unwrap(),
        &key_provider_details.provider.x25519_public_key,
        &[],
    )
    .unwrap();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/backup_encryption_key", key_provider_details.provider.ip_address))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message).unwrap())
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await.unwrap();
        panic!("Bad status code {}: {}", status, text);
    }
    Ok(())
}

/// Make a request to a given TSS node to recover an encryption key
pub async fn request_recover_encryption_key(
    key_provider_details: KeyProviderDetails,
) -> Result<[u8; 32], KeyProviderError> {
    let quote = Vec::new(); // TODO

    // Generate encryption keypair used for receiving the key
    let response_secret_key = StaticSecret::random_from_rng(OsRng);
    let response_key = PublicKey::from(&response_secret_key).to_bytes();

    let key_request = RecoverEncryptionKeyRequest {
        tss_account: key_provider_details.tss_account,
        response_key,
        quote,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/recover_encryption_key", key_provider_details.provider.ip_address))
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

/// [ValidatorInfo] of a TSS node chosen to make a key backup, together with the account ID of the TSS
/// node who the backup is for
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProviderDetails {
    pub provider: ValidatorInfo,
    pub tss_account: SubxtAccountId32,
}

/// Payload of the encrypted POST request body for the `/backup_encryption_key` HTTP route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEncryptionKeyRequest {
    key: [u8; 32],
    tss_account: SubxtAccountId32,
    // TODO im not sure we need a quote here, as we should have registered with the staking pallet
    // by the time we make this request, so they can just check that which proves we have done an
    // attestation on chain
    quote: Vec<u8>,
}

/// POST request body for thse `/recover_encryption_key` HTTP route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverEncryptionKeyRequest {
    /// The account ID of the TSS node requesting to recover their encryption key
    tss_account: SubxtAccountId32,
    /// An ephemeral encryption public key used to receive and encrypted response
    response_key: X25519PublicKey,
    /// A TDX quote
    quote: Vec<u8>,
}

/// HTTP to backup an encryption key on initial launch
pub async fn backup_encryption_key(
    State(app_state): State<AppState>,
    Json(encrypted_backup_request): Json<EncryptedSignedMessage>,
) -> Result<(), KeyProviderError> {
    // Build quote input
    // Verify quote

    let signed_message = encrypted_backup_request.decrypt(&app_state.x25519_secret, &[]).unwrap();
    let backup_request: BackupEncryptionKeyRequest =
        serde_json::from_slice(&signed_message.message.0).unwrap();

    let mut backups = app_state.encryption_key_backups.write().unwrap();
    backups.insert(backup_request.tss_account.0, backup_request.key);

    Ok(())
}

/// HTTP endpoint to recover an encryption key following a process restart
pub async fn recover_encryption_key(
    State(app_state): State<AppState>,
    Json(key_request): Json<RecoverEncryptionKeyRequest>,
) -> Result<Json<EncryptedSignedMessage>, KeyProviderError> {
    // TODO Build quote input
    // TODO Verify quote
    //
    let backups = app_state.encryption_key_backups.read().unwrap();
    let key = backups.get(&key_request.tss_account.0).ok_or(KeyProviderError::NoKeyInStore)?;

    // Encrypt response
    let signed_message =
        EncryptedSignedMessage::new(&app_state.pair, key.to_vec(), &key_request.response_key, &[])
            .unwrap();
    Ok(Json(signed_message))
}

/// Create a backup of our key-value store encryption key by sending it to another TSS node to store
pub async fn make_key_backup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    key: [u8; 32],
    sr25519_pair: &sr25519::Pair,
    storage_path: PathBuf,
) {
    let tss_account = SubxtAccountId32(sr25519_pair.public().0);
    // Select a provider by making chain query and choosing a tss node
    let key_provider_details = select_key_provider(api, rpc, tss_account).await;
    // Get them to backup the key
    request_backup_encryption_key(key, key_provider_details.clone(), sr25519_pair).await.unwrap();
    // Store provider details so we know who to ask when recovering
    store_key_provider_details(storage_path, key_provider_details).unwrap();
}

/// Store the details of a TSS node who has a backup of our encryption key in a file
fn store_key_provider_details(
    mut path: PathBuf,
    key_provider_details: KeyProviderDetails,
) -> std::io::Result<()> {
    path.push(KEY_PROVIDER_FILENAME);
    std::fs::write(path, serde_json::to_vec(&key_provider_details).unwrap())
}

/// Retrieve the details of a TSS node who has a backup of our encryption key from a file
pub fn get_key_provider_details(mut path: PathBuf) -> std::io::Result<KeyProviderDetails> {
    path.push(KEY_PROVIDER_FILENAME);
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes).unwrap())
}

/// Choose a TSS node to request to make a backup from
async fn select_key_provider(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    tss_account: SubxtAccountId32,
) -> KeyProviderDetails {
    let validators_query = entropy::storage().session().validators();
    let validators = query_chain(api, rpc, validators_query, None).await.unwrap().unwrap();
    // .ok_or_else(|| SubgroupGetError::ChainFetch("Error getting validators"))?;

    let mut deterministic_rng = StdRng::from_seed(tss_account.0);
    let random_index = deterministic_rng.gen_range(0..validators.len());
    let validator = &validators[random_index];

    let threshold_address_query =
        entropy::storage().staking_extension().threshold_servers(validator);
    let server_info = query_chain(api, rpc, threshold_address_query, None).await.unwrap().unwrap();
    // .ok_or_else(|| SubgroupGetError::ChainFetch("threshold_servers query error"))?;
    KeyProviderDetails {
        provider: ValidatorInfo {
            x25519_public_key: server_info.x25519_public_key,
            ip_address: std::str::from_utf8(&server_info.endpoint).unwrap().to_string(),
            tss_account: server_info.tss_account,
        },
        tss_account,
    }
}
