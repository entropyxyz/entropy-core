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
    attestation::api::{create_quote, verify_pck_certificate_chain},
    backup_provider::errors::BackupProviderError,
    chain_api::entropy,
    validation::EncryptedSignedMessage,
    AppState, EntropyConfig, SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_client::substrate::query_chain;
use entropy_shared::{user::ValidatorInfo, QuoteContext, QuoteInputData, X25519PublicKey};
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use std::path::PathBuf;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use tdx_quote::Quote;
use x25519_dalek::{PublicKey, StaticSecret};

const BACKUP_PROVIDER_FILENAME: &str = "backup-provider-details.json";

/// Make a request to a given TSS node to backup a given encryption key
/// This makes a client request to [backup_encryption_key]
pub async fn request_backup_encryption_key(
    key: [u8; 32],
    backup_provider_details: BackupProviderDetails,
    sr25519_pair: &sr25519::Pair,
) -> Result<(), BackupProviderError> {
    let signed_message = EncryptedSignedMessage::new(
        sr25519_pair,
        key.to_vec(),
        &backup_provider_details.provider.x25519_public_key,
        &[],
    )?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/backup_provider/backup_encryption_key",
            backup_provider_details.provider.ip_address
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message)?)
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await?;
        return Err(BackupProviderError::BadProviderResponse(status, text));
    }
    Ok(())
}

/// Make a request to a given TSS node to recover an encryption key
pub async fn request_recover_encryption_key(
    backup_provider_details: BackupProviderDetails,
) -> Result<[u8; 32], BackupProviderError> {
    // Generate encryption keypair used for receiving the key
    let response_secret_key = StaticSecret::random_from_rng(OsRng);
    let response_key = PublicKey::from(&response_secret_key).to_bytes();

    let quote_nonce = request_quote_nonce(&response_secret_key, &backup_provider_details).await?;

    // Quote input contains: key_provider_details.tss_account, and response_key
    let quote = create_quote(
        quote_nonce,
        backup_provider_details.tss_account.clone(),
        &response_secret_key,
        QuoteContext::EncryptionKeyRecoveryRequest,
    )
    .await?;

    let key_request = RecoverEncryptionKeyRequest {
        tss_account: backup_provider_details.tss_account,
        response_key,
        quote,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/backup_provider/recover_encryption_key",
            backup_provider_details.provider.ip_address
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&key_request)?)
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await?;
        return Err(BackupProviderError::BadProviderResponse(status, text));
    }

    let response_bytes = response.bytes().await?;

    let encrypted_response: EncryptedSignedMessage = serde_json::from_slice(&response_bytes)?;
    let signed_message = encrypted_response.decrypt(&response_secret_key, &[])?;

    signed_message.message.0.try_into().map_err(|_| BackupProviderError::BadKeyLength)
}

/// [ValidatorInfo] of a TSS node chosen to make a key backup, together with the account ID of the TSS
/// node who the backup is for
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupProviderDetails {
    pub provider: ValidatorInfo,
    pub tss_account: SubxtAccountId32,
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

/// HTTP endpoint to backup an encryption key on initial launch
/// The request body should be an encryption key to backup as a [u8; 32] wrapped in an [EncryptedSignedMessage]
pub async fn backup_encryption_key(
    State(app_state): State<AppState>,
    Json(encrypted_backup_request): Json<EncryptedSignedMessage>,
) -> Result<(), BackupProviderError> {
    let signed_message = encrypted_backup_request.decrypt(&app_state.x25519_secret, &[])?;
    let key: [u8; 32] =
        signed_message.message.0.try_into().map_err(|_| BackupProviderError::BadKeyLength)?;

    let tss_account = SubxtAccountId32(signed_message.sender.0);
    // Check for tss account on the staking pallet - which proves they have made an on-chain attestation
    let threshold_address_query =
        entropy::storage().staking_extension().threshold_to_stash(&tss_account);
    let (api, rpc) = app_state.get_api_rpc().await?;
    query_chain(&api, &rpc, threshold_address_query, None)
        .await?
        .ok_or(BackupProviderError::NotRegisteredWithStakingPallet)?;

    let mut backups =
        app_state.encryption_key_backups.write().map_err(|_| BackupProviderError::RwLockPoison)?;
    backups.insert(tss_account.0, key);

    Ok(())
}

/// HTTP endpoint to recover an encryption key following a process restart.
/// The request body should contain a JSON encoded [RecoverEncryptionKeyRequest].
/// If successfull, the response body will contain the encryption key as a [u8; 32] wrapped in an
/// [EncryptedSignedMessage].
pub async fn recover_encryption_key(
    State(app_state): State<AppState>,
    Json(key_request): Json<RecoverEncryptionKeyRequest>,
) -> Result<Json<EncryptedSignedMessage>, BackupProviderError> {
    let quote = Quote::from_bytes(&key_request.quote)?;

    let nonce = {
        let nonces =
            app_state.attestation_nonces.read().map_err(|_| BackupProviderError::RwLockPoison)?;
        nonces.get(&key_request.response_key).ok_or(BackupProviderError::NoNonceInStore)?.clone()
    };

    let expected_input_data = QuoteInputData::new(
        key_request.tss_account.clone(),
        key_request.response_key,
        nonce,
        QuoteContext::EncryptionKeyRecoveryRequest,
    );
    if quote.report_input_data() != expected_input_data.0 {
        return Err(BackupProviderError::BadQuoteInputData);
    }

    // Check build-time measurement matches a current-supported release of entropy-tss
    // This bit differs slightly in the attestation pallet implementation vs entropy-tss
    // because here we don't have direct access to the parameters pallet - we need to make a query
    let mrtd_value = quote.mrtd().to_vec();
    let query = entropy::storage().parameters().accepted_mrtd_values();
    let (api, rpc) = app_state.get_api_rpc().await?;
    let accepted_mrtd_values: Vec<_> = query_chain(&api, &rpc, query, None)
        .await?
        .ok_or(BackupProviderError::NoMeasurementValues)?
        .into_iter()
        .map(|v| v.0)
        .collect();
    if !accepted_mrtd_values.contains(&mrtd_value) {
        return Err(entropy_shared::VerifyQuoteError::BadMrtdValue.into());
    };

    let _pck = verify_pck_certificate_chain(&quote)?;

    let backups =
        app_state.encryption_key_backups.read().map_err(|_| BackupProviderError::RwLockPoison)?;
    let key = backups.get(&key_request.tss_account.0).ok_or(BackupProviderError::NoKeyInStore)?;

    // Encrypt response
    let signed_message =
        EncryptedSignedMessage::new(&app_state.pair, key.to_vec(), &key_request.response_key, &[])?;
    Ok(Json(signed_message))
}

/// Create a backup of our key-value store encryption key by sending it to another TSS node to store
pub async fn make_key_backup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    key: [u8; 32],
    sr25519_pair: &sr25519::Pair,
    storage_path: PathBuf,
) -> Result<(), BackupProviderError> {
    let tss_account = SubxtAccountId32(sr25519_pair.public().0);
    // Select a provider by making chain query and choosing a tss node
    let key_provider_details = select_backup_provider(api, rpc, tss_account).await?;
    // Get them to backup the key
    request_backup_encryption_key(key, key_provider_details.clone(), sr25519_pair).await?;
    // Store provider details so we know who to ask when recovering
    store_key_provider_details(storage_path, key_provider_details)?;
    Ok(())
}

/// Store the details of a TSS node who has a backup of our encryption key in a file
fn store_key_provider_details(
    mut path: PathBuf,
    backup_provider_details: BackupProviderDetails,
) -> Result<(), BackupProviderError> {
    path.push(BACKUP_PROVIDER_FILENAME);
    Ok(std::fs::write(path, serde_json::to_vec(&backup_provider_details)?)?)
}

/// Retrieve the details of a TSS node who has a backup of our encryption key from a file
pub fn get_key_provider_details(
    mut path: PathBuf,
) -> Result<BackupProviderDetails, BackupProviderError> {
    path.push(BACKUP_PROVIDER_FILENAME);
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Choose a TSS node to request to make a backup
async fn select_backup_provider(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    tss_account: SubxtAccountId32,
) -> Result<BackupProviderDetails, BackupProviderError> {
    let validators_query = entropy::storage().session().validators();
    let validators = query_chain(api, rpc, validators_query, None)
        .await?
        .ok_or(BackupProviderError::NoValidators)?;
    if validators.is_empty() {
        return Err(BackupProviderError::NoValidators);
    }

    let mut deterministic_rng = StdRng::from_seed(tss_account.0);
    let random_index = deterministic_rng.gen_range(0..validators.len());
    let validator = &validators[random_index];

    let threshold_address_query =
        entropy::storage().staking_extension().threshold_servers(validator);
    let server_info = query_chain(api, rpc, threshold_address_query, None)
        .await?
        .ok_or(BackupProviderError::NoServerInfo)?;

    Ok(BackupProviderDetails {
        provider: ValidatorInfo {
            x25519_public_key: server_info.x25519_public_key,
            ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
            tss_account: server_info.tss_account,
        },
        tss_account,
    })
}

pub async fn quote_nonce(
    State(app_state): State<AppState>,
    Json(response_key): Json<X25519PublicKey>,
) -> Result<Json<EncryptedSignedMessage>, BackupProviderError> {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut nonces =
        app_state.attestation_nonces.write().map_err(|_| BackupProviderError::RwLockPoison)?;
    nonces.insert(response_key, nonce);
    // Encrypt response
    let signed_message =
        EncryptedSignedMessage::new(&app_state.pair, nonce.to_vec(), &response_key, &[])?;
    Ok(Json(signed_message))
}

async fn request_quote_nonce(
    response_secret_key: &StaticSecret,
    backup_provider_details: &BackupProviderDetails,
) -> Result<[u8; 32], BackupProviderError> {
    let response_key = PublicKey::from(response_secret_key).to_bytes();

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/backup_provider/quote_nonce",
            backup_provider_details.provider.ip_address
        ))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&response_key)?)
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await?;
        return Err(BackupProviderError::BadProviderResponse(status, text));
    }

    let response_bytes = response.bytes().await?;

    let encrypted_response: EncryptedSignedMessage = serde_json::from_slice(&response_bytes)?;
    let signed_message = encrypted_response.decrypt(response_secret_key, &[])?;

    signed_message.message.0.try_into().map_err(|_| BackupProviderError::BadKeyLength)
}
