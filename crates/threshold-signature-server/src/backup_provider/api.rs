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
    attestation::api::{check_quote_measurement, create_quote},
    backup_provider::errors::BackupProviderError,
    chain_api::entropy,
    validation::EncryptedSignedMessage,
    AppState, EntropyConfig, SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_client::substrate::query_chain;
use entropy_shared::{
    attestation::{verify_pck_certificate_chain, QuoteContext, QuoteInputData},
    user::ValidatorInfo,
    X25519PublicKey,
};
use rand::{seq::SliceRandom, RngCore};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sp_core::{sr25519, Pair};
use std::path::PathBuf;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};
use tdx_quote::Quote;
use x25519_dalek::{PublicKey, StaticSecret};

const BACKUP_PROVIDER_FILENAME: &str = "backup-provider-details.json";

/// Client function to make a request to a given TSS node to backup a given encryption key
/// This makes a client request to [backup_encryption_key]
pub async fn request_backup_encryption_key(
    key: [u8; 32],
    backup_provider_details: BackupProviderDetails,
    sr25519_pair: &sr25519::Pair,
) -> Result<(), BackupProviderError> {
    // Encrypt the key to the backup provider's public x25519 key
    let signed_message = EncryptedSignedMessage::new(
        sr25519_pair,
        key.to_vec(),
        &backup_provider_details.provider.x25519_public_key,
        &[],
    )?;

    // Make the request
    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/backup_encryption_key",
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
            "http://{}/recover_encryption_key",
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

    // Decrypt the response
    let encrypted_response: EncryptedSignedMessage = serde_json::from_slice(&response_bytes)?;
    let signed_message = encrypted_response.decrypt(&response_secret_key, &[])?;

    signed_message.message.0.try_into().map_err(|_| BackupProviderError::BadKeyLength)
}

/// [ValidatorInfo] of a TSS node chosen to make a key backup, together with the account ID of the
/// TSS node who the backup is for
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupProviderDetails {
    pub provider: ValidatorInfo,
    pub tss_account: SubxtAccountId32,
}

/// POST request body for the `/recover_encryption_key` HTTP route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverEncryptionKeyRequest {
    /// The account ID of the TSS node requesting to recover their encryption key
    tss_account: SubxtAccountId32,
    /// An ephemeral encryption public key used to receive an encrypted response
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
    if !app_state.is_ready() {
        return Err(BackupProviderError::NotReady);
    }

    // Decrypt the request body to get the key to be backed-up
    let signed_message = encrypted_backup_request.decrypt(&app_state.x25519_secret, &[])?;
    let tss_account = signed_message.account_id();
    let key: [u8; 32] =
        signed_message.message.0.try_into().map_err(|_| BackupProviderError::BadKeyLength)?;

    // Check for TSS account on the staking pallet - which proves they have made an on-chain attestation
    let threshold_address_query = entropy::storage()
        .staking_extension()
        .threshold_to_stash(SubxtAccountId32(*tss_account.as_ref()));
    let (api, rpc) = app_state.get_api_rpc().await?;
    query_chain(&api, &rpc, threshold_address_query, None)
        .await?
        .ok_or(BackupProviderError::NotRegisteredWithStakingPallet)?;

    let mut backups = app_state
        .encryption_key_backup_provider
        .write()
        .map_err(|_| BackupProviderError::RwLockPoison)?;
    backups.insert(tss_account, key);

    Ok(())
}

/// HTTP endpoint to recover an encryption key following a process restart.
/// The request body should contain a JSON encoded [RecoverEncryptionKeyRequest].
/// If successful, the response body will contain the encryption key as a [u8; 32] wrapped in an
/// [EncryptedSignedMessage].
pub async fn recover_encryption_key(
    State(app_state): State<AppState>,
    Json(key_request): Json<RecoverEncryptionKeyRequest>,
) -> Result<Json<EncryptedSignedMessage>, BackupProviderError> {
    if !app_state.is_ready() {
        return Err(BackupProviderError::NotReady);
    }

    let quote = Quote::from_bytes(&key_request.quote)?;

    let nonce = {
        let mut nonces =
            app_state.attestation_nonces.write().map_err(|_| BackupProviderError::RwLockPoison)?;
        nonces.remove(&key_request.response_key).ok_or(BackupProviderError::NoNonceInStore)?
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

    let (api, rpc) = app_state.get_api_rpc().await?;
    check_quote_measurement(&api, &rpc, &quote).await?;

    let _pck = verify_pck_certificate_chain(&quote)?;

    let key = {
        let backups = app_state
            .encryption_key_backup_provider
            .read()
            .map_err(|_| BackupProviderError::RwLockPoison)?;
        *backups.get(&key_request.tss_account.0.into()).ok_or(BackupProviderError::NoKeyInStore)?
    };

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
pub(crate) fn store_key_provider_details(
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
    // Get all active validators
    let validators_query = entropy::storage().session().validators();
    let validators = query_chain(api, rpc, validators_query, None)
        .await?
        .ok_or(BackupProviderError::NoValidators)?;
    if validators.is_empty() {
        return Err(BackupProviderError::NoValidators);
    }

    // Choose one randomly
    let validator = validators.choose(&mut OsRng).unwrap();

    // Get associated details
    let threshold_address_query =
        entropy::storage().staking_extension().threshold_servers(validator);
    let server_info = query_chain(api, rpc, threshold_address_query, None)
        .await?
        .ok_or(BackupProviderError::NoServerInfo)?;

    tracing::info!(
        "Selected TSS account {} to act as a db encrpytion key backup provider",
        server_info.tss_account
    );

    Ok(BackupProviderDetails {
        provider: ValidatorInfo {
            x25519_public_key: server_info.x25519_public_key,
            ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
            tss_account: server_info.tss_account,
        },
        tss_account,
    })
}

/// HTTP POST route which provides a quote nonce to be used in the quote when requesting to recover
/// an encryption key.
/// The nonce is returned encrypted with the given ephemeral public key. This key is also used as a
/// lookup key for the nonce.
pub async fn quote_nonce(
    State(app_state): State<AppState>,
    Json(response_key): Json<X25519PublicKey>,
) -> Result<Json<EncryptedSignedMessage>, BackupProviderError> {
    if !app_state.is_ready() {
        return Err(BackupProviderError::NotReady);
    }

    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);

    {
        let mut nonces =
            app_state.attestation_nonces.write().map_err(|_| BackupProviderError::RwLockPoison)?;
        nonces.insert(response_key, nonce);
    }

    // Encrypt response
    let signed_message =
        EncryptedSignedMessage::new(&app_state.pair, nonce.to_vec(), &response_key, &[])?;
    Ok(Json(signed_message))
}

/// Client function used to make a POST request to `backup_provider_quote_nonce`
async fn request_quote_nonce(
    response_secret_key: &StaticSecret,
    backup_provider_details: &BackupProviderDetails,
) -> Result<[u8; 32], BackupProviderError> {
    let response_key = PublicKey::from(response_secret_key).to_bytes();

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://{}/backup_provider_quote_nonce",
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
