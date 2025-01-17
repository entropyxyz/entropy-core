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
    attestation::api::create_quote, chain_api::entropy, key_provider::errors::KeyProviderError,
    validation::EncryptedSignedMessage, AppState, EntropyConfig, SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_client::substrate::query_chain;
use entropy_shared::{user::ValidatorInfo, QuoteContext, QuoteInputData, X25519PublicKey};
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
    let key_request =
        BackupEncryptionKeyRequest { tss_account: key_provider_details.tss_account, key };

    let signed_message = EncryptedSignedMessage::new(
        sr25519_pair,
        serde_json::to_vec(&key_request)?,
        &key_provider_details.provider.x25519_public_key,
        &[],
    )?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/backup_encryption_key", key_provider_details.provider.ip_address))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&signed_message)?)
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await?;
        return Err(KeyProviderError::BadProviderResponse(status, text));
    }
    Ok(())
}

/// Make a request to a given TSS node to recover an encryption key
pub async fn request_recover_encryption_key(
    key_provider_details: KeyProviderDetails,
) -> Result<[u8; 32], KeyProviderError> {
    // Generate encryption keypair used for receiving the key
    let response_secret_key = StaticSecret::random_from_rng(OsRng);
    let response_key = PublicKey::from(&response_secret_key).to_bytes();

    // TODO This is tricky as having to request a nonce means we need 2 request-responses to recover the
    // key
    let quote_nonce = [0; 32];

    // Quote input should contain: key_provider_details.tss_account, and response_key
    let quote = create_quote(
        quote_nonce,
        key_provider_details.tss_account.clone(),
        &response_secret_key,
        QuoteContext::EncryptionKeyRecoveryRequest,
    )
    .await?;

    let key_request = RecoverEncryptionKeyRequest {
        tss_account: key_provider_details.tss_account,
        response_key,
        quote,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{}/recover_encryption_key", key_provider_details.provider.ip_address))
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&key_request)?)
        .send()
        .await?;

    let status = response.status();
    if status != reqwest::StatusCode::OK {
        let text = response.text().await?;
        return Err(KeyProviderError::BadProviderResponse(status, text));
    }

    let response_bytes = response.bytes().await?;

    let encrypted_response: EncryptedSignedMessage = serde_json::from_slice(&response_bytes)?;
    let signed_message = encrypted_response.decrypt(&response_secret_key, &[])?;

    signed_message.message.0.try_into().map_err(|_| KeyProviderError::BadKeyLength)
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
    /// The encryption key to be backed-up
    key: [u8; 32],
    /// The account ID of the TSS node for whom the backup should be made
    tss_account: SubxtAccountId32,
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
    let signed_message = encrypted_backup_request.decrypt(&app_state.x25519_secret, &[])?;
    let backup_request: BackupEncryptionKeyRequest =
        serde_json::from_slice(&signed_message.message.0)?;

    // Check for tss account on the staking pallet - which proves they have made an on-chain attestation
    let threshold_address_query =
        entropy::storage().staking_extension().threshold_to_stash(&backup_request.tss_account);
    let (api, rpc) = app_state.get_api_rpc().await?;
    query_chain(&api, &rpc, threshold_address_query, None)
        .await?
        .ok_or(KeyProviderError::NotRegisteredWithStakingPallet)?;

    let mut backups =
        app_state.encryption_key_backups.write().map_err(|_| KeyProviderError::RwLockPoison)?;
    backups.insert(backup_request.tss_account.0, backup_request.key);

    Ok(())
}

/// HTTP endpoint to recover an encryption key following a process restart
pub async fn recover_encryption_key(
    State(app_state): State<AppState>,
    Json(key_request): Json<RecoverEncryptionKeyRequest>,
) -> Result<Json<EncryptedSignedMessage>, KeyProviderError> {
    // TODO verify quote - and move verifying quote logic to the attestation module
    // let quote = Quote::from_bytes(&quote).map_err(|_| VerifyQuoteError::BadQuote)?;

    let nonce = [0; 32]; // TODO
    let _expected_input_data = QuoteInputData::new(
        key_request.tss_account.clone(),
        key_request.response_key,
        nonce,
        QuoteContext::EncryptionKeyRecoveryRequest,
    );
    // if quote.report_input_data() != expected_input_data.0 {
    //     return Err(KeyProviderError::BadQuoteInputData);
    // }

    // Check build-time measurement matches a current-supported release of entropy-tss
    // let mrtd_value =
    //     BoundedVec::try_from(quote.mrtd().to_vec()).map_err(|_| VerifyQuoteError::BadMrtdValue)?;
    // let accepted_mrtd_values = pallet_parameters::Pallet::<T>::accepted_mrtd_values();
    // ensure!(accepted_mrtd_values.contains(&mrtd_value), VerifyQuoteError::BadMrtdValue);
    //
    // let pck = verify_pck_certificate_chain(&quote)?;

    let backups =
        app_state.encryption_key_backups.read().map_err(|_| KeyProviderError::RwLockPoison)?;
    let key = backups.get(&key_request.tss_account.0).ok_or(KeyProviderError::NoKeyInStore)?;

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
) -> Result<(), KeyProviderError> {
    let tss_account = SubxtAccountId32(sr25519_pair.public().0);
    // Select a provider by making chain query and choosing a tss node
    let key_provider_details = select_key_provider(api, rpc, tss_account).await?;
    // Get them to backup the key
    request_backup_encryption_key(key, key_provider_details.clone(), sr25519_pair).await?;
    // Store provider details so we know who to ask when recovering
    store_key_provider_details(storage_path, key_provider_details)?;
    Ok(())
}

/// Store the details of a TSS node who has a backup of our encryption key in a file
fn store_key_provider_details(
    mut path: PathBuf,
    key_provider_details: KeyProviderDetails,
) -> Result<(), KeyProviderError> {
    path.push(KEY_PROVIDER_FILENAME);
    Ok(std::fs::write(path, serde_json::to_vec(&key_provider_details)?)?)
}

/// Retrieve the details of a TSS node who has a backup of our encryption key from a file
pub fn get_key_provider_details(mut path: PathBuf) -> Result<KeyProviderDetails, KeyProviderError> {
    path.push(KEY_PROVIDER_FILENAME);
    let bytes = std::fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Choose a TSS node to request to make a backup from
async fn select_key_provider(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    tss_account: SubxtAccountId32,
) -> Result<KeyProviderDetails, KeyProviderError> {
    let validators_query = entropy::storage().session().validators();
    let validators = query_chain(api, rpc, validators_query, None).await?.unwrap();

    let mut deterministic_rng = StdRng::from_seed(tss_account.0);
    let random_index = deterministic_rng.gen_range(0..validators.len());
    let validator = &validators[random_index];

    let threshold_address_query =
        entropy::storage().staking_extension().threshold_servers(validator);
    let server_info = query_chain(api, rpc, threshold_address_query, None).await?.unwrap();

    Ok(KeyProviderDetails {
        provider: ValidatorInfo {
            x25519_public_key: server_info.x25519_public_key,
            ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
            tss_account: server_info.tss_account,
        },
        tss_account,
    })
}
