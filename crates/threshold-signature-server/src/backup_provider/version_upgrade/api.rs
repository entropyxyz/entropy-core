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
use crate::{
    backup_provider::api::{
        get_key_provider_details, store_key_provider_details, BackupProviderDetails,
    },
    chain_api::entropy,
    helpers::substrate::query_chain,
    node_info::api::version,
    validation::EncryptedSignedMessage,
    AppState, SubxtAccountId32,
};
use axum::{extract::State, Json};
use entropy_kvdb::{
    kv_manager::helpers::{deserialize, serialize},
    DbDump,
};
use entropy_shared::NEXT_NETWORK_PARENT_KEY;
use serde::{Deserialize, Serialize};

use super::errors::BackupEncryptedDbError;

/// The backup payload
#[derive(Debug, Serialize, Deserialize)]
struct DbBackup {
    /// entropy-tss version info so we know which version this backup was made with
    version: String,
    /// Details of the TSS node who holds the encryption key for this db
    backup_provider_details: BackupProviderDetails,
    /// The encrypted key-value store dump
    db_dump: DbDump,
}

/// HTTP POST route which produces and encrypted db backup together with recovery details
pub async fn backup_encrypted_db(
    State(app_state): State<AppState>,
    Json(encrypted_nonce): Json<EncryptedSignedMessage>,
) -> Result<Vec<u8>, BackupEncryptedDbError> {
    if !app_state.is_ready() {
        return Err(BackupEncryptedDbError::NotReady);
    }

    let signed_message = encrypted_nonce.decrypt(&app_state.x25519_secret, &[])?;
    let stash_account = SubxtAccountId32(signed_message.sender.0);

    // To prove that the caller is the node operator, check that this is our associated stash
    // account
    let threshold_address_query =
        entropy::storage().staking_extension().threshold_to_stash(app_state.subxt_account_id());
    let (api, rpc) = app_state.get_api_rpc().await?;
    let actual_stash_account = query_chain(&api, &rpc, threshold_address_query, None)
        .await?
        .ok_or(BackupEncryptedDbError::CannotGetStashAccount)?;
    if actual_stash_account != stash_account {
        return Err(BackupEncryptedDbError::Unauthorized);
    }

    // TODO to protect against replay attacts the message should contain a nonce
    // let nonce: [u8; 32] =
    //     signed_message.message.0.try_into().map_err(|_| BackupEncryptedDbError::BadNonceLength)?;

    // Check that we are not a signer
    if app_state.kv_store.kv().exists(&hex::encode(NEXT_NETWORK_PARENT_KEY)).await?
        || app_state.kv_store.kv().exists(&hex::encode(NEXT_NETWORK_PARENT_KEY)).await?
    {
        return Err(BackupEncryptedDbError::CannotUpgradeWhileSigner);
    }

    // Make the backup
    let storage_path = app_state.kv_store.storage_path().to_path_buf();
    let db_backup = DbBackup {
        version: version().await,
        backup_provider_details: get_key_provider_details(storage_path)?,
        db_dump: app_state.kv_store.kv().export_db().await?,
    };

    Ok(serialize(&db_backup).unwrap())
}

/// HTTP POST route which takes an encrypted db backup together with recovery details and recovers
/// them
pub async fn recover_encrypted_db(
    State(app_state): State<AppState>,
    Json(encrypted_db_backup): Json<EncryptedSignedMessage>,
) -> Result<(), BackupEncryptedDbError> {
    // This can only be called in a non-ready state - that is you cant recover a backup when the
    // node is already up and running
    if app_state.is_ready() {
        return Err(BackupEncryptedDbError::Ready);
    }
    let signed_message = encrypted_db_backup.decrypt(&app_state.x25519_secret, &[])?;
    let _stash_account = SubxtAccountId32(signed_message.sender.0);

    let db_backup: DbBackup = deserialize(&signed_message.message.0).unwrap();

    // TODO version check
    // Based on version, filter db keys into the ones that are still relevant

    let storage_path = app_state.kv_store.storage_path().to_path_buf();
    store_key_provider_details(storage_path, db_backup.backup_provider_details)?;
    app_state.kv_store.kv().import_db(db_backup.db_dump).await?;

    // TODO now we need to check that we can move to a ready state, and do an on-chain check that
    // the stash account is correct.
    // eg: loop with a timer, polling app_state.is_ready()
    // Do stash account check like above
    // If it fails we probably need to restore the old db.
    // Another approach would be to make the on-chain check before, reading the TSS account ID
    // directly out of the db dump
    //
    // But then we should still check here that we can get to ready state
    Ok(())
}
