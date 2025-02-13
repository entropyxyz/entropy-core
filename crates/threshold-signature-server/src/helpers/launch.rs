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

//! Utilities for starting and running the server.

use std::path::PathBuf;

use crate::{
    backup_provider::api::{
        get_key_provider_details, make_key_backup, request_recover_encryption_key,
    },
    chain_api::entropy,
    helpers::{substrate::query_chain, validator::get_signer_and_x25519_secret},
    AppState,
};
use clap::Parser;
use entropy_client::substrate::SubstrateError;
use entropy_kvdb::kv_manager::{error::KvError, KvManager};
use rand::RngCore;
use rand_core::OsRng;
use serde::Deserialize;
use sp_core::crypto::Ss58Codec;
use sp_core::{sr25519, Pair};
use x25519_dalek::StaticSecret;

pub const DEFAULT_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";
pub const DEFAULT_BOB_MNEMONIC: &str =
    "where sight patient orphan general short empower hope party hurt month voice";
pub const DEFAULT_ALICE_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";
pub const DEFAULT_CHARLIE_MNEMONIC: &str =
    "lake carry still awful point mention bike category tornado plate brass lock";
pub const DEFAULT_DAVE_MNEMONIC: &str =
    "beef dutch panic monkey black glad audit twice humor gossip wealth drive";
pub const DEFAULT_EVE_MNEMONIC: &str =
    "impact federal dish number fun crisp various wedding radio immense whisper glue";
pub const LATEST_BLOCK_NUMBER_NEW_USER: &str = "LATEST_BLOCK_NUMBER_NEW_USER";
pub const LATEST_BLOCK_NUMBER_RESHARE: &str = "LATEST_BLOCK_NUMBER_RESHARE";
pub const LATEST_BLOCK_NUMBER_ATTEST: &str = "LATEST_BLOCK_NUMBER_ATTEST";
pub const LATEST_BLOCK_NUMBER: &str = "LATEST_BLOCK_NUMBER";

pub const LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH: &str = "LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH";

const X25519_SECRET: &str = "X25519_SECRET";
const SR25519_SEED: &str = "SR25519_SEED";

#[cfg(any(test, feature = "test_helpers"))]
pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

pub const KEY_MNEMONIC: &str = "MNEMONIC";

// Deafult name for TSS server
// Will set mnemonic and db path
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ValidatorName {
    Alice,
    Bob,
    Charlie,
    Dave,
    Eve,
}

impl std::fmt::Display for ValidatorName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

/// Output for --setup-only flag
#[derive(Deserialize, Debug, Clone)]
pub struct SetupOnlyOutput {
    pub dh_public_key: String,
    pub account_id: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Configuration {
    pub endpoint: String,
}

impl Configuration {
    pub fn new(endpoint: String) -> Configuration {
        Configuration { endpoint }
    }
}

/// Setup the encrypted key-value store, recovering the encryption key if needed
/// Returns the kv store, the TSS keypairs, and the encryption key if it needs to be backed-up
pub async fn setup_kv_store(
    validator_name: &Option<ValidatorName>,
    storage_path: Option<PathBuf>,
) -> anyhow::Result<(KvManager, sr25519::Pair, StaticSecret, Option<[u8; 32]>)> {
    let storage_path = storage_path.unwrap_or_else(|| build_db_path(validator_name));

    // Check for existing database with backup details
    if let Ok(key_provider_details) = get_key_provider_details(storage_path.clone()) {
        // Retrieve encryption key from another TSS node
        let key = request_recover_encryption_key(key_provider_details).await?;

        // Open existing db with recovered key
        let kv_manager = KvManager::new(storage_path, key)?;

        // Get keypairs from existing db
        let x25519_secret: [u8; 32] = kv_manager
            .kv()
            .get(X25519_SECRET)
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("X25519 secret from db is not 32 bytes"))?;
        let sr25519_seed: [u8; 32] = kv_manager
            .kv()
            .get(SR25519_SEED)
            .await?
            .try_into()
            .map_err(|_| anyhow::anyhow!("sr25519 seed from db is not 32 bytes"))?;
        let pair = sr25519::Pair::from_seed(&sr25519_seed);
        Ok((kv_manager, pair, x25519_secret.into(), None))
    } else {
        // Generate TSS account (or use ValidatorName to get a test account)
        let (pair, seed, x25519_secret, encryption_key) = if cfg!(test) || validator_name.is_some()
        {
            let (pair, seed, x25519_secret) =
                get_signer_and_x25519_secret(&development_mnemonic(validator_name).to_string())?;
            // For testing, the db encryption key is just the TSS account id
            let encryption_key = pair.public().0;
            (pair, seed, x25519_secret, encryption_key)
        } else {
            // Generate new keys
            let (pair, seed) = sr25519::Pair::generate();
            let x25519_secret = StaticSecret::random_from_rng(OsRng);
            let mut encryption_key = [0; 32];
            OsRng.fill_bytes(&mut encryption_key);
            (pair, seed, x25519_secret, encryption_key)
        };

        // Open store with generated key
        let kv_manager = KvManager::new(storage_path, encryption_key)?;

        // Store TSS secret keys in kv store
        let reservation = kv_manager.kv().reserve_key(X25519_SECRET.to_string()).await?;
        kv_manager.kv().put(reservation, x25519_secret.to_bytes().to_vec()).await?;
        let reservation = kv_manager.kv().reserve_key(SR25519_SEED.to_string()).await?;
        kv_manager.kv().put(reservation, seed.to_vec()).await?;

        // Return the encryption key so that it can be backed up as part of the pre-requisite checks
        Ok((kv_manager, pair, x25519_secret, Some(encryption_key)))
    }
}

/// Build the storage path for the key-value store, providing separate subdirectories for the
/// different test accounts when testing
pub fn build_db_path(validator_name: &Option<ValidatorName>) -> PathBuf {
    if cfg!(test) {
        return PathBuf::from(entropy_kvdb::get_db_path(true));
    }

    let mut root: PathBuf = PathBuf::from(entropy_kvdb::get_db_path(false));
    // Alice has no extra subdirectory
    if validator_name == &Some(ValidatorName::Bob) {
        root.push("bob");
    };

    if validator_name == &Some(ValidatorName::Charlie) {
        root.push("charlie");
    };

    if validator_name == &Some(ValidatorName::Dave) {
        root.push("dave");
    };

    if validator_name == &Some(ValidatorName::Eve) {
        root.push("eve");
    };
    root
}

#[derive(Parser, Debug, Clone)]
#[command(about, version)]
pub struct StartupArgs {
    /// Use the developer key Bob.
    #[arg(short = 'b', long = "bob")]
    pub bob: bool,
    /// Use the developer key Alice.
    #[arg(short = 'a', long = "alice")]
    pub alice: bool,
    /// Use the developer key dave.
    #[arg(long = "charlie")]
    pub charlie: bool,
    /// Use the developer key dave.
    #[arg(long = "dave")]
    pub dave: bool,
    /// Use the developer key Eve.
    #[arg(short = 'e', long = "eve")]
    pub eve: bool,
    /// Websocket endpoint for the entropy blockchain.
    #[arg(
        short = 'c',
        long = "chain-endpoint",
        required = false,
        default_value = "ws://localhost:9944"
    )]
    pub chain_endpoint: String,
    /// Url to host threshold (axum) server on.
    #[arg(short = 'u', long = "threshold-url", required = false, default_value = "127.0.0.1:3001")]
    pub threshold_url: String,

    /// Whether to allow a validator key to be null.
    #[arg(short = 'd', long = "dev")]
    pub dev: bool,

    /// Whether or not to execute a specific test
    #[cfg(test)]
    #[arg(long = "test", required = false, default_value = "*")]
    pub test: String,

    /// Whether or not to print stdout during testing
    #[arg(long = "nocapture")]
    pub nocapture: bool,

    /// The configuration settings around logging.
    #[clap(flatten)]
    pub logger: crate::helpers::logger::Instrumentation,

    /// The path to a password file
    #[arg(short = 'f', long = "password-file")]
    pub password_file: Option<PathBuf>,
}

pub fn development_mnemonic(validator_name: &Option<ValidatorName>) -> bip39::Mnemonic {
    let mnemonic = if let Some(validator_name) = validator_name {
        match validator_name {
            ValidatorName::Alice => DEFAULT_ALICE_MNEMONIC,
            ValidatorName::Bob => DEFAULT_BOB_MNEMONIC,
            ValidatorName::Charlie => DEFAULT_CHARLIE_MNEMONIC,
            ValidatorName::Dave => DEFAULT_DAVE_MNEMONIC,
            ValidatorName::Eve => DEFAULT_EVE_MNEMONIC,
        }
    } else {
        DEFAULT_MNEMONIC
    };

    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
        .expect("Unable to parse given mnemonic.")
}

pub async fn setup_latest_block_number(kv: &KvManager) -> Result<(), KvError> {
    let exists_result_new_user =
        kv.kv().exists(LATEST_BLOCK_NUMBER_NEW_USER).await.expect("issue querying DB");
    if !exists_result_new_user {
        let reservation = kv
            .kv()
            .reserve_key(LATEST_BLOCK_NUMBER_NEW_USER.to_string())
            .await
            .expect("Issue reserving latest block number");
        kv.kv()
            .put(reservation, 0u32.to_be_bytes().to_vec())
            .await
            .expect("failed to update latest block number");
    }
    let exists_result_proactive_refresh =
        kv.kv().exists(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH).await.expect("issue querying DB");
    if !exists_result_proactive_refresh {
        let reservation = kv
            .kv()
            .reserve_key(LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH.to_string())
            .await
            .expect("Issue reserving latest block number");
        kv.kv()
            .put(reservation, 0u32.to_be_bytes().to_vec())
            .await
            .expect("failed to update latest block number");
    }
    let exists_result_reshare =
        kv.kv().exists(LATEST_BLOCK_NUMBER_RESHARE).await.expect("issue querying DB");
    if !exists_result_reshare {
        let reservation = kv
            .kv()
            .reserve_key(LATEST_BLOCK_NUMBER_RESHARE.to_string())
            .await
            .expect("Issue reserving latest block number");
        kv.kv()
            .put(reservation, 0u32.to_be_bytes().to_vec())
            .await
            .expect("failed to update latest block number");
    }
    let exists_result_attest =
        kv.kv().exists(LATEST_BLOCK_NUMBER_ATTEST).await.expect("issue querying DB");
    if !exists_result_attest {
        let reservation = kv
            .kv()
            .reserve_key(LATEST_BLOCK_NUMBER_ATTEST.to_string())
            .await
            .expect("Issue reserving latest block number");
        kv.kv()
            .put(reservation, 0u32.to_be_bytes().to_vec())
            .await
            .expect("failed to update latest block number");
    }
    Ok(())
}

pub async fn check_node_prerequisites(
    app_state: AppState,
    key_to_backup: Option<[u8; 32]>,
) -> Result<(), &'static str> {
    use crate::chain_api::{get_api, get_rpc};
    let url = &app_state.configuration.endpoint;
    let account_id = app_state.account_id();

    let connect_to_substrate_node = || async {
        tracing::info!("Attempting to establish connection to Substrate node at `{}`", url);

        let api = get_api(url).await.map_err(|_| {
            Err::<(), String>("Unable to connect to Substrate chain API".to_string())
        })?;

        let rpc = get_rpc(url)
            .await
            .map_err(|_| Err("Unable to connect to Substrate chain RPC".to_string()))?;

        Ok((api, rpc))
    };

    // Use the default maximum elapsed time of 15 minutes.
    // This means if we do not get a connection within 15 minutes the process will terminate and the
    // keypair will be lost.
    let backoff = backoff::ExponentialBackoff::default();

    let (api, rpc) = backoff::future::retry(backoff.clone(), connect_to_substrate_node)
        .await
        .map_err(|_| "Timed out waiting for connection to chain")?;

    tracing::info!("Sucessfully connected to Substrate node!");
    app_state.cache.connected_to_chain_node().map_err(|_| "Poisoned mutex")?;

    tracing::info!("Checking balance of threshold server AccountId `{}`", &account_id);

    let balance_query = || async {
        let has_minimum_balance = crate::validator::api::check_balance_for_fees(
            &api,
            &rpc,
            account_id.to_ss58check().to_string(),
            entropy_shared::MIN_BALANCE,
        )
        .await
        .map_err(|e| {
            tracing::warn!("Account: {} {}", &account_id, e);
            e.to_string()
        })?;
        if !has_minimum_balance {
            Err("Minimum balance not met".to_string())?
        }
        Ok(())
    };

    backoff::future::retry(backoff.clone(), balance_query)
        .await
        .map_err(|_| "Timed out waiting for account to be funded")?;

    tracing::info!("The account `{}` has enough funds for submitting extrinsics.", &account_id);

    // Now check if there exists a threshold server with our details - if there is not,
    // we need to wait until there is
    let check_for_tss_account_id = || async {
        let stash_address_query = entropy::storage()
            .staking_extension()
            .threshold_to_stash(subxt::utils::AccountId32(*account_id.as_ref()));

        let _stash_address =
            query_chain(&api, &rpc, stash_address_query, None).await?.ok_or_else(|| {
                tracing::warn!(
                    "TSS account ID {account_id} not yet registered on-chain - you need to \
                    call `validate` or `change_threshold_accounts`"
                );
                SubstrateError::NoEvent
            })?;
        Ok(())
    };

    tracing::info!("Checking if our account ID has been registered on chain `{}`", &account_id);
    backoff::future::retry(backoff, check_for_tss_account_id)
        .await
        .map_err(|_| "Timed out waiting for TSS account to be registered on chain")?;

    if let Some(key_to_backup) = key_to_backup {
        tracing::info!("Backing up keyshare...");
        make_key_backup(
            &api,
            &rpc,
            key_to_backup,
            &app_state.pair,
            app_state.kv_store.storage_path().to_path_buf(),
        )
        .await
        .map_err(|e| {
            tracing::error!("Could not make key backup: {}", e);
            "Could not make key backup"
        })?;
        tracing::info!("Successfully backed up keyshare");
    }

    tracing::info!("TSS node passed all prerequisite checks and is ready");
    app_state.cache.make_ready().map_err(|_| "Poisoned mutex")?;
    Ok(())
}
