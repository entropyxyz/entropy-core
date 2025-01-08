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

use std::{fs, path::PathBuf};

use crate::{chain_api::entropy, helpers::substrate::query_chain, AppState};
use clap::Parser;
use entropy_client::substrate::SubstrateError;
use entropy_kvdb::{
    encrypted_sled::PasswordMethod,
    kv_manager::{error::KvError, KvManager},
};
use entropy_shared::NETWORK_PARENT_KEY;
use serde::Deserialize;
use sp_core::crypto::Ss58Codec;

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

pub const LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH: &str = "LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH";

#[cfg(any(test, feature = "test_helpers"))]
pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

pub const FORBIDDEN_KEYS: [&str; 1] = [NETWORK_PARENT_KEY];

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

pub async fn load_kv_store(
    validator_name: &Option<ValidatorName>,
    password_path: Option<PathBuf>,
) -> KvManager {
    let mut root: PathBuf = PathBuf::from(entropy_kvdb::get_db_path(false));
    if cfg!(test) {
        return KvManager::new(
            entropy_kvdb::get_db_path(true).into(),
            PasswordMethod::NoPassword.execute().unwrap(),
        )
        .unwrap();
    }

    if validator_name == &Some(ValidatorName::Alice) {
        return KvManager::new(root, PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    };

    if validator_name == &Some(ValidatorName::Bob) {
        root.push("bob");
        return KvManager::new(root, PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    };

    if validator_name == &Some(ValidatorName::Charlie) {
        root.push("charlie");
        return KvManager::new(root, PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    };

    if validator_name == &Some(ValidatorName::Dave) {
        root.push("dave");
        return KvManager::new(root, PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    };

    if validator_name == &Some(ValidatorName::Eve) {
        root.push("eve");
        return KvManager::new(root, PasswordMethod::NoPassword.execute().unwrap()).unwrap();
    };

    let password = if let Some(password_path) = password_path {
        std::str::from_utf8(&fs::read(password_path).expect("error reading password file"))
            .expect("failed to convert password to string")
            .trim()
            .to_string()
            .into()
    } else {
        PasswordMethod::Prompt.execute().unwrap()
    };

    // this step takes a long time due to password-based decryption
    KvManager::new(root, password).unwrap()
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

pub async fn check_node_prerequisites(app_state: AppState) -> Result<(), &'static str> {
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
    tracing::info!("TSS node passed all prerequisite checks and is ready");
    app_state.make_ready();
    Ok(())
}
