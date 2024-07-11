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

use clap::Parser;
use entropy_kvdb::{
    encrypted_sled::PasswordMethod,
    kv_manager::{error::KvError, KvManager},
};
use serde::Deserialize;
use serde_json::json;
use subxt::ext::sp_core::{
    crypto::{AccountId32, Ss58Codec},
    sr25519, Pair,
};

use crate::helpers::validator::get_signer_and_x25519_secret;

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
pub const LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH: &str = "LATEST_BLOCK_NUMBER_PROACTIVE_REFRESH";

#[cfg(test)]
pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

pub const FORBIDDEN_KEYS: [&str; 3] =
    [FORBIDDEN_KEY_MNEMONIC, FORBIDDEN_KEY_SHARED_SECRET, FORBIDDEN_KEY_DIFFIE_HELLMAN_PUBLIC];

pub const FORBIDDEN_KEY_MNEMONIC: &str = "MNEMONIC";
pub const FORBIDDEN_KEY_SHARED_SECRET: &str = "SHARED_SECRET";
pub const FORBIDDEN_KEY_DIFFIE_HELLMAN_PUBLIC: &str = "DH_PUBLIC";

// Deafult name for TSS server
// Will set mnemonic and db path
#[derive(Debug, PartialEq)]
pub enum ValidatorName {
    Alice,
    Bob,
    Charlie,
    Dave,
    Eve,
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
    /// Indicates that a Threshold server **should not** ask its peers for key-share data.
    ///
    /// This is useful to avoid in cases where:
    ///
    /// - The network is being bootstrapped and peers don't have any useful data yet.
    ///
    /// - There is outdated information about peers (e.g, outdated IP addresses coming from the
    ///   on-chain registry) and we don't want to sync outdated key-shares.
    #[arg(short = 's', long = "no-sync")]
    pub no_sync: bool,
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

    /// Set up the key-value store (KVDB), or ensure one already exists, print setup information to
    /// stdout, then exit. Supply the `--password-file` option for fully non-interactive operation.
    ///
    /// Returns the AccountID and Diffie-Hellman Public Keys associated with this server.
    #[arg(long = "setup-only")]
    pub setup_only: bool,

    /// The BIP-39 mnemonic (i.e seed phrase) to use for deriving the Threshold Signature Server
    /// SR25519 account ID and the X25519 public key.
    ///
    /// The SR25519 account is responsible for signing and submitting extrinsics to the Entropy
    /// network.
    ///
    /// The X25519 public key is used for encrypting/decrypting messages to other threshold
    /// servers.
    ///
    /// Note that this may keep a mnemonic in your shell history. If you would like to avoid this
    /// use one of the alternative options, or tools like the 1Password CLI.
    ///
    /// **Alternatives**: There are two other ways to supply the mnemonic to the TSS: the
    /// `--mnemonic-file` flag and the `THRESHOLD_SERVER_MNEMONIC` environment variable.
    ///
    /// **Warning**: Passing this flag will overwrite any existing mnemonic! If you would like to
    /// use an existing mnemonic omit this flag when running the process.
    #[arg(long = "mnemonic")]
    pub mnemonic: Option<bip39::Mnemonic>,

    /// The path to a file containing the BIP-39 mnemonic (i.e seed phrase) to use for deriving the
    /// Threshold Signature Server SR25519 account ID and the X25519 public key.
    ///
    /// **Alternatives**: There are two other ways to supply the mnemonic to the TSS: the
    /// `--mnemonic` flag and the `THRESHOLD_SERVER_MNEMONIC` environment variable.
    ///
    /// **Warning**: Passing this flag will overwrite any existing mnemonic! If you would like to
    /// use an existing mnemonic omit this flag when running the process.
    #[arg(long = "mnemonic-file", conflicts_with = "mnemonic")]
    pub mnemonic_file: Option<PathBuf>,
}

pub async fn has_mnemonic(kv: &KvManager) -> bool {
    let exists = kv.kv().exists(FORBIDDEN_KEY_MNEMONIC).await.expect("issue querying DB");

    if exists {
        tracing::debug!("Existing mnemonic found in keystore.");
    }

    exists
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

pub async fn setup_mnemonic(kv: &KvManager, mnemonic: bip39::Mnemonic) {
    if has_mnemonic(kv).await {
        tracing::warn!("Deleting account related keys from KVDB.");

        kv.kv()
            .delete(FORBIDDEN_KEY_MNEMONIC)
            .await
            .expect("Error deleting existing mnemonic from KVDB.");
        kv.kv()
            .delete(FORBIDDEN_KEY_SHARED_SECRET)
            .await
            .expect("Error deleting shared secret from KVDB.");
        kv.kv()
            .delete(FORBIDDEN_KEY_DIFFIE_HELLMAN_PUBLIC)
            .await
            .expect("Error deleting X25519 public key from KVDB.");
    }

    tracing::info!("Writing new mnemonic to KVDB.");

    // Write our new mnemonic to the KVDB.
    let reservation = kv
        .kv()
        .reserve_key(FORBIDDEN_KEY_MNEMONIC.to_string())
        .await
        .expect("Issue reserving mnemonic");
    kv.kv()
        .put(reservation, mnemonic.to_string().as_bytes().to_vec())
        .await
        .expect("failed to update mnemonic");

    let (pair, static_secret) =
        get_signer_and_x25519_secret(kv).await.expect("Cannot derive keypairs");
    let x25519_public_key = x25519_dalek::PublicKey::from(&static_secret).to_bytes();

    // Write the shared secret in the KVDB
    let shared_secret_reservation = kv
        .kv()
        .reserve_key(FORBIDDEN_KEY_SHARED_SECRET.to_string())
        .await
        .expect("Issue reserving ss key");
    kv.kv()
        .put(shared_secret_reservation, static_secret.to_bytes().to_vec())
        .await
        .expect("failed to update secret share");

    // Write the Diffie-Hellman key in the KVDB
    let diffie_hellman_reservation = kv
        .kv()
        .reserve_key(FORBIDDEN_KEY_DIFFIE_HELLMAN_PUBLIC.to_string())
        .await
        .expect("Issue reserving DH key");

    kv.kv()
        .put(diffie_hellman_reservation, x25519_public_key.to_vec())
        .await
        .expect("failed to update dh");

    // Now we write the TSS AccountID and X25519 public key to files for convenience reasons.
    let formatted_dh_public = format!("{x25519_public_key:?}").replace('"', "");
    fs::write(".entropy/public_key", formatted_dh_public).expect("Failed to write public key file");

    let id = AccountId32::new(pair.signer().public().0);
    fs::write(".entropy/account_id", format!("{id}")).expect("Failed to write account_id file");

    tracing::debug!("Starting process with account ID: `{id}`");
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
    Ok(())
}

pub async fn setup_only(kv: &KvManager) {
    let mnemonic = kv.kv().get(FORBIDDEN_KEYS[0]).await.expect("Issue getting mnemonic");
    let pair = <sr25519::Pair as Pair>::from_phrase(
        &String::from_utf8(mnemonic).expect("Issue converting mnemonic to string"),
        None,
    )
    .expect("Issue converting mnemonic to pair");
    let account_id = AccountId32::new(pair.0.public().into()).to_ss58check();

    let dh_public_key = kv.kv().get(FORBIDDEN_KEYS[2]).await.expect("Issue getting dh public key");
    let dh_public_key = format!("{dh_public_key:?}").replace('"', "");
    let output = json!({
        "account_id": account_id,
        "dh_public_key": dh_public_key,
    });

    println!("{}", output);
}
