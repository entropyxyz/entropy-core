//! Utilities for starting and running the server.

use std::{collections::HashMap, fs, path::PathBuf, sync::Mutex};

use bip39::{Language, Mnemonic};
use clap::{Args, Parser, Subcommand};
use dirs::home_dir;
use kvdb::{encrypted_sled::PasswordMethod, kv_manager::KvManager};
use serde::Deserialize;
use tofn::sdk::api::{RecoverableSignature, Signature};

use crate::{setup_mnemonic, sign_init::MessageDigest};

pub const DEFAULT_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";
pub const DEFAULT_BOB_MNEMONIC: &str =
    "where sight patient orphan general short empower hope party hurt month voice";
pub const DEFAULT_ALICE_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";

pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

pub(super) fn init_tracing() {
    let filter = tracing_subscriber::filter::LevelFilter::INFO.into();
    tracing_subscriber::filter::EnvFilter::builder()
        .with_default_directive(filter)
        .from_env_lossy();
}

#[derive(Deserialize, Debug, Clone)]
pub struct Configuration {
    pub endpoint: String,
}

impl Configuration {
    pub(crate) fn new(endpoint: String) -> Configuration { Configuration { endpoint } }
}

pub(super) async fn load_kv_store(is_bob: bool) -> KvManager {
    let kv_store: KvManager = if cfg!(test) {
        KvManager::new(
            kvdb::get_db_path(true).into(),
            PasswordMethod::NoPassword.execute().unwrap(),
        )
        .unwrap()
    } else {
        let mut root: PathBuf = PathBuf::from(kvdb::get_db_path(false));
        if is_bob {
            root.push("bob");
        }
        let password = PasswordMethod::Prompt.execute().unwrap();
        // this step takes a long time due to password-based decryption
        KvManager::new(root, password).unwrap()
    };
    kv_store
}

#[derive(Parser, Debug, Clone)]
pub struct StartupArgs {
    /// Wether to sync the keystore.
    #[arg(short = 's', long = "sync")]
    pub sync: bool,
    /// Use the developer key Bob.
    #[arg(short = 'b', long = "bob")]
    pub bob: bool,
    /// Use the developer key Alice.
    #[arg(short = 'a', long = "alice")]
    pub alice: bool,
    /// Websocket endpoint for the entropy blockchain.
    #[arg(
        short = 'c',
        long = "chain-endpoint",
        required = false,
        default_value = "ws://localhost:9944"
    )]
    pub chain_endpoint: String,

    /// Wether to allow a validator key to be null.
    #[arg(short = 'd', long = "dev")]
    pub dev: bool,
}

// TODO: JA Remove all below, temporary
/// The state used to temporarily store completed signatures
#[derive(Debug)]
pub struct SignatureState {
    pub signatures: Mutex<HashMap<String, RecoverableSignature>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Mutex::new(HashMap::new());
        SignatureState { signatures }
    }

    pub fn insert(&self, key: [u8; 32], value: &RecoverableSignature) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        println!("inside insert value: {:?}", value.clone());
        signatures.insert(hex::encode(key), *value);
    }

    pub fn get(&self, key: &String) -> [u8; 65] {
        let signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let result = *signatures.get(key).unwrap();
        result.as_ref().try_into().expect("slice with incorrect length")
    }

    pub fn drain(&self) {
        let mut signatures = self.signatures.lock().unwrap_or_else(|e| e.into_inner());
        let _ = signatures.drain();
    }
}
