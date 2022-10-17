//! Utilities for starting and running the server.

use std::{collections::HashMap, sync::Mutex};

use bip39::{Language, Mnemonic};
use kvdb::{encrypted_sled::PasswordMethod, kv_manager::KvManager};
use serde::Deserialize;
use tofn::sdk::api::Signature;

use crate::{setup_mnemonic, sign_init::MessageDigest};

const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";

pub const DEFAULT_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";
pub const DEFAULT_BOB_MNEMONIC: &str =
    "where sight patient orphan general short empower hope party hurt month voice";
pub const DEFAULT_ALICE_MNEMONIC: &str =
    "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";

pub(super) fn init_tracing() {
    let filter = tracing_subscriber::filter::LevelFilter::INFO.into();
    tracing_subscriber::filter::EnvFilter::builder()
        .with_default_directive(filter)
        .from_env_lossy();
}

#[derive(Deserialize, Debug, Clone)]
pub struct Configuration {
    #[serde(default = "default_endpoint")]
    // #[allow(dead_code)] // TODO(TK): unused?
    pub endpoint: String,
}
impl Configuration {
    pub(crate) fn new() -> Configuration {
        Configuration { endpoint: DEFAULT_ENDPOINT.to_string() }
    }
}

fn default_endpoint() -> String { DEFAULT_ENDPOINT.to_string() }

pub(super) async fn load_kv_store() -> KvManager {
    let kv_store: KvManager = if cfg!(test) {
        KvManager::new(kvdb::get_db_path().into(), PasswordMethod::NoPassword.execute().unwrap())
            .unwrap()
    } else {
        let root = project_root::get_project_root().unwrap();
        let password = PasswordMethod::Prompt.execute().unwrap();
        // this step takes a long time due to password-based decryption
        KvManager::new(root, password).unwrap()
    };
    setup_mnemonic(&kv_store).await;
    kv_store
}

/// The state used to temporarily store completed signatures
#[derive(Debug)]
pub struct SignatureState {
    pub signatures: Mutex<HashMap<[u8; 32], Signature>>,
}

impl SignatureState {
    pub fn new() -> SignatureState {
        let signatures = Mutex::new(HashMap::new());
        SignatureState { signatures }
    }

    pub fn insert(&self, key: [u8; 32], value: &Signature) {
        let mut signatures = self.signatures.lock().unwrap();
        signatures.insert(key, *value);
    }
}
