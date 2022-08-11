//! Utilities for starting and running the server.

use bip39::{Language, Mnemonic};
use kvdb::{encrypted_sled::PasswordMethod, kv_manager::KvManager};
use serde::Deserialize;

const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";
const DEFAULT_MNEMONIC: &str =
  "alarm mutual concert decrease hurry invest culture survey diagram crash snap click";

pub(super) fn init_tracing() {
  let filter = tracing_subscriber::filter::LevelFilter::INFO.into();
  tracing_subscriber::filter::EnvFilter::builder().with_default_directive(filter).from_env_lossy();
}

#[derive(Deserialize, Debug, Clone)]
pub struct Configuration {
  #[serde(default = "default_endpoint")]
  #[allow(dead_code)] // TODO(TK): unused?
  pub endpoint: String,
  pub mnemonic: String,
}
impl Configuration {
  pub(crate) fn new() -> Configuration {
    let c = if cfg!(test) {
      Configuration {
        mnemonic: DEFAULT_MNEMONIC.to_string(),
        endpoint: DEFAULT_ENDPOINT.to_string(),
      }
    } else {
      envy::from_env::<Configuration>().expect("Please provide MNEMONIC as env var")
    };
    assert!(Mnemonic::validate(&c.mnemonic, Language::English).is_ok(), "MNEMONIC is incorrect");
    c
  }
}

fn default_endpoint() -> String { DEFAULT_ENDPOINT.to_string() }

pub(super) fn load_kv_store() -> KvManager {
  if cfg!(test) {
    KvManager::new(kvdb::get_db_path().into(), PasswordMethod::NoPassword.execute().unwrap())
      .unwrap()
  } else {
    let root = project_root::get_project_root().unwrap();
    let password = PasswordMethod::Prompt.execute().unwrap();
    // this step takes a long time due to password-based decryption
    KvManager::new(root, password).unwrap()
  }
}
