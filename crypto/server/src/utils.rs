//! Utilities for starting and running the server.

use bip39::{Language, Mnemonic};
use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use rocket::routes;
use serde::Deserialize;
use std::{collections::HashMap, sync::Mutex};

const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";
const DEFAULT_MNEMONIC: &str =
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
		assert!(
			Mnemonic::validate(&c.mnemonic, Language::English).is_ok(),
			"MNEMONIC is incorrect"
		);
		c
	}
}

fn default_endpoint() -> String {
	DEFAULT_ENDPOINT.to_string()
}
