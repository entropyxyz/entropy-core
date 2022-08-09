//! # Signing Client
//!
//! ## Overview
//!
//! Signing Client, to be run by every Entropy node. Also see Communication Manager.
//!
//! ## Pieces Launched
//! - Rocket server - Includes global state and mutex locked IPs
//! - Sled DB KVDB
#![allow(unused_variables)]
#![allow(unused_imports)]

pub mod api;
mod context;
mod errors;
mod protocol_manager;
mod subscriber;

#[macro_use]
extern crate rocket;
use crate::{
	api::{new_party, subscribe},
	protocol_manager::{ProtocolManager, SigningMessage},
	subscriber::SubscriberManager,
};
use bip39::{Language, Mnemonic};
use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use rocket::routes;
use serde::Deserialize;
use std::{collections::HashMap, sync::Mutex};

pub type PartyUid = usize;
pub const SIGNING_PARTY_SIZE: usize = 6;
pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";
pub const DEFAULT_MNEMONIC: &str =
	"alarm mutual concert decrease hurry invest culture survey diagram crash snap click";

/// The state used by this node to create signatures
pub struct SignerState {
	/// kv-store configuration and ws-endpoint
	configuration: Configuration,
	/// Mapping of PartyIds to `SubscriberManager`s, one entry per active party.
	// TODO(TK): SubscriberManager to be replaced with None when subscribing phase ends.
	subscriber_manager_map: Mutex<HashMap<PartyUid, Option<SubscriberManager>>>,
	/// All shares stored by this node, see: StoredInfo (name is WIP)
	kv_manager: KvManager,
}

impl Default for SignerState {
	fn default() -> Self {
		Self {
			kv_manager: load_kv_store(),
			configuration: Configuration::load_environment_variables(),
			subscriber_manager_map: Mutex::default(),
		}
	}
}

// exclude kv manager
impl std::fmt::Debug for SignerState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Global")
			.field("configuration", &self.configuration)
			.field("subscriber_manager_map", &self.subscriber_manager_map)
			.finish()
	}
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Configuration {
	#[serde(default = "default_endpoint")]
	#[allow(dead_code)] // TODO(TK): unused?
	endpoint: String,
	mnemonic: String,
}
impl Configuration {
	fn load_environment_variables() -> Configuration {
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

fn load_kv_store() -> KvManager {
	if cfg!(test) {
		KvManager::new(get_db_path().into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap()
	} else {
		let root = project_root::get_project_root().unwrap();
		let password = PasswordMethod::Prompt.execute().unwrap();
		// this step takes a long time due to password-based decryption
		KvManager::new(root, password).unwrap()
	}
}

// required for serde default macro
fn default_endpoint() -> String {
	DEFAULT_ENDPOINT.to_string()
}

fn init_tracing() {
	let filter = tracing_subscriber::filter::LevelFilter::INFO.into();
	tracing_subscriber::filter::EnvFilter::builder()
		.with_default_directive(filter)
		.from_env_lossy();
}

#[launch] // initializes an async Rocket-specialized runtime
async fn rocket() -> _ {
	init_tracing();
	let signer_state = SignerState::default();
	rocket::build().mount("/", routes![new_party, subscribe]).manage(signer_state)
}
