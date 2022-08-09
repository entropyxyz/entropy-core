//! # Communication Manager
//!
//!
//! ## Overview
//!
//! Sends messages to nodes to initiate a signing protocol
//!
//! ## Pieces Launched
//! - Rocket server - Includes global state and mutex locked IPs
//! - Sled DB KVDB
#![allow(unused_variables)]

mod errors;
mod ip_discovery;
mod request_guards;
mod sign;
#[cfg(test)]
mod tests;

use crate::{ip_discovery::get_ip, sign::provide_share};
use bip39::{Language, Mnemonic};
pub use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
use rocket::routes;
use serde::Deserialize;
use std::sync::Mutex;
#[macro_use]
extern crate rocket;

// TODO(TK): move to common
pub type PartyUid = usize;
pub const SIGNING_PARTY_SIZE: usize = 6;
pub const DEFAULT_ENDPOINT: &str = "ws://localhost:9944";
pub const DEFAULT_MNEMONIC: &str =
	"alarm mutual concert decrease hurry invest culture survey diagram crash snap click";

/// holds KVDB instance, threshold mnemonic and endpoint of running node
pub struct CommunicationManagerState {
	configuration: Configuration,
	/// Generate unique ids for each signing party
	// TODO(TK): be more robust than a counter
	party_id_nonce: Mutex<usize>,
	// TODO(TK): what does this do that kv_manager doesn't do?
	current_ips: Mutex<Vec<String>>,
	/// Key: user address
	/// Value: information about every node's key-share for that user
	// TODO(TK): write these types
	kv_manager: KvManager,
}

impl Default for CommunicationManagerState {
	fn default() -> Self {
		Self {
			configuration: Configuration::new(),
			party_id_nonce: Mutex::default(),
			current_ips: Mutex::default(),
			kv_manager: load_kv_store(),
		}
	}
}

// exclude the database
impl std::fmt::Debug for CommunicationManagerState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Global")
			.field("configuration", &self.configuration)
			.field("party_id_nonce", &self.party_id_nonce)
			.field("current_ips", &self.current_ips)
			.finish()
	}
}

impl CommunicationManagerState {
	pub(crate) fn get_next_party_id(&self) -> PartyUid {
		let mut nonce = *self.party_id_nonce.lock().unwrap();
		nonce += 1;
		nonce
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
	fn new() -> Self {
		let c = if cfg!(test) {
			Self { mnemonic: DEFAULT_MNEMONIC.to_string(), endpoint: DEFAULT_ENDPOINT.to_string() }
		} else {
			envy::from_env::<Self>().expect("Please provide MNEMONIC as env var")
		};
		assert!(
			Mnemonic::validate(&c.mnemonic, Language::English).is_ok(),
			"MNEMONIC is incorrect"
		);
		c
	}
}

// required for serde default macro
fn default_endpoint() -> String {
	DEFAULT_ENDPOINT.to_string()
}

pub(crate) fn init_tracing() {
	let filter = tracing_subscriber::filter::LevelFilter::INFO.into();
	tracing_subscriber::filter::EnvFilter::builder()
		.with_default_directive(filter)
		.from_env_lossy();
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

#[launch]
async fn rocket() -> _ {
	init_tracing();
	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `signing_party`, list of global ip addresses for a
	let cm_state = CommunicationManagerState::default();
	rocket::build().mount("/cm", routes![provide_share, get_ip]).manage(cm_state)
}
