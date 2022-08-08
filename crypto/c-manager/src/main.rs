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
mod store_share;
#[cfg(test)]
mod tests;

use crate::{ip_discovery::get_ip, sign::provide_share, store_share::store_keyshare};
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
	// TODO(TK): This is only a mapping for the current IPs of a single party. Update to hold a DB.
	current_ips: Mutex<Vec<String>>,
	// Moved to signing_client, keep commented until other api methods are fixed
	// kv_manager: KvManager,
}

impl Default for CommunicationManagerState {
	fn default() -> Self {
		Self {
			configuration: Configuration::new(),
			party_id_nonce: Mutex::default(),
			current_ips: Mutex::default(),
		}
	}
}

// exclude the cm held database
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

#[launch]
async fn rocket() -> _ {
	init_tracing();
	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `signing_party`, list of global ip addresses for a
	let cm_state = CommunicationManagerState::default();
	rocket::build()
		.mount("/", routes![store_keyshare, provide_share, get_ip])
		.manage(cm_state)
}
