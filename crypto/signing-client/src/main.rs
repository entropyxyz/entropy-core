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

/// holds KVDB instance, threshold mnemonic and endpoint of running node
// #[derive(Default)]
pub struct SignerState {
	mnemonic: String,
	endpoint: String,
	/// Unique ids for each signing party
	party_id_nonce: Mutex<usize>,
	// TODO(TK): SubscriberManager to be replaced with None when subscribing phase ends.
	subscriber_manager_map: Mutex<HashMap<PartyUid, Option<SubscriberManager>>>,
	// TODO(TK): This is only a mapping for the current IPs of a single party. Update to similar to
	// map above
	current_ips: Mutex<Vec<String>>,
	/// Master of the Keys, storer of items of the form signer::party_info::StoredInfo
	kv_manager: KvManager,
}

impl Default for SignerState {
	#[allow(unconditional_recursion)]
	fn default() -> Self {
		Self { kv_manager: load_kv_store(), ..Default::default() }
	}
}

impl std::fmt::Debug for SignerState {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Global")
			.field("mnemonic", &self.mnemonic)
			.field("endpoint", &self.endpoint)
			.field("party_id_nonce", &self.party_id_nonce)
			.field("subscriber_manager_map", &self.subscriber_manager_map)
			.field("current_ips", &self.current_ips)
			.finish()
	}
}

impl SignerState {
	pub(crate) fn new(env: Configuration) -> Self {
		Self {
			mnemonic: env.mnemonic,
			endpoint: env.endpoint.unwrap(),
			kv_manager: load_kv_store(),
			..Default::default()
		}
	}

	// pub(crate) fn get_next_party_id(&self) -> PartyUid {
	// 	let mut nonce = *self.party_id_nonce.lock().unwrap();
	// 	nonce += 1;
	// 	nonce
	// }
}

fn default_endpoint() -> Option<String> {
	Some("ws://localhost:9944".to_string())
}

#[derive(Deserialize, Debug, Clone)]
pub(crate) struct Configuration {
	#[serde(default = "default_endpoint")]
	endpoint: Option<String>,
	mnemonic: String,
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
	let global = SignerState::new(load_environment_variables());

	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `signing_party`, list of global ip addresses for a
	// message.
	rocket::build().mount("/", routes![new_party, subscribe]).manage(global)
}

fn load_environment_variables() -> Configuration {
	let c = if cfg!(test) {
		Configuration {
			mnemonic:
				"alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
					.to_string(),
			endpoint: Some("ws://localhost:9944".to_string()),
		}
	} else {
		envy::from_env::<Configuration>().expect("Please provide MNEMONIC as env var")
	};
	assert!(Mnemonic::validate(&c.mnemonic, Language::English).is_ok(), "MNEMONIC is incorrect");
	c
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
