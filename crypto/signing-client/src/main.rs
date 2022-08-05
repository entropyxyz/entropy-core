//! # Signing Client
//!
//!
//! ## Overview
//!
//! Launches our signing client
//!
//! ## Pieces Launched
//!
//! - Rocket server - Includes global state and mutex locked IPs
//! - Sled DB KVDB
#![allow(unused_variables)]
use crate::{
	ip_discovery::{get_ip, new_party},
	sign::provide_share,
	signer::{subscribe, SubscriberManager},
	store_share::store_keyshare,
};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::Deserialize;
use std::{collections::HashMap, sync::Mutex};

#[macro_use]
extern crate rocket;

mod errors;
mod ip_discovery;
mod request_guards;
mod sign;
mod signer;
mod store_share;
pub use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};

#[cfg(test)]
mod tests;

pub type PartyUid = usize;
// pub type RxChannel = Meimpl Stream<Item = Result<Bytes, reqwest::Error>>;

pub const SIGNING_PARTY_SIZE: usize = 6;

/// holds KVDB instance, threshold mnemonic and endpoint of running node
// #[derive(Default)]
pub struct Global {
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

impl Default for Global {
	#[allow(unconditional_recursion)]
	fn default() -> Self {
		Self { kv_manager: load_kv_store(), ..Default::default() }
	}
}

impl std::fmt::Debug for Global {
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

impl Global {
	pub(crate) fn new(env: Configuration) -> Self {
		Self {
			mnemonic: env.mnemonic,
			endpoint: env.endpoint.unwrap(),
			kv_manager: load_kv_store(),
			..Default::default()
		}
	}

	pub(crate) fn get_next_party_id(&self) -> PartyUid {
		let mut nonce = *self.party_id_nonce.lock().unwrap();
		nonce += 1;
		nonce
	}
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
	let global = Global::new(load_environment_variables());

	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `signing_party`, list of global ip addresses for a
	// message.
	rocket::build()
		.mount("/", routes![store_keyshare, provide_share, get_ip, new_party, subscribe])
		.manage(global)
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
