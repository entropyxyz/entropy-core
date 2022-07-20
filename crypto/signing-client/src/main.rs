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
// #![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{
	ip_discovery::{get_ip, new_party},
	sign::provide_share,
	signer::signing_registration,
	store_share::store_keyshare,
};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::Deserialize;
use signer::{PartyId, SigningChannel };
use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};

use tofnd::{config::parse_args,  kv_manager::KvManager};

#[macro_use]
extern crate rocket;

mod errors;
mod ip_discovery;
mod request_guards;
mod sign;
mod signer;
mod store_share;
#[cfg(test)]
mod tests;

/// holds KVDB instance, threshold mnemonic and endpoint of running node
#[derive(Clone)]
pub struct Global {
	mnemonic: String,
	endpoint: String,
	kv_manager: KvManager,
	// TODO(TK): optimize: shard mutex
	signing_channels: Arc<Mutex<HashMap<PartyId, SigningChannel>>>,
	/// create unique ids for each signing party
	party_id_nonce: Arc<Mutex<usize>>,
}

// TODO(TK): improve doc comment description, this struct's function is unclear
// TODO(TK): use Arc<Mutex> to guarantee safety across await, and reduce unlock overhead
/// holds Mutex locked current IPs
pub struct IPs {
	current_ips: Arc<Mutex<Vec<String>>>,
}

fn default_endpoint() -> Option<String> {
	Some("ws://localhost:9944".to_string())
}

#[derive(Deserialize, Debug, Clone)]
struct Configuration {
	#[serde(default = "default_endpoint")]
	endpoint: Option<String>,
	mnemonic: String,
}
/*
	let current_ips = shared_data.current_ips.lock().unwrap();
	if current_ips.len() < 4 {
		current_ips.push(ip_address);
		Ok(Status::Ok)
*/

#[launch]
async fn rocket() -> _ {
	let env = load_environment_variables();
	let kv_manager = load_kv_store();
	// Mapping of parties to signing channels. Used by nodes to subscribe to a signing party.
	let signing_channels = Arc::new(Mutex::new(HashMap::new()));
	let global = Global {
		mnemonic: env.mnemonic,
		endpoint: env.endpoint.unwrap(),
		kv_manager,
		signing_channels,
		party_id_nonce: Arc::new(Mutex::new(0)),
	};
	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `new_party`, list of global ip addresses for a
	// message.
	let ips = IPs { current_ips: Arc::new(Mutex::new(vec![])) };
	rocket::build()
		.mount(
			"/",
			routes![
				store_keyshare,
				provide_share,
				get_ip,
				new_party,
				// TODO(TK): add signing protocol methods here
				signing_registration,
				// signing_results
			],
		)
		.manage(global)
		.manage(ips)
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
		let root = project_root::get_project_root().unwrap();
		KvManager::new(root, tofnd::encrypted_sled::PasswordMethod::NoPassword.execute().unwrap())
			.unwrap()
	} else {
		let cfg = parse_args().unwrap();
		println!("kv-store path: {:?}", cfg.tofnd_path);
		let password = cfg.password_method.execute().unwrap();
		// this step takes a long time due to password-based decryption
		KvManager::new(cfg.tofnd_path, password).unwrap()
	}
}
