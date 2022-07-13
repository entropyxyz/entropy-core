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
#![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{
	ip_discovery::{get_all_ips, get_ip},
	sign::provide_share,
	signer::{signing_message, signing_registration},
	store_share::store_keyshare,
};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, env, sync::Mutex};
use tofnd::{config::parse_args, encrypted_sled::Db as tofndDb, kv_manager::KvManager};
use tokio::sync::broadcast::channel;

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

/// holds KVDB instance, threshold mneumonic and endpoint of running node
#[derive(Clone)]
pub struct Global {
	mnemonic: String,
	endpoint: String,
	kv_manager: KvManager,
}

/// holds Mutex locked current IPs
pub struct IPs {
	current_ips: Mutex<Vec<String>>,
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

#[launch]
async fn rocket() -> _ {
	let c = load_environment_variables();
	let kv_manager = load_kv_store();
	let global = Global { mnemonic: c.mnemonic, endpoint: c.endpoint.unwrap(), kv_manager };
	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Thor @JA: what IPs are these?
	let ips = IPs { current_ips: Mutex::new(vec![]) };
	let hackmap: HashMap<usize, bool> = HashMap::new(); // TODO(TK): replace with something less dumb
	rocket::build()
		.mount(
			"/",
			routes![
				store_keyshare,
				provide_share,
				get_ip,
				get_all_ips,
				// TODO(TK): add signing protocol methods here
				signing_registration,
				signing_message,
				// signing_results
			],
		)
		.manage(global)
		// hack: manage a channel for only 1 signing party
		// TODO(TK): manage a pool of channels
		.manage(channel::<signer::SigningMessage>(1024).0)
		// hack: signing registration mapping: party_id->finished (true = protocol over)
		.manage(hackmap)
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
