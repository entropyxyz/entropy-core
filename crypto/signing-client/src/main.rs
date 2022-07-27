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
	store_share::store_keyshare,
};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::{Deserialize, Serialize};
use std::{env, sync::Mutex};

#[macro_use]
extern crate rocket;

mod encrypted_sled;
mod errors;
mod ip_discovery;
mod kv_manager;
mod request_guards;
mod sign;
mod signer;
mod store_share;
use crate::encrypted_sled::{get_db_path, PasswordMethod};
pub use kv_manager::KvManager;

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
	let ips = IPs { current_ips: Mutex::new(vec![]) };
	rocket::build()
		.mount(
			"/",
			routes![
				store_keyshare,
				provide_share,
				get_ip,
				get_all_ips,
				// TODO(TK): add signing protocol methods here
				// init_sign,
				// execute_sign,
				// handle_results,
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
		KvManager::new(
			get_db_path().into(),
			encrypted_sled::PasswordMethod::NoPassword.execute().unwrap(),
		)
		.unwrap()
	} else {
		let root = project_root::get_project_root().unwrap();
		let password = PasswordMethod::Prompt.execute().unwrap();
		// this step takes a long time due to password-based decryption
		KvManager::new(root, password).unwrap()
	}
}
