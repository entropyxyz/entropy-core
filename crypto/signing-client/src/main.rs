use crate::{sign::provide_share, store_share::store_keyshare};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::Deserialize;
use std::env;
use tofnd::{config::parse_args, encrypted_sled::Db as tofndDb, kv_manager::KvManager};

#[macro_use]
extern crate rocket;

use rocket::State;

#[cfg(test)]
mod tests;

mod com_manager;
mod errors;
mod request_guards;
mod sign;
mod store_share;

use com_manager::{broadcast, issue_idx, subscribe, Db};
// ToDo: JA add proper response types and formalize them across all endpoints

#[derive(Clone)]
pub struct Global {
	mnemonic: String,
	endpoint: String,
	kv_manager: KvManager,
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
	let kv_manager = load_kv_store().await;
	let global = Global {
		mnemonic: c.mnemonic.to_string(),
		endpoint: c.endpoint.unwrap().to_string(),
		kv_manager,
	};
	rocket::build()
		.mount(
			"/",
			routes![
				store_keyshare,
				// for testing, we let node1 not provede a share
				provide_share,
				subscribe,
				issue_idx,
				broadcast
			],
		)
		.manage(Db::empty())
		.manage(global)
}

fn load_environment_variables() -> Configuration {
	let c;

	if cfg!(test) {
		c = Configuration {
			mnemonic:
				"alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
					.to_string(),
			endpoint: Some("ws://localhost:9944".to_string()),
		}
	} else {
		c = envy::from_env::<Configuration>().expect("Please provide MNEMONIC as env var");
	}
	assert!(Mnemonic::validate(&c.mnemonic, Language::English).is_ok(), "MNEMONIC is incorrect");
	c
}

async fn load_kv_store() -> KvManager {
	let kv_manager;
	let cfg = parse_args().unwrap();

	if cfg!(test) {
		let root = project_root::get_project_root().unwrap();
		kv_manager = KvManager::new(root.clone(), get_test_password()).unwrap();
	} else {
		println!("{:?}", cfg.tofnd_path.clone());
		let password = cfg.password_method.execute().unwrap();
		// this step takes a long time due to password-based decryption
		kv_manager = KvManager::new(cfg.tofnd_path.clone(), password)
			.unwrap()
			.handle_mnemonic(&cfg.mnemonic_cmd)
			.await
			.unwrap();
	}
	kv_manager
}

pub fn get_test_password() -> tofnd::encrypted_sled::Password {
	tofnd::encrypted_sled::PasswordMethod::NoPassword.execute().unwrap()
}
