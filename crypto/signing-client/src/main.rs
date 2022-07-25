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
	ip_discovery::{get_ip, new_party, subscribe},
	sign::provide_share,
	store_share::store_keyshare,
};
use bip39::{Language, Mnemonic};
use rocket::routes;
use serde::Deserialize;
use signer::SigningMessage;
use std::{
	collections::HashMap,
	sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

use tofnd::{config::parse_args, kv_manager::KvManager};

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

pub type PartyId = usize;
pub type RxChannel = broadcast::Receiver<SigningMessage>;

pub const SIGNING_PARTY_SIZE: usize = 6;

/// holds KVDB instance, threshold mnemonic and endpoint of running node
#[derive(Debug, Default)]
pub struct Global {
	mnemonic: String,
	endpoint: String,
	// TODO(TK): sharding hashmap into Mutex<SigningChannel>
	signing_channels: Arc<Mutex<HashMap<PartyId, RxChannel>>>,
	/// create unique ids for each signing party
	party_id_nonce: Mutex<usize>,
	// TODO(TK): improve doc comment description for current_ips, this field's function is unclear
	current_ips: Arc<Mutex<Vec<String>>>,
}

impl Global {
	pub(crate) fn new(env: Configuration) -> Self {
		{
			Self { mnemonic: env.mnemonic, endpoint: env.endpoint.unwrap(), ..Self::default() }
		}
	}
}

/// KvManager doesn't implement Debug, so store it separately for logging convenience
pub struct EntropyKvManager(KvManager);

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
	let kv_manager = EntropyKvManager(load_kv_store());

	// TODO: JA maybe add check to see if blockchain is running at endpoint
	// Communication Manager: Collect IPs, for `signing_party`, list of global ip addresses for a
	// message.
	rocket::build()
		.mount("/", routes![store_keyshare, provide_share, get_ip, new_party, subscribe])
		.manage(global)
		.manage(kv_manager)
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
