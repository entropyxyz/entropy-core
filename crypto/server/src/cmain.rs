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
// #![allow(unused_variables)]

// mod errors;
// mod request_guards;
// mod sign;
// mod sign_req;
// #[cfg(test)]
// mod tests;

// use communication_manager::{sign::provide_share, sign_req::handle_signing};
// use bip39::{Language, Mnemonic};
// pub use kvdb::{encrypted_sled::PasswordMethod, get_db_path, kv_manager::KvManager};
// use rocket::routes;
// use serde::Deserialize;
// use std::sync::Mutex;
// #[macro_use]
// extern crate rocket;

// // TODO(TK): move to common
// pub type PartyUid = usize;
// pub type PlaceholderUserKey = &'static str;
// pub const SIGNING_PARTY_SIZE: usize = 6;

// /// holds KVDB instance, threshold mnemonic and endpoint of running node
// pub struct CommunicationManagerState {
// 	configuration: Configuration,
// 	/// Generate unique ids for each signing party
// 	// TODO(TK): be more robust than a counter
// 	party_id_nonce: Mutex<usize>,
// 	// TODO(TK): what does this do that kv_manager doesn't do?
// 	current_ips: Mutex<Vec<String>>,
// 	/// Key: user address
// 	/// Value: information about every node's key-share for that user
// 	// TODO(TK): write these types
// 	kv_manager: KvManager,
// }

// impl Default for CommunicationManagerState {
// 	fn default() -> Self {
// 		Self {
// 			configuration: Configuration::new(),
// 			party_id_nonce: Mutex::default(),
// 			current_ips: Mutex::default(),
// 			kv_manager: load_kv_store(),
// 		}
// 	}
// }

// // exclude the database
// impl std::fmt::Debug for CommunicationManagerState {
// 	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
// 		f.debug_struct("Global")
// 			.field("configuration", &self.configuration)
// 			.field("party_id_nonce", &self.party_id_nonce)
// 			.field("current_ips", &self.current_ips)
// 			.finish()
// 	}
// }

// impl CommunicationManagerState {
// 	#[allow(dead_code)]
// 	pub(crate) fn get_next_party_id(&self) -> PartyUid {
// 		let mut nonce = *self.party_id_nonce.lock().unwrap();
// 		nonce += 1;
// 		nonce
// 	}
// }
