//! # Store Share
//!
//! ## Overview
//!
//! Allows a user to send shards to nodes and have them store it.
//! User's substrate account acts as key value.
//!
//! ## Routes
//!
//! - /store_keyshare - Post - Takes in a key and value for user
// #![allow(unused_imports)]
// todo: move to api.rs and delete this file
use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::{
	fs::File,
	io::{BufWriter, Write},
};

/// User input, contains key (substrate key) and value (entropy shard)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserKvEntryUnparsed {
	/// User's substrate key
	pub key: String,
	// An encoded SecretKeyShare for this node
	pub value: Vec<u8>,
}

/// Parsed user input
#[derive(Debug, Deserialize, Clone)]
pub struct UserKvEntry {
	/// User's substrate key
	pub key: String,
	// An encoded SecretKeyShare for this node
	pub value: Vec<u8>, // TODO(TK): write this type
}

// TODO(TK)
impl TryFrom<UserKvEntryUnparsed> for UserKvEntry {
	type Error = ();

	fn try_from(value: UserKvEntryUnparsed) -> Result<Self, Self::Error> {
		todo!()
	}
}

// TODO(TK): Move this method to signing_client.
/// Accepts user input stores shard under user's substrate key in local KVDB
#[post("/store_keyshare", format = "json", data = "<user_input>")]
pub async fn store_keyshare(
	user_input: Json<UserKvEntryUnparsed>,
	state: &State<crate::Global>,
) -> Result<Status, std::io::Error> {
	// ToDo: JA verify proof
	// ToDo: validate is owner of key address
	// ToDo: JA make sure signed so other key doesn't override own key

	let user_input = UserKvEntry::try_from(user_input.into_inner()).unwrap();
	let kv_manager = &state.kv_manager;
	let reservation = kv_manager.kv().reserve_key(user_input.key.clone()).await.unwrap();
	kv_manager.kv().put(reservation, user_input.value.clone()).await.unwrap();

	Ok(Status::Ok)
}
