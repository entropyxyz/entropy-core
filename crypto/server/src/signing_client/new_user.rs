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

