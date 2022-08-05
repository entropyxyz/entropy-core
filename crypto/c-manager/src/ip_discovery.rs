//! # IP Discovery
//!
//!
//! ## Overview
//!
//! This file acts to help nodes communicate so they can start the signing process
//! Communication manager will collect IPs for all signers then inform them they are signing
//!
//! ## Routes
//!
//! get_ip - get - Comm manager accepts sign request for a message
//! get_all_ips - post - Comm manager sends signers all node addresses to sign message
#![allow(unused_variables)]
#![allow(unused_imports)]

use crate::{
	errors::{CustomIPError},
	Global, SIGNING_PARTY_SIZE,
};
use futures::TryFutureExt;
use reqwest::{self};
use rocket::{http::Status, serde::json::Json, State};
use tracing::instrument;
use common::CMInfoUnchecked;
use uuid::Uuid;

/// Collect IPs for all signers then informs them
#[instrument]
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, state: &State<Global>) -> Result<Status, CustomIPError> {
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	info!("get_ip");
	let init_party_info = {
		let ip_addresses = &mut *state.current_ips.lock().unwrap();
		if ip_addresses.contains(&ip_address) {
			return Err(CustomIPError::new("Duplicate IP"))
		} else if ip_addresses.len() < SIGNING_PARTY_SIZE {
			// TODO(TK): these should be ordered per the index each node has in the signing
			// protocol.
			ip_addresses.push(ip_address);
			return Ok(Status::Ok)
		} else {
			// All IP addresses collected. Construct InitPartyInfo and notify nodes to proceed.
			ip_addresses.push(ip_address);
			let party_id = state.get_next_party_id();
			let sig_uid = None; // todo: look for prior signature uids
			let key_uid = Uuid::new_v4(); // todo: get key_uid
			let msg = "".into(); // todo: get message
			CMInfoUnchecked::new(party_id, ip_addresses.clone(), key_uid, msg, sig_uid)
		}
	};

	let client = reqwest::Client::new();
	for ip in &init_party_info.ip_addresses {
		let res = client
			.post(format!("http://{}/new_party", ip))
			.header("Content-Type", "application/json")
			.json(&init_party_info)
			.send()
			.await
			.unwrap();
	}
	Ok(Status::Ok)
}
