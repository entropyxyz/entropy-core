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
	errors::CustomIPError, CommunicationManagerState, PlaceholderUserKey, SIGNING_PARTY_SIZE,
};
use futures::TryFutureExt;
use kvdb::kv_manager::KvManager;
use non_substrate_common::CMInfo;
use reqwest::{self};
use rocket::{http::Status, request::FromRequest, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

type SignersIPsPlaceholder = String;
type BadSignerPlaceholder = String;

/// User may call this method on the CM, telling the CM to initate a signing protocol.
///
/// The Communication Manager:
/// - Validates User
/// - Retrieves CMInfo committee information about this user from DB
/// - Selects a signing party
/// - Informs the signers a signing_protocol has begun by calling `new_party` on each node
/// - Reselects and reruns the if one or more signers failed or were offline.
#[instrument]
#[rocket::post("/sign_request", format = "json", data = "<sign_request>")]
pub async fn sign_request(
	sign_request: Json<SignRequest>,
	state: &State<CommunicationManagerState>,
) -> Result<Status, CustomIPError> {
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	info!("sign request for request: {:?}", sign_request);
	let mut sign_request = sign_request.into_inner();
	assert!(sign_request.validate_user());

	let cm_info = sign_request.get_user_info_from_db(&state.kv_manager).unwrap();
	let signers = sign_request.select_signers(&cm_info);
	if let Err(bad_signer) = sign_request.post_new_party(&signers, &cm_info).await {
		let _ = sign_request.punish_and_rerun(signers, bad_signer, cm_info).await;
	}
	Ok(Status::Ok)
}

// TODO(TK): rename
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
	user_ip_address: String,
	msg: Vec<u8>,        // todo: placeholder
	signed_msg: Vec<u8>, // todo: placeholder
}

impl SignRequest {
	fn validate_user(&self) -> bool {
		todo!();
	}

	fn get_user_info_from_db(&self, kv_manager: &KvManager) -> anyhow::Result<CMInfo> {
		todo!();
	}

	fn select_signers(&self, cm_info: &CMInfo) -> Vec<SignersIPsPlaceholder> {
		todo!()
	}

	async fn post_new_party(
		&self,
		signers: &[SignersIPsPlaceholder],
		cm_info: &CMInfo,
	) -> Result<(), BadSignerPlaceholder> {
		let client = reqwest::Client::new();
		for ip in signers {
			let res = client
				.post(format!("http://{}/new_party", ip))
				.header("Content-Type", "application/json")
				.json(&cm_info)
				.send()
				.await
				.unwrap();
		}
		Ok(())
	}

	async fn punish_and_rerun(
		&mut self,
		previous_signers: Vec<SignersIPsPlaceholder>,
		bad_signer: SignersIPsPlaceholder,
		cm_info: CMInfo,
	) -> anyhow::Result<()> {
		todo!()
	}
}

// fn construct_init_party_info(&self, kv_manager: &KvManager) -> CMInfo {
// 	let ip_addresses = &mut *kv_manager.lock().unwrap();
// 	if ip_addresses.contains(&sign_request.user_ip_address) {
// 		return Err(CustomIPError::new("Duplicate IP"))
// 	} else if ip_addresses.len() < SIGNING_PARTY_SIZE {
// 		// TODO(TK): these should be ordered per the index each node has in the signing
// 		// protocol.
// 		ip_addresses.push(sign_request.user_ip_address.to_string());
// 		return Ok(Status::Ok)
// 	} else {
// 		// All IP addresses collected. Construct InitPartyInfo and notify nodes to proceed.
// 		ip_addresses.push(sign_request.user_ip_address.to_string());
// 		let party_id = state.get_next_party_id();
// 		let sig_uid = None; // todo: look for prior signature uids
// 		let key_uid = Uuid::new_v4(); // todo: get key_uid
// 		let msg = "".into(); // todo: get message
// 		CMInfo::new(party_id, ip_addresses.clone(), key_uid, msg, sig_uid)
// 	}
// }
