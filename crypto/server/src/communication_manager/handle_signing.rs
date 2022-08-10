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
#![allow(dead_code)]

use futures::TryFutureExt;
use kvdb::kv_manager::KvManager;
use non_substrate_common::SignInit;
use reqwest::{self};
use rocket::{http::Status, request::FromRequest, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;

use crate::{
  communication_manager::errors::CustomIPError, CommunicationManagerState, SIGNING_PARTY_SIZE,
};

// TODO(TK): lots to do
/// Data from previous block, to be used to initate signature protocols by the CM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedBlockData {
  user_ip_address: String,
  msg:             Vec<u8>, // todo: placeholder
  signed_msg:      Vec<u8>, // todo: placeholder
}

type SignersIPsPlaceholder = String;
type BadSignerPlaceholder = String;
impl EncodedBlockData {
  fn validate_user(&self) -> bool {
    todo!();
  }

  fn get_user_info_from_db(&self, kv_manager: &KvManager) -> anyhow::Result<SignInit> {
    todo!();
  }

  fn select_signers(&self, cm_info: &SignInit) -> Vec<SignersIPsPlaceholder> { todo!() }

  async fn post_new_party(
    &self,
    signers: &[SignersIPsPlaceholder],
    cm_info: &SignInit,
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
    cm_info: SignInit,
  ) -> anyhow::Result<()> {
    todo!()
  }
}

// fn construct_init_party_info(&self, kv_manager: &KvManager) -> SignInit {
// 	let ip_addresses = &mut *kv_manager.lock().unwrap();
// 	if ip_addresses.contains(&handle_signing.user_ip_address) {
// 		return Err(CustomIPError::new("Duplicate IP"))
// 	} else if ip_addresses.len() < SIGNING_PARTY_SIZE {
// 		// TODO(TK): these should be ordered per the index each node has in the signing
// 		// protocol.
// 		ip_addresses.push(handle_signing.user_ip_address.to_string());
// 		return Ok(Status::Ok)
// 	} else {
// 		// All IP addresses collected. Construct InitPartyInfo and notify nodes to proceed.
// 		ip_addresses.push(handle_signing.user_ip_address.to_string());
// 		let party_id = state.get_next_party_id();
// 		let sig_uid = None; // todo: look for prior signature uids
// 		let key_uid = Uuid::new_v4(); // todo: get key_uid
// 		let msg = "".into(); // todo: get message
// 		SignInit::new(party_id, ip_addresses.clone(), key_uid, msg, sig_uid)
// 	}
// }
