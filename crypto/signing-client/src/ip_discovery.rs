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
#![allow(unused_imports)]
#![allow(unused_variables)]
use crate::{
	errors::CustomIPError,
	signer::{handle_signing, SigningMessage, SigningRegistrationMessage},
	Global, IPs,
};
use futures::{future, stream};
use reqwest::{self, Response};
use rocket::{
	http::{ContentType, Status},
	response::{status, stream::EventStream},
	serde::json::Json,
	State,
};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::sync::broadcast::Sender;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewParty {
	pub party_id: usize,
	pub ip_addresses: Vec<String>,
}

// TODO(TK): flatten state into a single global
/// Collect IPs for all signers then informs them
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(
	ip_address: String,
	state: &State<IPs>,
	global: &State<Global>,
) -> Result<Status, CustomIPError> {
	let shared_data: &IPs = state.inner();
	let global = global.inner();
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP

	let new_party = {
		let current_ips_mutex = shared_data.current_ips.clone();
		let current_ips = &mut *current_ips_mutex.lock().unwrap();
		if current_ips.contains(&ip_address) {
			return Err(CustomIPError::new("Duplicate IP"))
		// TODO(TK): why 4? replace with labeled const
		} else if current_ips.len() < 4 {
			current_ips.push(ip_address);
			return Ok(Status::Ok)
		} else {
			// TODO(TK): clarify what this branch is doing
			current_ips.push(ip_address);
			let v = current_ips.to_vec();
			let ips_and_party_id =
				NewParty { party_id: get_next_party_id(global), ip_addresses: current_ips.clone() };
			ips_and_party_id
		}
	};

	for ip in &new_party.ip_addresses {
		let full_route = format!("http://{}/post_new_party", ip);
		let res = reqwest::Client::new()
			.post(full_route)
			.header("Content-Type", "application/json")
			.json(&new_party.clone())
			.send()
			.await
			.unwrap();
	}
	Ok(Status::Ok)
}

/// increment the party_id_nonce, and return the next party_id
fn get_next_party_id(global: &Global) -> usize {
	let party_id_mutex = global.party_id_nonce.clone();
	let mut party_id = *party_id_mutex.lock().unwrap();
	party_id += 1;
	party_id
}

/// Communication Manager calls this endpoint on each node to inform the node that it is part of a
/// signing party. CM provides IP addresses of other nodes in the signing party for this node to
/// subscribe to.
#[post("/post_new_party", format = "json", data = "<ips_and_party_id>")]
pub async fn post_new_party(ips_and_party_id: Json<NewParty>, state: &State<IPs>) {
	let NewParty { ip_addresses, party_id } = ips_and_party_id.into_inner();

	let (tx, rx_channels) =
		tokio::spawn(rx_channels(ip_addresses.clone(), party_id)).await.unwrap();

	// initiate signing
	handle_signing(tx, rx_channels).await.unwrap();

	// TODO(TK): start signing, call `signing_registration` on each node in `ip_addresses`.
}

/// get rx channels from each other node in the signing party
// TODO(TK): the Response is a Reqwest, wrapping a stream. How do I poll messages from the stream?
// TODO(TK): move tx,rx genaration into this method
async fn rx_channels(
	ip_addresses: Vec<String>,
	party_id: usize,
) -> (Sender<SigningMessage>, Vec<EventStream<SigningMessage>>) {
	let mut handles = Vec::with_capacity(ip_addresses.len());
	let client = reqwest::Client::new();
	for ip in ip_addresses {
		handles.push(tokio::spawn(
			client
				.post(format!("http://{}/signing_registration", ip))
				.header("Content-Type", "application/json")
				.json(&SigningRegistrationMessage { party_id })
				.send(),
		))
	}
	let v: Vec<EventStream<SigningMessage>> = future::join_all(handles)
		.await
		.into_iter()
		.map(|res| res.unwrap().unwrap())
		.map(|res| {
			// TODO(TK): the Response is a stream. How do I do this type transformation?

			todo!();
		})
		.collect();

	// future::join_all(handles).await.into_iter().map(|res| res.unwrap().unwrap()).collect()
	todo!()
}
