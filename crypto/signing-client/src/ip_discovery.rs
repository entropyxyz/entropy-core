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
	errors::CustomIPError,
	signer::{handle_sign, SigningMessage, SigningRegistrationMessage},
	Global,
};
use futures::future;
use reqwest::{self};
use rocket::{http::Status, response::stream::ByteStream, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::Sender;
use tracing::instrument;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NewParty {
	pub party_id: usize,
	pub ip_addresses: Vec<String>,
}

// TODO(TK): flatten state into a single global
/// Collect IPs for all signers then informs them
#[instrument]
#[rocket::get("/get_ip/<ip_address>")]
pub async fn get_ip(ip_address: String, global: &State<Global>) -> Result<Status, CustomIPError> {
	info!("get_ip");
	let global = global.inner();
	// TODO JA do validation on recieved keys and if keys are already had
	// TODO JA figure out optimal node amount
	// TODO JA validate not a duplicated IP
	// TODO(TK): rewrote this to use an arc and unlock only once. Still could have better flow.

	let new_party = {
		let current_ips_mutex = global.current_ips.clone();
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

			NewParty { party_id: get_next_party_id(global), ip_addresses: current_ips.clone() }
		}
	};

	for ip in &new_party.ip_addresses {
		let res = reqwest::Client::new()
			.post(format!("http://{}/new_party", ip))
			.header("Content-Type", "application/json")
			.json(&new_party)
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
/// subscribe to and a party_id.
#[instrument]
#[post("/new_party", format = "json", data = "<new_party>")]
pub async fn new_party(
	new_party: Json<NewParty>,
	_global: &State<Global>,
	// TODO(TK): make an Error type
) -> Result<Status, CustomIPError> {
	info!("new_party");
	let NewParty { ip_addresses, party_id } = new_party.into_inner();

	// a new task is spawned for each created party
	tokio::spawn(async move {
		// Get broadcast sending channel & receiving channels for each other node.
		let (tx, rx_channels) = rx_channels(ip_addresses.clone(), party_id).await.unwrap();

		if let Err(e) = handle_sign(tx, rx_channels).await {
			// TODO(TK): handle errors
		}
	});
	Ok(Status::Ok)
}

/// Get rx channels from each other node in the signing party.
// TODO(TK): the Response is a Reqwest, wrapping a stream. How do I poll messages from the stream?
#[instrument]
async fn rx_channels(
	ip_addresses: Vec<String>,
	party_id: usize,
) -> anyhow::Result<(Sender<SigningMessage>, Vec<ByteStream<Vec<u8>>>)> {
	info!("rx_channels");
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
	// let v: Vec<ByteStream<Vec<u8>>> = future::join_all(handles)
	// 	.await
	// 	.into_iter()
	// 	.map(|res| {
	// 		let a: Result<Result<reqwest::Response, reqwest::Error>, tokio::task::JoinError> = res;
	// 		match res {
	// 			Err(e) => todo!(), // handle tokio error
	// 			Ok(res) => match res {
	// 				// handle response error
	// 				Err(e) => todo!(),
	// 				// response is a bytes stream from another node.
	// 				Ok(res) => ByteStream(res.bytes_stream()),
	// 			},
	// 		}
	// 	})
	// .collect();

	// future::join_all(handles).await.into_iter().map(|res| res.unwrap().unwrap()).collect()
	todo!()
}
