//! The User requests the Signature-client to store a keyshare localy.
use crate::Global;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use rocket::serde::json::Json;
use rocket::State;
use serde::{Deserialize, Serialize};
use std::{
	fs::File,
	io::{BufWriter, Write},
};
use tofnd::kv_manager::{error::KvError, KeyReservation, KvManager};
// ToDo: DF Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// Response of the key storing
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
	pub key: String,
	pub value: Vec<u8>,
}

// ToDo: JA add proper response types and formalize them
#[post("/store_keyshare", format = "json", data = "<user_input>")]
pub async fn store_keyshare(
	user_input: Json<User>,
	state: &State<Global>,
) -> Result<(), std::io::Error> {
	// ToDo: JA verify proof
	// ToDo: validate is owner of key address
	// ToDo: JA make sure signed so other key doesn't override own key

	let cached_state = state.inner();
	let kv_manager = cached_state.kv_manager.clone();

	let reservation = kv_manager.kv().reserve_key(user_input.clone().key).await.unwrap();
	let result = kv_manager.kv().put(reservation, user_input.clone().value).await.unwrap();

	Ok(())
}
