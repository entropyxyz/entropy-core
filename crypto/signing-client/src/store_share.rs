//! The User requests the Signature-client to store a keyshare localy.

use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use rocket::serde::json::Json;
use std::{
	fs::File,
	io::{BufWriter, Write},
};

// ToDo: DF Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// Response of the key storing

// ToDo: JA add proper response types and formalize them
#[post("/store_keyshare", format = "json", data = "<user_input>")]
pub fn store_keyshare(user_input: Json<LocalKey<Secp256k1>>) -> Result<(), std::io::Error> {
	// ToDo: JA verify proof
	// ToDo: JA make sure signed so other key doesn't override own key
	let file = File::create("key_share.json")?;
	let mut writer = BufWriter::new(file);
	serde_json::to_writer(&mut writer, &user_input.0)?;
	writer.flush()?;
	println!("keyshare received!");
	Ok(())
}
