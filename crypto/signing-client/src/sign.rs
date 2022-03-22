//! The Node requests the client to take part in a signature generation.

use common::{SigRequest, OCWMessage};
use parity_scale_codec::{Decode, Encode};
use subxt::{ClientBuilder, DefaultConfig, DefaultExtra, PairSigner, sp_runtime::AccountId32};
use std::fmt;

// load entropy metadata so that subxt knows what types can be handled by the entropy network
#[subxt::subxt(runtime_metadata_path = "../protocol/src/entropy_metadata.scale")]
pub mod entropy {}

// ToDo: Should we move declaration of structs to /crypto/common/ ?
//       If those types are necessary for the node's OCW, then maybe we should

/// This is the data transmitted in the signature generation request.
#[derive(Debug, Encode, Decode, FromForm)]
pub struct ProvideSignatureReq {
	/// temporary dummy, delete this later
	pub demo: u8,
	/* message
	 * nonce
	 * communication manager
	 * IDs of other signing nodes (necessary for Lagrange-polynomials) */
}

/// Response of the signing node
#[derive(Debug, Encode)]
struct SignRes {
	pub demo: u8,
}

pub type entropy_runtime = entropy::RuntimeApi<DefaultConfig, DefaultExtra<DefaultConfig>>;

/// Response to the node if the signature was created.
/// i.e. a signature that the data was stored successfully or Error Code.
#[derive(Responder)]
#[response(status = 200, content_type = "application/x-parity-scale-codec")]
pub struct ProvideSignatureRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post("/sign", format = "application/x-parity-scale-codec", data = "<encoded_data>")]
pub async fn provide_share(encoded_data: Vec<u8>) -> ProvideSignatureRes {
	println!("encoded_data {:?}", encoded_data);

	// ToDo: JA rename
	let data = OCWMessage::decode(&mut encoded_data.as_ref());
	let data = match data {
		Ok(x) => x,
		Err(err) => panic!("failed to decode input {}", err),
	};

	println!("data: {:?}", &data);

	let api = get_api("ws://localhost:9944").await.unwrap();

	let block_author = get_block_author(api).await.unwrap();
	// let _ = is_block_author().await

	for task in data {
		println!("task: {:?}", task);
		// ToDo: JA hardcoding
		let sign_cli = protocol::sign::SignCli {
			//ToDo: handle the unwrap... how do I use Result<> as a return type in a HTTP-route?
			address: surf::Url::parse("http://localhost:3001/").unwrap(),
			// ToDo: DF: use the proper sigID and convert it to String
			room: String::from("sig_id"), // String::from_utf8(sig_id.clone()).unwrap(),
			index: 2,
			// parties: sig_res.signing_nodes, // ToDo: DF is this correct??
			parties: vec![2, 1], // ToDo: DF is this correct??
			data_to_sign: String::from("entropy rocks!!"),
		};
		println!("Bob starts signing...");
		// ToDo: JA handle error
		let signature = protocol::sign::sign(sign_cli).await;
		println!("signature: {:?}", signature);
	}
	//todo!();
	// Ok(ProvideSignatureRes(SignRes { demo: 1 }.encode()))
	// ToDO: JA fix
	ProvideSignatureRes(SignRes { demo: 1 }.encode())
}

pub async fn get_api(url: &str) -> Result<entropy_runtime, subxt::Error> {
	let api = ClientBuilder::new()
			.set_url(url)
			.build()
			.await?
			.to_runtime_api::<entropy_runtime>();
	Ok(api)
}

pub async fn is_block_author(api: entropy_runtime, block_author: &AccountId32) -> Result<bool, subxt::Error> {

	let all_validator_keys = api
	.storage()
	.session()
	.queued_keys(None)
	.await?;

	let author_keys = all_validator_keys.iter().find(|&key| &key.0 == block_author);
	let key = author_keys.unwrap().1.babe.encode();
	let result = api.client.rpc().has_key(key.into(), "babe".to_string()).await?;
	Ok(result)
}

pub async fn get_block_author(api: entropy_runtime) -> Result<AccountId32, subxt::Error> {
	let block_number = api.storage().system().number(None).await?;
	let author = api.storage().propagation().block_author(block_number, None).await?.unwrap();
	Ok(author)
}


 // get the author of the block
 // query chain session.queuedKeys: author get babe PK
 // query node rpc has key babe babe PK
