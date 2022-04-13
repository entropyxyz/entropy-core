//! The Node requests the client to take part in a signature generation.

use std::thread;
use common::OCWMessage;
use parity_scale_codec::{Decode, Encode};
use std::str;
use subxt::{sp_runtime::AccountId32, ClientBuilder, DefaultConfig, SubstrateExtrinsicParams, PairSigner};
use sp_keyring::AccountKeyring;

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

pub type EntropyRuntime =
	entropy::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>;

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

	// TODO JA, unhardcode endpoint
	let api = get_api("ws://localhost:9944").await.unwrap();

	let handle = thread::spawn(|| async {
		// TODO JA, unhardcode endpoint
		let api_2 = get_api("ws://localhost:9944").await.unwrap();
		// TODO: JA add a menumoic fetch from encrypted file
		let mnemonic = "".to_string();
		let _ = acknowledge_responsibility(&api_2, mnemonic).await;
	});

	let block_author = get_block_author(&api).await.unwrap();
	let author_endpoint = get_author_endpoint(&api, &block_author).await.unwrap();
	let string_author_endpoint = convert_endpoint(&author_endpoint);
	let bool_block_author = is_block_author(&api, &block_author).await;

	// let author_endpoint = get_author_endpoint(api, &block_author).await.unwrap();

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
	// TODO: JA Thread blocks the return, not sure if needed a problem, keep an eye out for this downstream
	handle.join().unwrap().await;
	//todo!();
	// Ok(ProvideSignatureRes(SignRes { demo: 1 }.encode()))
	// ToDO: JA fix
	ProvideSignatureRes(SignRes { demo: 1 }.encode())
}

pub async fn get_api(url: &str) -> Result<EntropyRuntime, subxt::Error<entropy::DispatchError>> {
	let api = ClientBuilder::new()
		.set_url(url)
		.build()
		.await?
		.to_runtime_api::<EntropyRuntime>();
	Ok(api)
}

pub async fn is_block_author(
	api: &EntropyRuntime,
	block_author: &AccountId32,
) -> Result<bool, subxt::Error<entropy::DispatchError>> {
	let all_validator_keys = api.storage().session().queued_keys(None).await?;

	let author_keys = all_validator_keys.iter().find(|&key| &key.0 == block_author);
	let key = author_keys.unwrap().1.babe.encode();
	let result = api.client.rpc().has_key(key.into(), "babe".to_string()).await?;
	Ok(result)
}

pub async fn get_block_author(
	api: &EntropyRuntime,
) -> Result<AccountId32, subxt::Error<entropy::DispatchError>> {
	let block_number = get_block_number(api).await?;
	let author = api.storage().propagation().block_author(&block_number, None).await?.unwrap();
	Ok(author)
}

pub async fn get_block_number(api: &EntropyRuntime) -> Result<u32, subxt::Error<entropy::DispatchError>>  {
	let block_number = api.storage().system().number(None).await?;
	Ok(block_number)
}

pub async fn get_author_endpoint(
	api: &EntropyRuntime,
	block_author: &AccountId32,
) -> Result<Vec<u8>, subxt::Error<entropy::DispatchError>> {
	let author_endpoint = api
		.storage()
		.staking_extension()
		.endpoint_register(block_author, None)
		.await?
		.unwrap();
	Ok(author_endpoint)
}

pub fn convert_endpoint(author_endpoint: &Vec<u8>) -> Result<&str, std::str::Utf8Error> {
	Ok(str::from_utf8(author_endpoint).unwrap())
}

pub async fn acknowledge_responsibility(
	api: &EntropyRuntime,
	mnemonic: String
) -> Result<(), subxt::Error<entropy::DispatchError>> {
	let signer = PairSigner::new(AccountKeyring::Alice.pair());
	let block_number = get_block_number(api).await?;
	let result = api
		.tx()
		.relayer()
		.confirm_done(block_number, [].to_vec())
		.sign_and_submit_then_watch_default(&signer)
		.await?
		.wait_for_finalized_success()
		.await?;

	if let Some(event) = result.find_first::<entropy::relayer::events::ConfirmedDone>()? {
		println!("confirmed done block number: {:?}", event.1);
	} else {
		println!("Failed to confirm done event: {:?}", block_number);
	}
	Ok(())
}
