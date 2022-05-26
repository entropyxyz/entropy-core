//! The Node requests the client to take part in a signature generation.

use crate::Global;
use common::OCWMessage;
use constraints::whitelist::is_on_whitelist;
use parity_scale_codec::{Decode, Encode};
use rocket::State;
use sp_core::{sr25519::Pair as Sr25519Pair, Pair};
use sp_keyring::AccountKeyring;
use std::str;
use std::thread;
use subxt::{
	sp_runtime::AccountId32, ClientBuilder, Config, DefaultConfig, PairSigner,
	PolkadotExtrinsicParams,
};
use tofnd::kv_manager::KvManager;
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
	entropy::RuntimeApi<DefaultConfig, PolkadotExtrinsicParams<DefaultConfig>>;

/// Response to the node if the signature was created.
/// i.e. a signature that the data was stored successfully or Error Code.
#[derive(Responder)]
#[response(status = 200, content_type = "application/x-parity-scale-codec")]
pub struct ProvideSignatureRes(Vec<u8>);

//ToDo: receive keyshare and store locally
#[post("/sign", format = "application/x-parity-scale-codec", data = "<encoded_data>")]
pub async fn provide_share(encoded_data: Vec<u8>, state: &State<Global>) -> ProvideSignatureRes {
	println!("encoded_data {:?}", encoded_data);

	// ToDo: JA rename
	let data = OCWMessage::decode(&mut encoded_data.as_ref());
	let data = match data {
		Ok(x) => x,
		Err(err) => panic!("failed to decode input {}", err),
	};
	let raw_address = &data[0].account;
	let address_slice: &[u8; 32] =
		&raw_address.clone().try_into().expect("slice with incorrect length");

	let user = AccountId32::new(*address_slice);

	println!("data: {:?}", &data);
	let cached_state = state.inner();
	let endpoint = cached_state.endpoint.clone();
	let mnemonic = cached_state.mnemonic.clone();
	let kv_manager = cached_state.kv_manager.clone();

	let api = get_api(&endpoint).await.unwrap();
	let block_number = get_block_number(&api).await.unwrap();
	// TODO: JA This thread needs to happen after all signing processes are completed and contain locations in vec of any failures (which need to be stored locally in DB temporarily)
	let handle = thread::spawn(move || async move {
		let api_2 = get_api(&endpoint).await.unwrap();
		let block_author = get_block_author(&api_2).await.unwrap();
		if is_block_author(&api_2, &block_author).await.unwrap() {
			let result = acknowledge_responsibility(&api_2, &mnemonic, block_number).await;
			println!("result of acknowledge responsibility: {:?}", result)
		} else {
			println!("result of no acknowledgmen");
		}
	});

	let block_author = get_block_author(&api).await.unwrap();
	let author_endpoint = get_author_endpoint(&api, &block_author).await.unwrap();
	let string_author_endpoint = convert_endpoint(&author_endpoint);
	let bool_block_author = is_block_author(&api, &block_author).await.unwrap();

	let address_whitelist = get_whitelist(&api, &user).await.unwrap();
	//TODO: JA this is where we send the decoded address
	let is_address_whitelisted = is_on_whitelist(address_whitelist, &vec![]);
	let does_have_key = does_have_key(kv_manager, user.to_string()).await;
	if (does_have_key && !bool_block_author) {
		let _result = send_ip_address(&author_endpoint).await;
	}
	// let result = send_ip_address_function().await;
	// for task in data {
	// 	println!("task: {:?}", task);
	// 	// ToDo: JA hardcoding
	// 	let sign_cli = protocol::sign::SignCli {
	// 		//ToDo: handle the unwrap... how do I use Result<> as a return type in a HTTP-route?
	// 		address: surf::Url::parse("http://localhost:3001/").unwrap(),
	// 		// ToDo: DF: use the proper sigID and convert it to String
	// 		room: String::from("sig_id"), // String::from_utf8(sig_id.clone()).unwrap(),
	// 		index: 2,
	// 		// parties: sig_res.signing_nodes, // ToDo: DF is this correct??
	// 		parties: vec![2, 1], // ToDo: DF is this correct??
	// 		data_to_sign: String::from("entropy rocks!!"),
	// 	};
	// 	println!("Bob starts signing...");
	// 	// ToDo: JA handle error
	// 	let signature = protocol::sign::sign(sign_cli).await;
	// 	println!("signature: {:?}", signature);
	// }
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

pub async fn get_block_number(
	api: &EntropyRuntime,
) -> Result<u32, subxt::Error<entropy::DispatchError>> {
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
	mnemonic: &String,
	block_number: u32,
) -> Result<(), subxt::Error<entropy::DispatchError>> {
	let pair: Sr25519Pair = Pair::from_string(mnemonic, None).unwrap();
	let signer = PairSigner::new(pair);
	// TODO: JA unhardcode failures and block number should be of the target block
	let result = api
		.tx()
		.relayer()
		.confirm_done(block_number.saturating_sub(2), vec![])
		.sign_and_submit_then_watch_default(&signer)
		.await?
		.wait_for_in_block()
		.await?
		.wait_for_success()
		.await?;

	if let Some(event) = result.find_first::<entropy::relayer::events::ConfirmedDone>()? {
		println!("confirmed done block number: {:?}", event.1);
	} else {
		println!("Failed to confirm done event: {:?}", block_number);
	}
	Ok(())
}

pub async fn get_whitelist(
	api: &EntropyRuntime,
	user: &AccountId32,
) -> Result<Vec<Vec<u8>>, subxt::Error<entropy::DispatchError>> {
	let whitelist = api.storage().constraints().address_whitelist(user, None).await?;

	Ok(whitelist)
}

pub async fn does_have_key(kv: KvManager, user: String) -> bool {
	kv.kv().exists(&user).await.unwrap()
}

// pub async fn send_ip_address_function() {
// 	send_ip_address("test".to_string()).await.unwrap();
// }

pub async fn send_ip_address(author_endpoint: &Vec<u8>) {
	let client = reqwest::Client::new();
	//TODO fix to get ip address locally and send
	let route = "/get_ip/127.0.0.1/3001";
	let mut ip = str::from_utf8(author_endpoint).unwrap().to_string();
	ip.push_str(route);
	let response = client.get(ip);
}
