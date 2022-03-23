use super::rocket;
use crate::sign::{get_api, get_block_author, is_block_author, get_author_endpoint, convert_endpoint};
use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use parity_scale_codec::Encode;
use rocket::{
	http::{ContentType, Status},
	local::asynchronous::Client,
};
use sp_keyring::AccountKeyring;
use std::{env, fs::remove_file};
use subxt::sp_core::{
	crypto::{Pair, Ss58Codec},
	sr25519,
};
// use crate::utils::test_context;

async fn setup_client() -> rocket::local::asynchronous::Client {
	Client::tracked(super::rocket()).await.expect("valid `Rocket`")
}

fn get_path(extension: &str) -> String {
	let path = env::current_dir();

	let mut file_path: String = path.unwrap().as_path().display().to_string().to_owned();
	file_path.push_str(extension);
	file_path
}

#[rocket::async_test]
async fn test_store_share() {
	let file_path = get_path("/src/mocks/local-share1.json");

	let file = tokio::fs::read(file_path).await;

	let json: LocalKey<Secp256k1> = serde_json::from_slice(&file.unwrap()).unwrap();
	// Construct a client to use for dispatching requests.
	let client = setup_client().await;
	let response = client
		.post("/store_keyshare")
		.header(ContentType::JSON)
		.body(serde_json::to_string(&json).unwrap())
		.dispatch()
		.await;

	assert_eq!(response.status(), Status::Ok);
	assert_eq!(response.into_string().await, None);

	let new_path = get_path("/local-share2.json");

	// check to see if new file was stored
	let result = remove_file(new_path);
	assert_eq!(result.is_ok(), true);
}

#[rocket::async_test]
async fn test_store_share_fail_wrong_data() {
	// Construct a client to use for dispatching requests.
	let client = setup_client().await;

	let response = client
		.post("/store_keyshare")
		.header(ContentType::JSON)
		.body(
			r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
		)
		.dispatch()
		.await;
	assert_eq!(response.status(), Status::UnprocessableEntity);
}

#[rocket::async_test]
async fn provide_share() {
	let encoded_data = vec![8, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0];

	// Construct a client to use for dispatching requests.
	let client = setup_client().await;

	let response = client
		.post("/sign")
		.header(ContentType::new("application", "x-parity-scale-codec"))
		.body(&encoded_data)
		.dispatch()
		.await;
	assert_eq!(response.status(), Status::Ok);
	assert_eq!(response.into_string().await, Some("\u{1}".into()));
}

#[rocket::async_test]
async fn provide_share_fail_wrong_data() {
	// Construct a client to use for dispatching requests.
	let client = setup_client().await;

	let response = client
		.post("/sign")
		.header(ContentType::new("application", "x-parity-scale-codec"))
		.body(
			r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
		)
		.dispatch()
		.await;
	assert_eq!(response.status(), Status::InternalServerError);
}

#[rocket::async_test]
async fn get_is_block_author() {
	// test_context().await;
	let api = get_api("ws://localhost:9944").await;
	let alice_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Alice//stash", None)
			.expect("Could not obtain stash signer pair")
			.public()
			.into();
	let result = is_block_author(&api.unwrap(), &alice_stash_id).await;
	assert_eq!(result.unwrap(), true);
}

#[rocket::async_test]
async fn not_is_block_author() {
	// test_context().await;
	let api = get_api("ws://localhost:9944").await;
	let bob_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Bob//stash", None)
			.expect("Could not obtain stash signer pair")
			.public()
			.into();
	let result = is_block_author(&api.unwrap(), &bob_stash_id).await;
	assert_eq!(result.unwrap(), false);
}

// TODO: JA review this test see if best idea
#[rocket::async_test]
#[should_panic = "called `Option::unwrap()` on a `None` value"]
async fn not_validator_block_author() {
	// test_context().await;
	let api = get_api("ws://localhost:9944").await;
	let bob_stash_id: subxt::sp_runtime::AccountId32 = sr25519::Pair::from_string("//Bob", None)
		.expect("Could not obtain stash signer pair")
		.public()
		.into();
	let result = is_block_author(&api.unwrap(), &bob_stash_id).await;
	assert_eq!(result.unwrap(), false);
}

#[rocket::async_test]
async fn test_get_block_author() {
	// test_context().await;
	let api = get_api("ws://localhost:9944").await;
	let result = get_block_author(&api.unwrap()).await;
	println!("result {:?}", result);
	let alice_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Alice//stash", None)
			.expect("Could not obtain stash signer pair")
			.public()
			.into();

	assert_eq!(result.unwrap(), alice_stash_id);
}

#[rocket::async_test]
async fn test_get_author_endpoint() {
	// test_context().await;
	let api = get_api("ws://localhost:9944").await;
	let alice_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Alice//stash", None)
		.expect("Could not obtain stash signer pair")
		.public()
		.into();

	let result = get_author_endpoint(&api.unwrap(), alice_stash_id).await;
	let endpoint = convert_endpoint(&result.as_ref().unwrap());

	assert_eq!(endpoint.unwrap(), "ws://localhost:3001");
}
