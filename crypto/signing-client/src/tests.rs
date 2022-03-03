use super::rocket;
use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use rocket::{
	http::{ContentType, Status},
	local::asynchronous::Client,
	tokio::io::AsyncReadExt,
};
use std::{env, fs::remove_file};

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
	let encoded_data = vec![
		4, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0,
	];

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
