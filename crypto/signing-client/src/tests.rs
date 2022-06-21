use super::{rocket, IPs};
use crate::ip_discovery::{get_all_ips, IpAddresses};
use crate::sign::{
	acknowledge_responsibility, convert_endpoint, does_have_key, get_api, get_author_endpoint,
	get_block_author, get_block_number, get_whitelist, is_block_author, send_ip_address,
};
use crate::store_share::{store_keyshare, User};
use crate::{get_test_password, Global};
use curv::elliptic::curves::secp256_k1::Secp256k1;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;
use parity_scale_codec::Encode;
use rocket::tokio::time::{sleep, Duration};
use rocket::{
	figment::Figment,
	http::{ContentType, Status},
	local::asynchronous::Client,
	Config, State,
};
use serial_test::serial;
use sp_core::{sr25519::Pair as Sr25519Pair, Pair as Pair2};
use sp_keyring::AccountKeyring;
use std::{
	env,
	fs::{remove_dir_all, remove_file},
	sync::Mutex,
	thread, time,
};
use subxt::{
	sp_core::{
		crypto::{Pair, Ss58Codec},
		sr25519,
	},
	PairSigner,
};
use testing_utils::context::{test_context, test_context_stationary};
use tofnd::kv_manager::{KeyReservation, KvManager};

async fn setup_client() -> rocket::local::asynchronous::Client {
	Client::tracked(super::rocket().await).await.expect("valid `Rocket`")
}

fn get_path(extension: &str) -> String {
	let path = env::current_dir();

	let mut file_path: String = path.unwrap().as_path().display().to_string().to_owned();
	file_path.push_str(extension);
	file_path
}

#[rocket::async_test]
#[serial]
async fn test_store_share() {
	let key = "14ffvYx6uFkqr3jXvYc5Joeczvnq8oqCiABdNA3a1M9R16F2".to_string();

	let file_path = get_path("/src/mocks/local-share1.json");

	let file = tokio::fs::read(file_path).await;
	let client = setup_client().await;

	let user_input = User { key: key.clone(), value: file.unwrap() };

	let response = client
		.post("/store_keyshare")
		.header(ContentType::JSON)
		.body(serde_json::to_string(&user_input.clone()).unwrap())
		.dispatch()
		.await;

	assert_eq!(response.status(), Status::Ok);
	assert_eq!(response.into_string().await, None);
	// fails to add already added share
	let response = client
		.post("/store_keyshare")
		.header(ContentType::JSON)
		.body(serde_json::to_string(&user_input).unwrap())
		.dispatch()
		.await;

	assert_eq!(response.status(), Status::InternalServerError);

	// delete KV store after tests
	let root = project_root::get_project_root().unwrap();
	let mut file_path: String = root.as_path().display().to_string().to_owned();
	file_path.push_str("/kvstore");
	let result = remove_dir_all(file_path);
	assert_eq!(result.is_ok(), true);
}

#[rocket::async_test]
#[serial]
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
#[serial]
async fn test_sign() {
	let cxt = test_context_stationary().await;
	let now = time::Instant::now();
	// sleep to make sure one block has been mined or else panic
	sleep(Duration::from_secs(8u64)).await;

	let encoded_data = vec![
		4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189,
		4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162,
		125,
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
#[serial]
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
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
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
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
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
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
	let bob_stash_id: subxt::sp_runtime::AccountId32 = sr25519::Pair::from_string("//Bob", None)
		.expect("Could not obtain stash signer pair")
		.public()
		.into();
	let result = is_block_author(&api.unwrap(), &bob_stash_id).await;
	assert_eq!(result.unwrap(), false);
}

#[rocket::async_test]
async fn test_get_block_author() {
	let cxt = test_context().await;
	sleep(Duration::from_secs(10u64)).await;
	let api = get_api(&cxt.node_proc.ws_url).await;
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
async fn test_get_block_number() {
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
	let result = get_block_number(&api.unwrap()).await;
	assert_eq!(result.is_ok(), true);
}

#[rocket::async_test]
async fn test_get_author_endpoint() {
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
	let alice_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Alice//stash", None)
			.expect("Could not obtain stash signer pair")
			.public()
			.into();

	let result = get_author_endpoint(&api.unwrap(), &alice_stash_id).await;
	let endpoint = convert_endpoint(&result.as_ref().unwrap());

	assert_eq!(endpoint.unwrap(), "ws://localhost:3001");
}

#[rocket::async_test]
async fn test_send_responsibility_message() {
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
	sleep(Duration::from_secs(25u64)).await;
	let mnemonic =
		"alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
			.to_string();

	let result = acknowledge_responsibility(&api.unwrap(), &mnemonic, 3u32).await;
	assert_eq!(result.is_ok(), true);
}

#[rocket::async_test]
async fn test_get_whitelist() {
	let cxt = test_context().await;
	let api = get_api(&cxt.node_proc.ws_url).await;
	let alice_stash_id: subxt::sp_runtime::AccountId32 =
		sr25519::Pair::from_string("//Alice//stash", None)
			.expect("Could not obtain stash signer pair")
			.public()
			.into();

	let result = get_whitelist(&api.as_ref().unwrap(), &alice_stash_id).await;
	assert_eq!(result.unwrap().len(), 0);

	let pair: Sr25519Pair = Pair2::from_string("//Alice//stash", None).unwrap();
	let signer = PairSigner::new(pair);

	api.as_ref()
		.unwrap()
		.tx()
		.constraints()
		.add_whitelist_address(vec![vec![10]])
		.sign_and_submit_then_watch_default(&signer)
		.await
		.unwrap()
		.wait_for_in_block()
		.await
		.unwrap()
		.wait_for_success()
		.await
		.unwrap();

	let result2 = get_whitelist(&api.unwrap(), &alice_stash_id).await;
	assert_eq!(result2.as_ref().unwrap().len(), 1);
	assert_eq!(result2.unwrap(), vec![vec![10u8]]);
}

#[rocket::async_test]
#[serial]
async fn test_have_keyshare() {
	let key = "12mXVvtCubeKrVx99EWQCpJrLxnmzAgXqwHePLoamVN31Kn5".to_string();
	// launch kv manager
	let root = project_root::get_project_root().unwrap();
	let kv_manager = KvManager::new(root.clone(), get_test_password()).unwrap();

	let result = does_have_key(&kv_manager.clone(), key.clone()).await;
	assert_eq!(result, false);

	let reservation = kv_manager.kv().reserve_key(key.clone()).await.unwrap();
	let _ = kv_manager.kv().put(reservation, "dummy".to_owned().as_bytes().to_vec()).await;

	let result_2 = does_have_key(&kv_manager.clone(), key.clone()).await;
	assert_eq!(result_2, true);
	// delete key so tests rerun
	let _ = kv_manager.kv().delete(&key).await.unwrap();
	let result_3 = does_have_key(&kv_manager, key.clone()).await;
	assert_eq!(result_3, false);
}

// TODO: same rocket not connect error with test, works when tested manually with server running on port 3002
#[rocket::async_test]
#[ignore]
async fn send_ip_address_test() {
	let client = setup_client().await;
	let result = send_ip_address(&"http://127.0.0.1:3002".as_bytes().to_vec()).await;
	// assert_eq!(result.status(), Status::Ok);
}

#[rocket::async_test]
#[serial]
async fn get_all_ips_test() {
	let client = setup_client().await;
	let all_ip_vec = vec!["test".to_string(), "test".to_string()];
	let all_ips = IpAddresses { ip_addresses: all_ip_vec.clone() };

	let response = client
		.post("/get_all_ips")
		.header(ContentType::JSON)
		.body(serde_json::to_string(&all_ips.clone()).unwrap())
		.dispatch()
		.await;
	assert_eq!(response.status(), Status::Ok);
}

#[rocket::async_test]
#[serial]
async fn get_ip_test() {
	let client = setup_client().await;
	let send = "/get_ip/localhost:3002";

	let ips = IPs { current_ips: Mutex::new(vec![]) };

	create_clients(3002i64).await;

	let response = client.get("/get_ip/localhost:3002").dispatch().await;
	assert_eq!(response.status(), Status::Ok);

	let response_fail = client.get("/get_ip/localhost:3002").dispatch().await;
	assert_eq!(response_fail.status(), Status::InternalServerError);

	let response_2 = client.get("/get_ip/localhost:3003").dispatch().await;
	assert_eq!(response_2.status(), Status::Ok);

	let response_3 = client.get("/get_ip/localhost:3004").dispatch().await;
	assert_eq!(response_3.status(), Status::Ok);

	let response_4 = client.get("/get_ip/localhost:3005").dispatch().await;
	assert_eq!(response_4.status(), Status::Ok);

	let response_5 = client.get("/get_ip/localhost:3006").dispatch().await;
	// TODO: this should be Ok only happens in tests where can't connect to other http client
	assert_eq!(response_5.status(), Status::InternalServerError);
}

async fn create_clients(port: i64) {
	let config = rocket::Config::figment().merge(("port", port));

	let ips = IPs { current_ips: Mutex::new(vec![]) };
	Client::tracked(rocket::custom(config).mount("/", routes![get_all_ips]).manage(ips))
		.await
		.expect("valid `Rocket`");
}
