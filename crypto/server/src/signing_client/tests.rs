use std::{env, time};

use crate::user::ParsedUserInputPartyInfo;
use tofn::sdk::api::PartyShareCounts;
use tofn::gg20::keygen::{KeygenPartyId, SecretKeyShare};

use bincode::Options;
use std::{fs, path::Path};
use kvdb::{
  clean_tests, encrypted_sled::PasswordMethod, get_db_path, kv_manager::value::KvManager,
};
use rocket::{
  http::{ContentType, Status},
  local::asynchronous::Client,
  tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{sr25519::Pair as Sr25519Pair, Pair as Pair2};
use subxt::{sp_core::sr25519, PairSigner};
use testing_utils::context::{test_context, test_context_stationary};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
  Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_new_party() {
	// Construct a client to use for dispatching requests.
	let client = setup_client().await;

  let key = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string();
  let bincode = bincode::DefaultOptions::new();
  let root = project_root::get_project_root().unwrap();
  let path = format!("{}/0", root.display());
  let v_serialized = fs::read(path).unwrap();
  let user_input = ParsedUserInputPartyInfo { key: key.clone(), value: v_serialized.clone() };
  let response_keystore = client
  	.post("/user/new")
  	.header(ContentType::JSON)
  	.body(serde_json::to_string(&user_input.clone()).unwrap())
  	.dispatch()
  	.await;

  assert_eq!(response_keystore.status(), Status::Ok);

  let encoded_data = vec![
    8, 128, 209, 136, 240, 217, 145, 69, 231, 221, 189, 15, 30, 70, 231, 253, 64, 109, 185, 39, 68,
    21, 132, 87, 28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128, 212, 53, 147, 199, 21, 253, 211, 28,
    97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86, 132, 231, 165,
    109, 162, 125, 128, 209, 136, 240, 217, 145, 69, 231, 221, 189, 15, 30, 70, 231, 253, 64, 109,
    185, 39, 68, 21, 132, 87, 28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128, 212, 53, 147, 199, 21,
    253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86,
    132, 231, 165, 109, 162, 125,
  ];

  let response = client.post("/signer/new_party").body(&encoded_data).dispatch().await;
  assert_eq!(response.status(), Status::Ok);
  clean_tests();
}

#[rocket::async_test]
#[ignore]
async fn new_party_fail_wrong_data() {
  // Construct a client to use for dispatching requests.
  let client = setup_client().await;

  let response = client
    .post("/signer/new_party")
    .body(
      r##"{
		"name": "John Doe",
		"email": "j.doe@m.com",
		"password": "123456"
	}"##,
    )
    .dispatch()
    .await;

  assert_eq!(response.status(), Status::new(500));
  clean_tests();
}
