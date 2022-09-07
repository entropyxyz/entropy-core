use std::{env, fs, path::Path, time};

use bincode::Options;
use kvdb::{
  clean_tests, encrypted_sled::PasswordMethod, get_db_path, kv_manager::value::KvManager,
};
use parity_scale_codec::{Decode, Encode};
use rocket::{
  http::{ContentType, Status},
  local::asynchronous::Client,
  tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{sr25519::Pair as Sr25519Pair, Pair as Pair2};
use substrate_common::{Message, SigRequest};
use subxt::{sp_core::sr25519, PairSigner};
use testing_utils::context::{test_context, test_context_stationary};
use tofn::{
  gg20::keygen::{KeygenPartyId, SecretKeyShare},
  sdk::api::PartyShareCounts,
};

use crate::{
  new_party, new_user, subscribe_to_me,
  user::{ParsedUserInputPartyInfo, UserInputPartyInfo},
  CommunicationManagerState, Configuration, SignerState,
};

pub async fn setup_client() -> rocket::local::asynchronous::Client {
  Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_new_party() {
  let port_0 = 3001;
  let port_1 = 3002;
  // Construct a client to use for dispatching requests.
  tokio::spawn(async move {
    create_clients(port_0.clone(), "0".to_string()).await;
  });
  tokio::time::sleep(Duration::from_secs(1)).await;

  tokio::spawn(async move {
    create_clients(port_1.clone(), "1".to_string()).await;
  });
  tokio::time::sleep(Duration::from_secs(1)).await;

  let client = reqwest::Client::new();

  store_key(&client, port_0.clone(), "0".to_string()).await;
  store_key(&client, port_1.clone(), "1".to_string()).await;

  let handle = tokio::spawn(async move {
    let encoded_data: Vec<u8> = Message {
      sig_request: SigRequest { sig_hash: [128, 209].to_vec() },
      account:     [
        240, 217, 145, 69, 231, 221, 189, 15, 30, 70, 231, 253, 64, 109, 185, 39, 68, 21, 132, 87,
        28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128, 212, 53, 147,
      ]
      .to_vec(),
    }
    .encode();

    let client = reqwest::Client::new();

    let url = format!("http:///127.0.0.1:{}/signer/new_party", port_0);
    let response = client.post(url).body(encoded_data.clone()).send().await;
    assert_eq!(response.unwrap().status(), 200);
  });
  // [
  //   message: {
  //     sig: {
  //       sig: hash
  //     },
  //     address: "0x0000000000000000000000000000000000000000",
  //   }
  // ]
  let handle_2 = tokio::spawn(async move {
    let encoded_data: Vec<u8> = Message {
      sig_request: SigRequest { sig_hash: [128, 209].to_vec() },
      account:     [
        240, 217, 145, 69, 231, 221, 189, 15, 30, 70, 231, 253, 64, 109, 185, 39, 68, 21, 132, 87,
        28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128, 212, 53, 147,
      ]
      .to_vec(),
    }
    .encode();

    let client = reqwest::Client::new();

    let url2 = format!("http:///127.0.0.1:{}/signer/new_party", port_1);
    let response_2 = client.post(url2).body(encoded_data.clone()).send().await;
    assert_eq!(response_2.unwrap().status(), 200);
  });
  handle.await.unwrap();
  handle_2.await.unwrap();
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

async fn create_clients(port: i64, key_number: String) {
  let config = rocket::Config::figment().merge(("port", port));

  let communication_manager_state = CommunicationManagerState::default();
  let signer_state = SignerState::default();
  let configuration = Configuration::new();

  let path = format!("test_db_{}", key_number);
  let _ = std::fs::remove_dir_all(path.clone());

  let kv_store =
    KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();

  let _ = rocket::custom(config)
    .mount("/signer", routes![new_party, subscribe_to_me])
    .mount("/user", routes![new_user])
    .manage(communication_manager_state)
    .manage(signer_state)
    .manage(configuration)
    .manage(kv_store)
    .launch()
    .await
    .expect("valid `Rocket`");
}

async fn store_key(client: &reqwest::Client, port: i64, key_number: String) {
  let key = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string();
  let bincode = bincode::DefaultOptions::new();
  let root = project_root::get_project_root().unwrap();
  let path = format!("{}/{}", root.display(), key_number);
  let v_serialized = fs::read(path).unwrap();
  let user_input = UserInputPartyInfo { key: key.clone(), value: v_serialized.clone() };
  let url = format!("http:///127.0.0.1:{}/user/new", port);
  let response_keystore = client.post(url).json(&user_input.clone()).send().await;

  assert_eq!(response_keystore.unwrap().status(), 200);
}
