use std::{env, fs, path::Path, str::FromStr, time};

use bincode::Options;
use kvdb::{
    clean_tests, encrypted_sled::PasswordMethod, get_db_path, kv_manager::value::KvManager,
};
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{crypto::AccountId32, sr25519::Pair as Sr25519Pair, Pair as Pair2};
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
        create_clients(port_0, "0".to_string()).await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    tokio::spawn(async move {
        create_clients(port_1, "1".to_string()).await;
    });
    tokio::time::sleep(Duration::from_secs(1)).await;

    let client = reqwest::Client::new();

    let encoded_data_1 = vec![
        8, 128, 209, 136, 240, 217, 145, 69, 231, 221, 189, 15, 30, 70, 231, 253, 64, 109, 185, 39,
        68, 21, 132, 87, 28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128, 212, 53, 147, 199, 21, 253,
        211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133, 76, 205, 227, 154, 86,
        132, 231, 165, 109, 162, 125, 128, 209, 136, 240, 217, 145, 69, 231, 221, 189, 15, 30, 70,
        231, 253, 64, 109, 185, 39, 68, 21, 132, 87, 28, 98, 58, 255, 29, 22, 82, 225, 75, 6, 128,
        212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88,
        133, 76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
    ];
    let encoded_data_2 = encoded_data_1.clone();

    let handle = tokio::spawn(async move {
        let client = reqwest::Client::new();

        let url = format!("http:///127.0.0.1:{}/signer/new_party", port_0);
        let response = client.post(url).body(encoded_data_1).send().await;
        assert_eq!(response.unwrap().status(), 200);
    });
    let handle_2 = tokio::spawn(async move {
        let client = reqwest::Client::new();

        let url2 = format!("http:///127.0.0.1:{}/signer/new_party", port_1);
        let response_2 = client.post(url2).body(encoded_data_2).send().await;
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

    // Shortcut: store the shares manually
    let root = project_root::get_project_root().unwrap();
    let path = format!("{}/{}", root.display(), if port == 3001 { 0 } else { 1 });
    let v_serialized = fs::read(path).unwrap();
    let key = AccountId32::from_str("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY").unwrap();

    let reservation = kv_store.kv().reserve_key(key.to_string()).await.unwrap();
    let result = kv_store.kv().put(reservation, v_serialized).await;

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
