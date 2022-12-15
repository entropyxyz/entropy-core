use std::{fs, path::PathBuf};

use hex_literal::hex;
use kvdb::{
    clean_tests, encrypted_sled::PasswordMethod, get_db_path, kv_manager::value::KvManager,
};
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
    Ignite, Rocket,
};
use serial_test::serial;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use sp_keyring::AccountKeyring;
use subxt::tx::{PairSigner, Signer};
use testing_utils::context::test_context;

use super::api::{get_all_keys, get_and_store_values, get_key_url, sync_kvdb};
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    new_user,
    signing_client::SignerState,
    utils::{
        Configuration, SignatureState, DEFAULT_BOB_MNEMONIC, DEFAULT_ENDPOINT, DEFAULT_MNEMONIC,
    },
};
pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_sync_kvdb() {
    clean_tests();
    let client = setup_client().await;

    let response = client.post("/validator/sync_kvdb").header(ContentType::JSON).dispatch().await;

    dbg!(response);
}

#[rocket::async_test]
async fn test_get_all_keys() {
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();

    let mut result = get_all_keys(&api, 3).await.unwrap();
    let mut result_2 = get_all_keys(&api, 5).await.unwrap();
    let mut result_3 = get_all_keys(&api, 1).await.unwrap();
    let mut result_4 = get_all_keys(&api, 6).await.unwrap();

    let mut expected_results = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL",
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy",
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw",
    ];
    result.sort();
    expected_results.sort();
    result_2.sort();
    result_3.sort();
    result_4.sort();

    assert_eq!(result, expected_results);
    assert_eq!(result_2, expected_results);
    assert_eq!(result_3, expected_results);
    assert_eq!(result_4, expected_results);
}

#[rocket::async_test]
#[should_panic]
async fn test_get_all_keys_fail() {
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let _ = get_all_keys(&api, 0).await.unwrap();
}

#[rocket::async_test]
#[serial]
async fn test_get_and_store_values() {
    clean_tests();
    let cxt = test_context().await;

    let keys = vec![
        "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2DjL".to_string(),
        "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy".to_string(),
        "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEZcCj68kUMaw".to_string(),
    ];

    let port_0 = 3002;
    let port_1 = 3003;
    let values = vec![vec![10], vec![11], vec![12]];
    // Construct a client to use for dispatching requests.
    let client0 = create_clients(port_0, "0".to_string(), values.clone(), keys.clone()).await;
    let client1 = create_clients(port_1, "1".to_string(), vec![], keys.clone()).await;

    tokio::spawn(async move { client0.0.launch().await.unwrap() });
    tokio::spawn(async move { client1.0.launch().await.unwrap() });

    let _result =
        get_and_store_values(keys.clone(), &client1.1, "127.0.0.1:3002".to_string(), 1).await;
    for (i, key) in keys.iter().enumerate() {
        let value = client1.1.kv().get(&key).await.unwrap();
        assert_eq!(value, values[i]);
    }
    clean_tests();
}

#[rocket::async_test]
#[serial]
async fn test_get_key_url() {
    clean_tests();
    let cxt = test_context().await;
    let api = get_api(&cxt.node_proc.ws_url).await.unwrap();
    let p_alice = <sr25519::Pair as Pair>::from_string(DEFAULT_MNEMONIC, None).unwrap();
    let signer_alice = PairSigner::<EntropyConfig, sr25519::Pair>::new(p_alice);

    let result = get_key_url(&api, &signer_alice).await.unwrap();

    assert_eq!("127.0.0.1:3001", result);
}

async fn create_clients(
    port: i64,
    key_number: String,
    values: Vec<Vec<u8>>,
    keys: Vec<String>,
) -> (Rocket<Ignite>, KvManager) {
    let config = rocket::Config::figment().merge(("port", port));

    let signer_state = SignerState::default();
    let configuration = Configuration::new(DEFAULT_ENDPOINT.to_string());
    let signature_state = SignatureState::new();

    let path = format!("test_db_{}", key_number);
    let _ = std::fs::remove_dir_all(path.clone());

    let kv_store =
        KvManager::new(path.into(), PasswordMethod::NoPassword.execute().unwrap()).unwrap();

    // Shortcut: store the shares manually
    let root = project_root::get_project_root().unwrap();
    let share_id = i32::from(port != 3001);
    let path: PathBuf =
        [root, "test_data".into(), "key_shares".into(), share_id.to_string().into()]
            .into_iter()
            .collect();

    for (i, value) in values.iter().enumerate() {
        let reservation = kv_store.clone().kv().reserve_key(keys[i].to_string()).await.unwrap();
        let result = kv_store.clone().kv().put(reservation, value.to_vec()).await;
    }

    let result = rocket::custom(config)
        .mount("/validator", routes![sync_kvdb])
        .mount("/user", routes![new_user])
        .manage(signer_state)
        .manage(configuration)
        .manage(kv_store.clone())
        .manage(signature_state)
        .ignite()
        .await
        .unwrap();

    (result, kv_store)
}
