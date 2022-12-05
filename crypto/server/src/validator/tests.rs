use hex_literal::hex;
use kvdb::clean_tests;
use rocket::{
    http::{ContentType, Status},
    local::asynchronous::Client,
    tokio::time::{sleep, Duration},
};
use serial_test::serial;
use sp_core::{crypto::AccountId32, sr25519, Pair};
use subxt::tx::{PairSigner, Signer};
use testing_utils::context::test_context;

use super::api::get_all_keys;
use crate::{
    chain_api::{entropy, get_api, EntropyConfig},
    utils::{DEFAULT_BOB_MNEMONIC, DEFAULT_MNEMONIC},
};
pub async fn setup_client() -> rocket::local::asynchronous::Client {
    Client::tracked(crate::rocket().await).await.expect("valid `Rocket`")
}

#[rocket::async_test]
#[serial]
async fn test_sync_keys() {
    clean_tests();
    let client = setup_client().await;

    let response = client.post("/validator/sync_keys").header(ContentType::JSON).dispatch().await;

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
